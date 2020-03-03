/*
 * Copyright (c) 2018 LabKey Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.labkey.api.security;


import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.labkey.api.cache.Cache;
import org.labkey.api.cache.CacheManager;
import org.labkey.api.util.DateUtil;
import org.labkey.api.util.FileUtil;
import org.labkey.api.util.HeartBeat;
import org.labkey.api.util.HtmlString;
import org.labkey.api.util.PageFlowUtil;
import org.labkey.api.util.Pair;
import org.labkey.api.util.Path;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;

import static org.labkey.api.util.DOM.*;

/**
 * This is not a defense against any particular vulnerability
 * however, this can help protect against wasting resources being consumed by scanners
 *
 * Note that this code is not particularly concerned about speed since this only happens on already failed requests
 */
public class BlacklistFilter
{
    static Logger _log = Logger.getLogger(BlacklistFilter.class);

    static Cache<String,Suspicious> suspiciousMap = CacheManager.getStringKeyCache(1_000, CacheManager.HOUR, "suspicious");
    static Cache<String,Suspicious> blacklist = CacheManager.getStringKeyCache(1_000, CacheManager.DAY, "blacklist");


    private static String getBrowserKey(HttpServletRequest req)
    {
        return req.getRemoteHost() + '|' + req.getHeader("User-Agent");
    }


    static void handleBadRequest(HttpServletRequest req)
    {
        String key = getBrowserKey(req);
        final String host = req.getRemoteHost();
        final String userAgent = req.getHeader("User-Agent");
        Suspicious s = suspiciousMap.get(key, null, (k, a) -> new Suspicious(host,userAgent));
        int count = s.add(req);
        String uri = req.getRequestURI();
        String q = req.getQueryString();
        if (count == 1 || count == 10)
        {
            _log.log(count==1?Level.INFO:Level.WARN,
            count + " suspicious request(s) by this host: " + host + " " + userAgent + (null == s.user ? "" : "(" + s.user + ")") + "\n" + uri + (null==q ? "" : "?" + q));
        }
        if (count > 10)
            blacklist.put(key,s);
    }


    static void handleNotFound(HttpServletRequest req)
    {
        if (isSuspicious(req.getRequestURI(),req.getQueryString(),req.getHeader("User-Agent")))
        {
            handleBadRequest(req);
        }
    }


    static boolean isOnBlacklist(HttpServletRequest req)
    {
        String key = getBrowserKey(req);

        boolean blacklisted = null != blacklist.get(key);
        Suspicious s = suspiciousMap.get(key);
        return s != null && s.getCount() > 20;
    }


    final static Pattern[] sql1_patterns =
    {
            Pattern.compile("select\\s"),
            Pattern.compile("\\s((and)|(or)|(in))\\s"),
            Pattern.compile("[;<=>'\"]"),
            Pattern.compile("--\\s")
    };
    final static Pattern[] sql2_patterns =
    {
            Pattern.compile("\\(select\\s"),
            Pattern.compile("\\sunion\\s"),
            Pattern.compile("\\sorder\\s+by\\s"),
            Pattern.compile("['\"\\s]=['\"\\s]"),
            Pattern.compile("ctxsys\\.drithsx\\.sn"),
            Pattern.compile("\\s((dbo)|(master)|(sys))\\."),
            Pattern.compile("((information_schema)|(waitfor)|(pg_sleep)|(cha?r\\())")   // semicolon is too common to check for
    };
    private final static Pattern pipe_pattern = Pattern.compile("\\|\\s*(ls|id|echo|vol|curl|wget)");


    private static boolean isSqlInjectiony(String sql)
    {
        int count = 0;
        for (var p : sql2_patterns)
        {
            count += p.matcher(sql).find() ? 2 : 0;
            if (count > 1)
                return true;
        }
        for (var p : sql1_patterns)
        {
            count += p.matcher(sql).find() ? 1 : 0;
            if (count > 1)
                return true;
        }
        return false;
    }

    private static boolean isScriptInjectiony(String js)
    {
        if (js.contains("<script"))
            return true;
        if (js.contains("javascript:"))
            return true;
        if (js.contains("onerror="))
            return true;
        return false;
    }

    // make public for testing
    public static boolean isSuspicious(String request_path, String query, String userAgent)
    {
        final char REPLACEMENT_CHAR = '\uFFFD';
        final Set<String> suspectExtensions = PageFlowUtil.set("ini","dll","do","jsp","asp","aspx","php","pl","vbs");

        try
        {
            // CHARS
            // contains %2E %2F
            String raw_path = request_path.toLowerCase();
            query = StringUtils.trimToNull(query);
            if (raw_path.endsWith("/favicon.ico") && null==query)
                return false;
            boolean isActionURL = raw_path.endsWith(".post") || raw_path.endsWith(".view") || raw_path.endsWith(".api");

            // why encode '.' or '/'???
            if (raw_path.contains("%252e") || raw_path.contains("%252f") || raw_path.contains("%2e") || raw_path.contains("%2f") || raw_path.indexOf(REPLACEMENT_CHAR) != -1)
                return true;
            if (raw_path.startsWith("//"))
                return true;
            String decode_path = PageFlowUtil.decode(raw_path);
            if (decode_path.indexOf(REPLACEMENT_CHAR) != -1)
                return true;
            // PATH
            Path path = Path.parse(decode_path);
            Path norm = path.normalize();
            if (null == norm || !path.equals(norm))
                return true;
            for (String part : path)
            {
                if (part.startsWith(".") || part.startsWith("\">") || part.startsWith("wp-") || (part.startsWith("admin")&&!isActionURL))
                    return true;
                if (part.endsWith("-inf"))
                    return true;
                if (part.equals("") || part.equals("etc") || part.equals("data") || part.equals("phpunit"))
                    return true;
            }
            // EXTENSIONS
            String ext = FileUtil.getExtension(path.getName());
            if (null != ext && !path.contains("_webdav"))
                if (suspectExtensions.contains(ext))
                    return true;
            // QUERY STRING
            if (null != query)
            {
                for (Pair<String, String> p : PageFlowUtil.fromQueryString(query))
                {
                    String key = p.first.toLowerCase();
                    String value = p.second;
                    if (key.indexOf(REPLACEMENT_CHAR)!=-1 || value.indexOf(REPLACEMENT_CHAR)!=-1)
                        return true;
                    try {
                        value = PageFlowUtil.decode(value);
                        value = PageFlowUtil.decode(value);
                    } catch (Exception x) {/*pass*/}
                    value = value.toLowerCase();
                    if (pipe_pattern.matcher(value).find())
                        return true;
                    if (value.contains("/../../") || value.contains("/etc/") || value.endsWith(".ini"))
                        return true;
                    if (!"returnurl".equals(key) && !"service".equals(key) && (value.startsWith("http://") || value.startsWith("https://")))
                        return true;
                    if (isScriptInjectiony(value))
                        return true;
                    if (isSqlInjectiony(value))
                        return true;
                }
            }
            return false;
        }
        catch (IllegalArgumentException ex)
        {
            return true;
        }
    }

    public static Collection<Suspicious> reportSuspicious()
    {
        ArrayList<Suspicious> ret = new ArrayList<>();
        Set<String> keys = new TreeSet<>();
        keys.addAll(suspiciousMap.getKeys());
        keys.addAll(blacklist.getKeys());
        for (String key : keys)
        {
            Suspicious s = blacklist.get(key);
            if (null == s)
                s = suspiciousMap.get(key);
            if (null == s)
                continue;
            Suspicious copy = s.clone();
            if (copy.getCount() > 0)
                ret.add(copy);
        }
        return ret;
    }

    public static class Suspicious
    {
        public final String host;
        public final String userAgent;
        public String lastURL = null;
        public long lastRequestTime = 0;
        public String user = null;
        public int count = 0;

        public Suspicious(String host, String userAgent)
        {
            this.host = host;
            this.userAgent = userAgent;
        }

        public synchronized Suspicious clone()
        {
            Suspicious c = new Suspicious(this.host,this.userAgent);
            c.user = this.user;
            c.count = this.count;
            c.lastURL = this.lastURL;
            c.lastRequestTime = this.lastRequestTime;
            return c;
        }

        public synchronized int getCount()
        {
            return count;
        }

        public synchronized int add(HttpServletRequest req)
        {
            count++;
            User u = (User)req.getUserPrincipal();
            if (u != null && !u.isGuest())
                 this.user = u.getEmail();
            this.lastRequestTime = HeartBeat.currentTimeMillis();
            this.lastURL = req.getRequestURI() + "?" + req.getQueryString();
            return count;
        }

        public HtmlString getReport()
        {
            boolean blacklisted = null != blacklist.get(host + "|" + userAgent);
            StringBuilder sb = new StringBuilder();
            TABLE(cl("table"),
                    !blacklisted ? null : TR(TD(cl("labkey-error"), "blacklisted"), TD(A(at(Attribute.href,"admin-caches.view"),"clear"), " blacklist cache to reset")),
                    TR(TH("host"), TD(host)),
                    TR(TH("userAgent", TD(userAgent))),
                    TR(TH("user"), TD(user)),
                    TR(TH("time"), TD(DateUtil.toISO(lastRequestTime))),
                    TR(TH("url"), TD(lastURL))
            ).appendTo(sb);
            return HtmlString.unsafe(sb.toString());
        }
    }

    /*
    public static class TestCase extends Assert
    {
        @Test
        public void testSuspicious() throws Exception
        {
            try (InputStream is = this.getClass().getClassLoader().getResourceAsStream("org/labkey/api/security/urls.txt"))
            {
                List<String> urls = IOUtils.readLines(is,"UTF-8");
                for (String url : urls)
                {
                    String path = url;
                    String query = "";
                    int q = url.indexOf('?');
                    if (q != -1)
                    {
                        path = url.substring(0,q);
                        query = url.substring(q+1);
                    }
                    if (isSuspicious(path,query))
                        System.err.println(url);
                    else
                        System.out.println(url);
                }
            }
        }

        @Test
        public void testNotSuspicious()
        {
        }
    }
    */
}
