/*
 * Copyright (c) 2004-2009 Fred Hutchinson Cancer Research Center
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

package org.labkey.core.junit;

import junit.framework.TestCase;
import junit.framework.TestFailure;
import junit.framework.TestResult;
import org.apache.commons.lang.time.FastDateFormat;
import org.labkey.api.action.SimpleViewAction;
import org.labkey.api.action.SpringActionController;
import org.labkey.api.security.*;
import org.labkey.api.security.roles.NoPermissionsRole;
import org.labkey.api.util.PageFlowUtil;
import org.labkey.api.util.TestContext;
import org.labkey.api.view.HttpView;
import org.labkey.api.view.NavTree;
import org.labkey.api.view.JspView;
import org.labkey.api.view.template.PageConfig;
import org.springframework.validation.BindException;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.Controller;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.io.OutputStream;
import java.text.DateFormat;
import java.text.Format;
import java.util.*;


public class JunitController extends SpringActionController
{
    private static final ActionResolver _resolver = new DefaultActionResolver(JunitController.class);


    public JunitController()
    {
        super();
        setActionResolver(_resolver);
    }

    @RequiresSiteAdmin
    public class BeginAction extends SimpleViewAction
    {
        public ModelAndView getView(Object o, BindException errors) throws Exception
        {
            HttpView junitView = new HttpView()
            {
                @Override
                public void renderInternal(Object model, PrintWriter out) throws Exception
                {
                    Map<String, List<Class<? extends TestCase>>> testCases = JunitManager.getTestCases();

                    out.println("<div><table class=\"labkey-data-region\">");

                    for (String module : testCases.keySet())
                    {
                        String moduleTd = module;

                        for (Class<? extends TestCase> clazz : testCases.get(module))
                        {
                            out.println("<tr><td>" + moduleTd + "</td><td>");
                            moduleTd = "&nbsp;";
                            out.println(clazz.getName() + " <a href=\"run.view?testCase=" + clazz.getName() + "\">&lt;run&gt;</a></td></tr>");
                        }

                        out.println("<tr><td colspan=2>&nbsp;</td></tr>");
                    }

                    out.println("</table></div>");

                    out.print("<br>" + PageFlowUtil.generateButton("Run All", "run.view"));
                }
            };

            getPageConfig().setTemplate(PageConfig.Template.Dialog);
            return junitView;
        }

        public NavTree appendNavTrail(NavTree root)
        {
            return null;
        }
    }


    @RequiresSiteAdmin
    public class RunAction extends SimpleViewAction<TestForm>
    {
        public ModelAndView getView(TestForm form, BindException errors) throws Exception
        {
            TestContext.setTestContext(getViewContext().getRequest(), getUser());
            TestResult result = new TestResult();

            String testCase = form.getTestCase();
            if (null != testCase && 0 == testCase.length())
                testCase = null;

            Map<String, List<Class<? extends TestCase>>> testCases = JunitManager.getTestCases();

            for (String module : testCases.keySet())
            {
                for (Class<? extends TestCase> clazz : testCases.get(module))
                {
                    // check if the client has gone away
                    getViewContext().getResponse().getWriter().print(" ");
                    getViewContext().getResponse().flushBuffer();
                    // run test
                    if (null == testCase || testCase.equals(clazz.getName()))
                        JunitRunner.run(clazz, result);
                }
            }

            getPageConfig().setTemplate(PageConfig.Template.Dialog);
            return new TestResultView(result);
        }

        public NavTree appendNavTrail(NavTree root)
        {
            return null;
        }
    }


    public static class TestForm
    {
        private String _testCase;

        public String getTestCase()
        {
            return _testCase;
        }

        public void setTestCase(String testCase)
        {
            _testCase = testCase;
        }
    }


    private Class<? extends TestCase> findTestClass(String testCase)
    {
        Map<String, List<Class<? extends TestCase>>> testCases = JunitManager.getTestCases();

        for (String module : testCases.keySet())
        {
            for (Class<? extends TestCase> clazz : testCases.get(module))
            {
                if (null == testCase || testCase.equals(clazz.getName()))
                    return clazz;
            }
        }

        return null;
    }


    private static final LinkedList<String> list = new LinkedList<String>();
    private static final Format format = FastDateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.LONG);

    @RequiresPermission(ACL.PERM_NONE)
    public class AliveAction extends SimpleViewAction
    {
        public ModelAndView getView(Object o, BindException errors) throws Exception
        {
            synchronized(AliveAction.class)
            {
                HttpServletRequest request = getViewContext().getRequest();
                HttpServletResponse response = getViewContext().getResponse();
                TestContext.setTestContext(request, (User) request.getUserPrincipal());
                TestResult result = new TestResult();

                Class<? extends TestCase> test = findTestClass("org.labkey.api.data.DbSchema$TestCase");

                if (null != test)
                    JunitRunner.run(test, result);

                int status = HttpServletResponse.SC_OK;
                if (result.failureCount() != 0)
                    status = HttpServletResponse.SC_INTERNAL_SERVER_ERROR;

                String time = format.format(new Date());
                String statusString = "" + status + ": " + time + "    " + request.getHeader("User-Agent");
                if (list.size() > 20)
                    list.removeFirst();
                list.add(statusString);

                response.reset();
                response.setStatus(status);

                PrintWriter out = response.getWriter();
                response.setContentType("text/plain");

                out.println(status == HttpServletResponse.SC_OK ? "OK" : "ERROR");
                out.println();
                out.println("history");
                for (ListIterator it = list.listIterator(list.size()); it.hasPrevious();)
                    out.println(it.previous());

                response.flushBuffer();
                return null;
            }
        }

        public NavTree appendNavTrail(NavTree root)
        {
            return null;
        }
    }


    public static class TestResultView extends HttpView
    {
        TestResult _result;


        TestResultView(TestResult result)
        {
            _result = result;
            //setTitle("JUnit test results");
        }


        @Override
        public void renderInternal(Object model, PrintWriter out) throws Exception
        {
            if (_result.wasSuccessful())
                out.print("<br><h2>SUCCESS</h2>");
            else
                out.print("<h2 class=ms-error>FAILURE</h2>");
            out.print("<br><table><tr><td class=labkey-form-label>Tests</td><td align=right>");
            out.print("" + _result.runCount());
            out.print("</td></tr><tr><td class=labkey-form-label>Failures</td><td align=right>");
            out.print("" + _result.failureCount());
            out.print("</td></tr><tr><td class=labkey-form-label>Errors</td><td align=right>");
            out.print("" + _result.errorCount());
            out.print("</td></tr></table>");

            if (_result.errorCount() > 0)
            {
                out.println("<br><table width=\"640\"><td width=100><hr style=\"width:40; height:1;\"></td><td nowrap><b>errors</b></td><td width=\"100%\"><hr style=\"height:1;\"></td></tr></table>");
                for (Enumeration e = _result.errors(); e.hasMoreElements();)
                {
                    TestFailure tf = (TestFailure) e.nextElement();
                    out.print(PageFlowUtil.filter(tf.toString(),true));
                    out.print("<br><pre>");
                    tf.thrownException().printStackTrace(out);
                    out.print("</pre>");
                }
            }

            if (_result.failureCount() > 0)
            {
                out.println("<table width=\"640\"><td width=100><hr style=\"width:40; height:1;\"></td><td nowrap><b>failures</b></td><td width=\"100%\"><hr style=\"height:1;\"></td></tr></table>");
                for (Enumeration e = _result.failures(); e.hasMoreElements();)
                {
                    TestFailure f = (TestFailure) e.nextElement();
                    if (f.thrownException().getMessage().startsWith("<div>"))
                        out.println(f.thrownException().getMessage() + "<br>");
                    else
                        out.println(PageFlowUtil.filter(f.thrownException().getMessage(),true) + "<br>");
                    String testName = f.failedTest().getClass().getName();
                    int count=0;
                    for (StackTraceElement ste : f.thrownException().getStackTrace())
                    {
                         if (ste.getClassName().equals(testName))
                        {
                            out.print(PageFlowUtil.filter(ste.toString()));
                            out.println("<br>");
                            count++;
                            if (count >= 3)
                                break;
                        }
                    }
                    out.println("<p/>");
                }
            }
        }
    }


    @RequiresPermission(ACL.PERM_NONE)
    public class EchoFormAction implements Controller
    {
        public ModelAndView handleRequest(HttpServletRequest req, HttpServletResponse res) throws Exception
        {
            PrintWriter out = res.getWriter();
            out.println("<html><head></head><body><form method=GET>");
            Enumeration<String> names = req.getParameterNames();
            while (names.hasMoreElements())
            {
                String name = names.nextElement();
                out.print("<input name='");
                out.print(h(name));
                out.print("' value='");
                out.print(h(req.getParameter(name)));
                out.print("'>");
                out.print(h(name));
                out.println("<br>");
            }

            out.println("<input type=submit></body></html>");
            return null;
        }
    }

    static String h(String s)
    {
        return PageFlowUtil.filter(s);
    }
}
