/*
 * Copyright (c) 2007-2013 LabKey Corporation
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

package org.labkey.core;

import org.apache.commons.beanutils.ConvertUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;
import org.json.JSONArray;
import org.json.JSONObject;
import org.labkey.api.action.ApiAction;
import org.labkey.api.action.ApiResponse;
import org.labkey.api.action.ApiSimpleResponse;
import org.labkey.api.action.ApiUsageException;
import org.labkey.api.action.ExportAction;
import org.labkey.api.action.MutatingApiAction;
import org.labkey.api.action.SimpleApiJsonForm;
import org.labkey.api.action.SimpleRedirectAction;
import org.labkey.api.action.SimpleViewAction;
import org.labkey.api.action.SpringActionController;
import org.labkey.api.admin.CoreUrls;
import org.labkey.api.attachments.Attachment;
import org.labkey.api.attachments.AttachmentCache;
import org.labkey.api.attachments.AttachmentParent;
import org.labkey.api.attachments.AttachmentService;
import org.labkey.api.data.CacheableWriter;
import org.labkey.api.data.ColumnInfo;
import org.labkey.api.data.Container;
import org.labkey.api.data.ContainerManager;
import org.labkey.api.data.ContainerManager.ContainerParent;
import org.labkey.api.data.DataRegionSelection;
import org.labkey.api.data.DbScope;
import org.labkey.api.data.PropertyManager;
import org.labkey.api.data.Results;
import org.labkey.api.data.SimpleFilter;
import org.labkey.api.data.TableInfo;
import org.labkey.api.exp.Identifiable;
import org.labkey.api.exp.LsidManager;
import org.labkey.api.exp.ObjectProperty;
import org.labkey.api.exp.OntologyManager;
import org.labkey.api.exp.OntologyObject;
import org.labkey.api.exp.PropertyDescriptor;
import org.labkey.api.exp.PropertyType;
import org.labkey.api.exp.api.ExperimentService;
import org.labkey.api.module.AllowedBeforeInitialUserIsSet;
import org.labkey.api.module.AllowedDuringUpgrade;
import org.labkey.api.module.FolderType;
import org.labkey.api.module.Module;
import org.labkey.api.module.ModuleLoader;
import org.labkey.api.module.ModuleProperty;
import org.labkey.api.pipeline.PipeRoot;
import org.labkey.api.pipeline.PipelineService;
import org.labkey.api.query.QueryService;
import org.labkey.api.query.SchemaKey;
import org.labkey.api.query.UserSchema;
import org.labkey.api.security.IgnoresTermsOfUse;
import org.labkey.api.security.RequiresLogin;
import org.labkey.api.security.RequiresNoPermission;
import org.labkey.api.security.RequiresPermissionClass;
import org.labkey.api.security.User;
import org.labkey.api.security.UserManager;
import org.labkey.api.security.permissions.AdminPermission;
import org.labkey.api.security.permissions.DeletePermission;
import org.labkey.api.security.permissions.InsertPermission;
import org.labkey.api.security.permissions.Permission;
import org.labkey.api.security.permissions.ReadPermission;
import org.labkey.api.security.permissions.UpdatePermission;
import org.labkey.api.security.roles.RoleManager;
import org.labkey.api.services.ServiceRegistry;
import org.labkey.api.settings.AppProps;
import org.labkey.api.settings.LookAndFeelProperties;
import org.labkey.api.util.Compress;
import org.labkey.api.util.DateUtil;
import org.labkey.api.util.PageFlowUtil;
import org.labkey.api.util.PageFlowUtil.Content;
import org.labkey.api.util.PageFlowUtil.NoContent;
import org.labkey.api.util.Path;
import org.labkey.api.util.StringUtilsLabKey;
import org.labkey.api.view.ActionURL;
import org.labkey.api.view.HtmlView;
import org.labkey.api.view.JspView;
import org.labkey.api.view.NavTree;
import org.labkey.api.view.NotFoundException;
import org.labkey.api.view.Portal;
import org.labkey.api.view.RedirectException;
import org.labkey.api.view.TermsOfUseException;
import org.labkey.api.view.UnauthorizedException;
import org.labkey.api.view.VBox;
import org.labkey.api.view.ViewContext;
import org.labkey.api.view.WebPartView;
import org.labkey.api.view.WebTheme;
import org.labkey.api.view.WebThemeManager;
import org.labkey.api.webdav.ModuleStaticResolverImpl;
import org.labkey.api.webdav.WebdavResolver;
import org.labkey.api.webdav.WebdavResource;
import org.labkey.api.writer.ZipUtil;
import org.labkey.core.query.CoreQuerySchema;
import org.labkey.core.security.SecurityController;
import org.labkey.core.workbook.CreateWorkbookBean;
import org.labkey.core.workbook.MoveWorkbooksBean;
import org.labkey.core.workbook.WorkbookFolderType;
import org.labkey.core.workbook.WorkbookQueryView;
import org.labkey.core.workbook.WorkbookSearchView;
import org.springframework.validation.BindException;
import org.springframework.validation.Errors;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.Controller;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

/**
 * User: jeckels
 * Date: Jan 4, 2007
 */
public class CoreController extends SpringActionController
{
    private static final Map<Container, Content> _themeStylesheetCache = new ConcurrentHashMap<>();
    private static final Map<Container, Content> _customStylesheetCache = new ConcurrentHashMap<>();
    private static final Map<Container, Content> _combinedStylesheetCache = new ConcurrentHashMap<>();
    private static final Map<Content, Content> _setCombinedStylesheet = new ConcurrentHashMap<>();
    private static final Logger _log = Logger.getLogger(CoreController.class);

    private static ActionResolver _actionResolver = new DefaultActionResolver(CoreController.class);

    public CoreController()
    {
        setActionResolver(_actionResolver);
    }

    public static class CoreUrlsImpl implements CoreUrls
    {
        private ActionURL getRevisionURL(Class<? extends Controller> actionClass, Container c)
        {
            ActionURL url = new ActionURL(actionClass, c);
            url.addParameter("revision", AppProps.getInstance().getLookAndFeelRevision());
            return url;
        }

        public ActionURL getThemeStylesheetURL()
        {
            return getRevisionURL(ThemeStylesheetAction.class, ContainerManager.getRoot());
        }

        public ActionURL getThemeStylesheetURL(Container c)
        {
            Container project = c.getProject();
            LookAndFeelProperties laf = LookAndFeelProperties.getInstance(project);

            if (laf.hasProperties())
                return getRevisionURL(ThemeStylesheetAction.class, project);
            return null;
        }

        public ActionURL getCustomStylesheetURL()
        {
            return getCustomStylesheetURL(ContainerManager.getRoot());
        }

        public ActionURL getCustomStylesheetURL(Container c)
        {
            Container settingsContainer = LookAndFeelProperties.getSettingsContainer(c);
            Content css;
            try
            {
                css = getCustomStylesheetContent(settingsContainer);
            }
            catch (Exception e)
            {
                throw new RuntimeException(e);
            }

            if (css instanceof NoContent)
                return null;
            return getRevisionURL(CustomStylesheetAction.class, settingsContainer);
        }

        public ActionURL getCombinedStylesheetURL(Container c)
        {
            Container s = LookAndFeelProperties.getSettingsContainer(c);
            return getRevisionURL(CombinedStylesheetAction.class, s);
        }

        @Override
        public ActionURL getContainerRedirectURL(Container c, String pageFlow, String action)
        {
            ActionURL url = new ActionURL(ContainerRedirectAction.class, c);
            url.addParameter("pageflow", pageFlow);
            url.addParameter("action", action);

            return url;
        }

        @Override
        public ActionURL getDownloadFileLinkBaseURL(Container container, PropertyDescriptor pd)
        {
            return new ActionURL(DownloadFileLinkAction.class, container).addParameter("propertyId", pd.getPropertyId());
        }

        @Override
        public ActionURL getAttachmentIconURL(Container c, String filename)
        {
            ActionURL url = new ActionURL(GetAttachmentIconAction.class, c);

            if (null != filename)
            {
                int dotPos = filename.lastIndexOf(".");
                if (dotPos > -1 && dotPos < filename.length() - 1)
                    url.addParameter("extension", filename.substring(dotPos + 1).toLowerCase());
            }

            return url;
        }

        @Override
        public ActionURL getProjectsURL(Container c)
        {
            return new ActionURL(ProjectsAction.class, c);
        }
    }

    abstract class BaseStylesheetAction extends ExportAction
    {
        @Override
        public void checkPermissions() throws TermsOfUseException, UnauthorizedException
        {
            // Stylesheets can be retrieved always by anyone.  This do-nothing override is even more permissive than
            //  using @RequiresNoPermission and @IgnoresTermsOfUse since it also allows access in the root container even
            //  when impersonation is limited to a specific project.
        }

        public void export(Object o, HttpServletResponse response, BindException errors) throws Exception
        {
            HttpServletRequest request = getViewContext().getRequest();
            Content content = getContent(request, response);

            // No custom stylesheet for this container
            if (content instanceof NoContent)
                return;

            PageFlowUtil.sendContent(request, response, content, getContentType());
        }

        String getContentType()
        {
            return "text/css";
        }

        abstract Content getContent(HttpServletRequest request, HttpServletResponse response) throws Exception;
    }


    @RequiresNoPermission
    @IgnoresTermsOfUse
    @AllowedDuringUpgrade
    @AllowedBeforeInitialUserIsSet
    public class ThemeStylesheetAction extends BaseStylesheetAction
    {
        Content getContent(HttpServletRequest request, HttpServletResponse response) throws Exception
        {
            Container c = getContainer();
            Content content = _themeStylesheetCache.get(c);
            Integer dependsOn = AppProps.getInstance().getLookAndFeelRevision();

            if(AppProps.getInstance().isDevMode()){
                content = null;
            }
            
            if (null == content || !dependsOn.equals(content.dependencies))
            {
                JspView view = new JspView("/org/labkey/core/themeStylesheet.jsp");
                view.setFrame(WebPartView.FrameType.NOT_HTML);
                Content contentRaw = PageFlowUtil.getViewContent(view, request, response);
                content  = new Content(compileCSS(contentRaw.content));
                content.dependencies = dependsOn;
                content.compressed = compressCSS(content.content);
                _themeStylesheetCache.put(c, content);
            }
            return content;
        }
    }

    @RequiresPermissionClass(ReadPermission.class)
    public class ProjectsAction extends SimpleViewAction
    {
        @Override
        public ModelAndView getView(Object o, BindException errors) throws Exception
        {
            Portal.WebPart config = new Portal.WebPart();
            config.setIndex(1);
            config.setRowId(-1);
            JspView<Portal.WebPart> view = new JspView<>("/org/labkey/core/project/projects.jsp", config);
            view.setTitle("Projects");
            return view;
        }

        @Override
        public NavTree appendNavTrail(NavTree root)
        {
            return root;
        }
    }

    @RequiresPermissionClass(ReadPermission.class)
    public class DownloadFileLinkAction extends SimpleViewAction<DownloadFileLinkForm>
    {
        public ModelAndView getView(DownloadFileLinkForm form, BindException errors) throws Exception
        {
            if (form.getPropertyId() == null)
            {
                throw new NotFoundException("No propertyId specified");
            }
            PropertyDescriptor pd = OntologyManager.getPropertyDescriptor(form.getPropertyId().intValue());
            if (pd == null)
                throw new NotFoundException();

            if (pd.getPropertyType() != PropertyType.FILE_LINK)
                throw new IllegalArgumentException("Property not file link type");

            OntologyObject obj = null;
            File file;
            if (form.getObjectId() != null || form.getObjectURI() != null)
            {
                if (form.getObjectId() != null)
                {
                    obj = OntologyManager.getOntologyObject(form.getObjectId().intValue());
                }
                else if (form.getObjectURI() != null)
                {
                    // Don't filter by container - we'll redirect to the correct container ourselves
                    obj = OntologyManager.getOntologyObject(null, form.getObjectURI());
                }
                if (obj == null)
                    throw new NotFoundException("No matching ontology object found");

                if (!obj.getContainer().equals(getContainer()))
                {
                    ActionURL correctedURL = getViewContext().getActionURL().clone();
                    Container objectContainer = obj.getContainer();
                    if (objectContainer == null)
                        throw new NotFoundException();
                    correctedURL.setContainer(objectContainer);
                    throw new RedirectException(correctedURL);
                }

                Map<String, ObjectProperty> properties = OntologyManager.getPropertyObjects(obj.getContainer(), obj.getObjectURI());
                ObjectProperty fileProperty = properties.get(pd.getPropertyURI());
                if (fileProperty == null || fileProperty.getPropertyType() != PropertyType.FILE_LINK || fileProperty.getStringValue() == null)
                    throw new NotFoundException();
                file = new File(fileProperty.getStringValue());
            }
            else if (form.getSchemaName() != null && form.getQueryName() != null && form.getPk() != null)
            {
                UserSchema schema = QueryService.get().getUserSchema(getUser(), getContainer(), form.getSchemaName());
                if (schema == null)
                    throw new NotFoundException("Schema not found");

                TableInfo table = schema.getTable(form.getQueryName(), false);
                if (table == null)
                    throw new NotFoundException("Query not found in schema");

                List<ColumnInfo> pkCols = table.getPkColumns();
                if (pkCols.size() != 1)
                    throw new NotFoundException("Query must have only one pk column");
                ColumnInfo pkCol = pkCols.get(0);

                ColumnInfo col = table.getColumn(pd.getName());
                if (col == null)
                    throw new NotFoundException("PropertyColumn not found on table");

                Object pkVal = ConvertUtils.convert(form.getPk(), pkCol.getJavaClass());
                SimpleFilter filter = new SimpleFilter(pkCol.getFieldKey(), pkVal);
                try (Results results = QueryService.get().select(table, Collections.singletonList(col), filter, null))
                {
                    if (results.getSize() != 1 || !results.next())
                        throw new NotFoundException("Row not found for primary key");

                    String filename = results.getString(col.getFieldKey());
                    if (filename == null)
                        throw new NotFoundException();

                    file = new File(filename);
                }
            }
            else
            {
                throw new IllegalArgumentException("objectURI or schemaName, queryName, and pk required.");
            }

            // For security reasons, make sure the user hasn't tried to download a file that's not under
            // the pipeline root.  Otherwise, they could get access to any file on the server.
            PipeRoot root = PipelineService.get().findPipelineRoot(getContainer());
            if (root == null)
                throw new NotFoundException("No pipeline root for container " + getContainer().getPath());

            if (!root.hasPermission(getContainer(), getUser(), ReadPermission.class))
                throw new UnauthorizedException();

            if (!root.isUnderRoot(file))
                throw new NotFoundException("Cannot download file that isn't under the pipeline root for container " + getContainer().getPath());

            if (!file.exists())
            {
                Identifiable identifiable = null;
                if (obj != null)
                    identifiable = LsidManager.get().getObject(obj.getObjectURI());
                if (identifiable != null && identifiable.getName() != null)
                {
                    throw new NotFoundException("The file '" + file.getName() + "' attached to the object '" + identifiable.getName() + "' cannot be found. It may have been deleted.");
                }
                throw new NotFoundException("File " + file.getPath() + " does not exist on the server file system. It may have been deleted.");
            }

            if (file.isDirectory())
                ZipUtil.zipToStream(getViewContext().getResponse(), file, false);
            else
                PageFlowUtil.streamFile(getViewContext().getResponse(), file, true);
            return null;
        }

        public NavTree appendNavTrail(NavTree root)
        {
            throw new UnsupportedOperationException("Not Yet Implemented");
        }
    }

    public static class DownloadFileLinkForm
    {
        private Integer _propertyId;
        private Integer _objectId;
        private String _objectURI;
        private SchemaKey _schemaName;
        private String _queryName;
        private String _pk;

        public Integer getObjectId()
        {
            return _objectId;
        }

        public void setObjectId(Integer objectId)
        {
            _objectId = objectId;
        }

        public Integer getPropertyId()
        {
            return _propertyId;
        }

        public void setPropertyId(Integer propertyId)
        {
            _propertyId = propertyId;
        }

        public String getObjectURI()
        {
            return _objectURI;
        }

        public void setObjectURI(String objectURI)
        {
            _objectURI = objectURI;
        }

        public SchemaKey getSchemaName()
        {
            return _schemaName;
        }

        public void setSchemaName(SchemaKey schemaName)
        {
            _schemaName = schemaName;
        }

        public String getQueryName()
        {
            return _queryName;
        }

        public void setQueryName(String queryName)
        {
            _queryName = queryName;
        }

        public String getPk()
        {
            return _pk;
        }

        public void setPk(String pk)
        {
            _pk = pk;
        }
    }

    @RequiresNoPermission
    @IgnoresTermsOfUse
    @AllowedDuringUpgrade
    public class CustomStylesheetAction extends BaseStylesheetAction
    {
        Content getContent(HttpServletRequest request, HttpServletResponse response) throws Exception
        {
            return getCustomStylesheetContent(getContainer());
        }
    }


    private static Content getCustomStylesheetContent(Container c) throws IOException, ServletException
    {
        Content content = _customStylesheetCache.get(c);
        Integer dependsOn = AppProps.getInstance().getLookAndFeelRevision();

        if (null == content || !dependsOn.equals(content.dependencies))
        {
            AttachmentParent parent = new ContainerParent(c);
            Attachment cssAttachment = AttachmentCache.lookupCustomStylesheetAttachment(parent);

            if (null == cssAttachment)
            {
                content = new NoContent(dependsOn);
            }
            else
            {
                CacheableWriter writer = new CacheableWriter();
                AttachmentService.get().writeDocument(writer, parent, cssAttachment.getName(), false);
                content = new Content(new String(writer.getBytes()));
                content.dependencies = dependsOn;
                content.compressed = compressCSS(content.content);
            }

            _customStylesheetCache.put(c, content);
        }

        return content;
    }


    @RequiresNoPermission
    @IgnoresTermsOfUse
    @AllowedDuringUpgrade
    @AllowedBeforeInitialUserIsSet
    public class CombinedStylesheetAction extends BaseStylesheetAction
    {
        Content getContent(HttpServletRequest request, HttpServletResponse response) throws Exception
        {
            Container c = getContainer();
            if (null == c)
                c = ContainerManager.getRoot();
            c = LookAndFeelProperties.getSettingsContainer(c);

            Content content = _combinedStylesheetCache.get(c);
            Integer dependsOn = AppProps.getInstance().getLookAndFeelRevision();

            if (null == content || !dependsOn.equals(content.dependencies) || AppProps.getInstance().isDevMode())
            {
                InputStream is = null;
                try
                {
                    // get the root resolver
                    WebdavResolver r = ModuleStaticResolverImpl.get(); //ServiceRegistry.get(WebdavResolver.class);
                    WebTheme webTheme = WebThemeManager.getTheme(c);

                    WebdavResource stylesheet = r.lookup(new Path(webTheme.getStyleSheet()));

                    Content root = getCustomStylesheetContent(ContainerManager.getRoot());
                    Content theme = c.isRoot() ? null : (new ThemeStylesheetAction().getContent(request,response));
                    Content custom = c.isRoot() ? null : getCustomStylesheetContent(c);
                    WebdavResource extAll = r.lookup(Path.parse("/" + PageFlowUtil.extJsRoot() + "/resources/css/ext-all.css"));
                    WebdavResource extPatches = r.lookup(Path.parse("/" + PageFlowUtil.extJsRoot() + "/resources/css/ext-patches.css"));
                    WebdavResource ext4All = r.lookup(Path.parse(PageFlowUtil.resolveExtThemePath(c)));
                    StringWriter out = new StringWriter();

                    _appendCss(out, extAll);     // Ext 3
                    _appendCss(out, extPatches);
                    _appendCss(out, ext4All);    // Ext 4
                    _appendCss(out, stylesheet);
                    _appendCss(out, root);
                    _appendCss(out, theme);
                    _appendCss(out, custom);

                    String css = out.toString();
                    content = new Content(css);
                    content.compressed = compressCSS(css);
                    content.dependencies = dependsOn;
                    // save space
                    content.content = null; out = null;

                    synchronized (_setCombinedStylesheet)
                    {
                        Content shared = content.copy();
                        shared.modified = 0;
                        shared.dependencies = "";
                        if (!_setCombinedStylesheet.containsKey(shared))
                        {
                            _setCombinedStylesheet.put(shared,shared);
                        }
                        else
                        {
                            shared = _setCombinedStylesheet.get(shared);
                            content.content = shared.content;
                            content.encoded = shared.encoded;
                            content.compressed = shared.compressed;
                        }
                    }
                    _combinedStylesheetCache.put(c, content);
                }
                finally
                {
                    IOUtils.closeQuietly(is);
                }
            }

            return content;
        }
    }


    void _appendCss(StringWriter out, WebdavResource r)
    {
        if (null == r || !r.isFile())
            return;
        assert null != r.getFile();
        String s = PageFlowUtil.getFileContentsAsString(r.getFile());
        Path p = Path.parse(getViewContext().getContextPath()).append(r.getPath()).getParent();
        _appendCss(out, p, s);
    }


    void _appendCss(StringWriter out, Content content)
    {
        if (null == content || content instanceof NoContent)
            return;
        // relative URLs aren't really going to work (/labkey/core/container/), so path=null
        _appendCss(out, null, content.content);
    }
    

    void _appendCss(StringWriter out, Path p, String s)
    {
        String compiled = compileCSS(s);
        if (null != p)
            compiled = compiled.replaceAll("url\\(\\s*([^/])", "url(" + p.toString("/","/") + "$1");
        out.write(compiled);
        out.write("\n");
    }
    

    private static String compileCSS(String s)
    {
        if (!StringUtilsLabKey.isText(s))
        {
            return "\n/* CSS FILE CONTAINS NON-PRINTABLE CHARACTERS */\n";
        }
        else
        {
            return s;
        }
    }


    private static byte[] compressCSS(String s)
    {
        String c = s;

        try
        {
            if (!StringUtilsLabKey.isText(s))
            {
                c = "\n/* CSS FILE CONTAINS NON-PRINTABLE CHARACTERS */\n";
            }
            else
            {
                c = c.replaceAll("/\\*(?:.|[\\n\\r])*?\\*/", "");
                c = c.replaceAll("(?:\\s|[\\n\\r])+", " ");
                c = c.replaceAll("\\s*}\\s*", "}\r\n");
            }
        }
        catch (StackOverflowError e)
        {
            // replaceAll() can blow up
        }
        return Compress.compressGzip(c.trim());
    }


    static AtomicReference<Content> _combinedJavascript = new AtomicReference<>();

    @RequiresNoPermission
    @IgnoresTermsOfUse
    @AllowedDuringUpgrade
    @AllowedBeforeInitialUserIsSet
    public class CombinedJavascriptAction extends BaseStylesheetAction
    {
        Content getContent(HttpServletRequest request, HttpServletResponse response) throws Exception
        {
            Content ret = _combinedJavascript.get();
            if (null == ret)
            {
                // get the root resolver
                WebdavResolver r = ModuleStaticResolverImpl.get();
                
                Set<String> scripts = new LinkedHashSet<>();
                Set<String> includes = new LinkedHashSet<>();
                PageFlowUtil.getJavaScriptPaths(getContainer(), getUser(), scripts, includes);
                List<String> concat = new ArrayList<>();
                for (String path : scripts)
                {
                    WebdavResource script = r.lookup(Path.parse(path));
                    assert(script != null && script.isFile()) : "Failed to find: " + path;
                    if (script == null || !script.isFile())
                        continue;
                    concat.add("/* ---- " + path + " ---- */");
                    List<String> content = PageFlowUtil.getStreamContentsAsList(script.getInputStream(getUser()));
                    concat.addAll(content);
                }
                int len = 0;
                for (String s : concat)
                    len = s.length()+1;
                StringBuilder sb = new StringBuilder(len);
                for (String s : concat)
                {
                    String t = StringUtils.trimToNull(s);
                    if (t == null) continue;
                    if (t.startsWith("//"))
                        continue;
                    sb.append(t).append('\n');
                }
                ret = new Content(sb.toString());
                ret.content = null;
                ret.compressed = Compress.compressGzip(ret.encoded);
                _combinedJavascript.set(ret);
            }
            return ret;
        }

        @Override
        String getContentType()
        {
            return "text/javascript";
        }
    }


    @RequiresNoPermission
    @IgnoresTermsOfUse
    public class ContainerRedirectAction extends SimpleRedirectAction<RedirectForm>
    {
        public ActionURL getRedirectURL(RedirectForm form) throws Exception
        {
            Container targetContainer = ContainerManager.getForId(form.getContainerId());
            if (targetContainer == null)
            {
                throw new NotFoundException();
            }
            ActionURL url = getViewContext().getActionURL().clone();
            url.deleteParameter("action");
            url.deleteParameter("pageflow");
            url.deleteParameter("containerId");
            url.setController(form.getPageflow());
            url.setAction(form.getAction());
            url.setContainer(targetContainer);
            return url;
        }
    }


    public static class RedirectForm
    {
        private String _containerId;
        private String _action;
        private String _pageflow;

        public String getAction()
        {
            return _action;
        }

        public void setAction(String action)
        {
            _action = action;
        }

        public String getContainerId()
        {
            return _containerId;
        }

        public void setContainerId(String containerId)
        {
            _containerId = containerId;
        }

        public String getPageflow()
        {
            return _pageflow;
        }

        public void setPageflow(String pageflow)
        {
            _pageflow = pageflow;
        }
    }

    public static class GetAttachmentIconForm
    {
        private String _extension;

        public String getExtension()
        {
            return _extension;
        }

        public void setExtension(String extension)
        {
            _extension = extension;
        }
    }

    @RequiresNoPermission
    public class GetAttachmentIconAction extends SimpleViewAction<GetAttachmentIconForm>
    {
        public ModelAndView getView(GetAttachmentIconForm form, BindException errors) throws Exception
        {
            String path = Attachment.getFileIcon(StringUtils.trimToEmpty(form.getExtension()));

            if (path != null)
            {
                //open the file and stream it back to the client
                HttpServletResponse response = getViewContext().getResponse();
                response.setContentType(PageFlowUtil.getContentTypeFor(path));
                response.setHeader("Cache-Control", "public");
                response.setHeader("Pragma", "");

                byte[] buf = new byte[4096];
                WebdavResolver staticFiles = ServiceRegistry.get().getService(WebdavResolver.class);

                WebdavResource file = staticFiles.lookup(Path.parse(path));
                if (file != null)
                {
                    InputStream is = file.getInputStream();
                    OutputStream os = response.getOutputStream();

                    try
                    {
                        for(int len; (len=is.read(buf))!=-1; )
                            os.write(buf,0,len);
                    }
                    finally
                    {
                        os.close();
                        is.close();
                    }
                }
                else
                {
                    _log.warn("Unable to retrieve icon file: " + path);
                }
            }
            else
            {
                _log.warn("No icon file found for extension: " + StringUtils.trimToEmpty(form.getExtension()));
            }
            return null;
        }

        public NavTree appendNavTrail(NavTree root)
        {
            return null;
        }
    }

    public static class LookupWorkbookForm
    {
        private String _id;

        public String getId()
        {
            return _id;
        }

        public void setId(String id)
        {
            _id = id;
        }
    }

    @RequiresPermissionClass(ReadPermission.class)
    public class LookupWorkbookAction extends SimpleViewAction<LookupWorkbookForm>
    {
        public ModelAndView getView(LookupWorkbookForm form, BindException errors) throws Exception
        {
            if (null == form.getId())
                throw new NotFoundException("You must supply the id of the workbook you wish to find.");

            try
            {
                int id = Integer.parseInt(form.getId());
                //try to lookup based on id
                Container container = ContainerManager.getForRowId(id);
                //if found, ensure it's a descendant of the current container, and redirect
                if (null != container && container.isDescendant(getContainer()))
                    throw new RedirectException(container.getStartURL(getViewContext().getUser()));
            }
            catch (NumberFormatException e) { /* continue on with other approaches */ }

            //next try to lookup based on name
            Container container = getContainer().findDescendant(form.getId());
            if (null != container)
                throw new RedirectException(container.getStartURL(getViewContext().getUser()));

            //otherwise, return a workbooks list with the search view
            HtmlView message = new HtmlView("<p class='labkey-error'>Could not find a workbook with id '" + form.getId() + "' in this folder or subfolders. Try searching or entering a different id.</p>");
            WorkbookQueryView wbqview = new WorkbookQueryView(getViewContext(), new CoreQuerySchema(getUser(), getContainer()));
            return new VBox(message, new WorkbookSearchView(wbqview), wbqview);
        }

        public NavTree appendNavTrail(NavTree root)
        {
            //if a view ends up getting rendered, the workbook id was not found
            return root.addChild("Workbooks");
        }
    }

    // Requires at least insert permission. Will check for admin if needed
    @RequiresPermissionClass(InsertPermission.class)
    public class CreateContainerAction extends ApiAction<SimpleApiJsonForm>
    {
        @Override
        public ApiResponse execute(SimpleApiJsonForm form, BindException errors) throws Exception
        {
            JSONObject json = form.getJsonObject();
            if (json == null)
            {
                throw new NotFoundException("No JSON posted");
            }
            String name = StringUtils.trimToNull(json.getString("name"));
            String title = StringUtils.trimToNull(json.getString("title"));
            String description = StringUtils.trimToNull(json.getString("description"));
            boolean workbook = json.has("isWorkbook") && !json.isNull("isWorkbook") ? json.getBoolean("isWorkbook") : false;

            if (!workbook)
            {
                if (!getContainer().hasPermission(getUser(), AdminPermission.class))
                {
                    throw new UnauthorizedException("You must have admin permissions to create subfolders");
                }
            }

            if (name != null && getContainer().getChild(name) != null)
            {
                throw new ApiUsageException("A child container with that name already exists");
            }

            try
            {
                Container newContainer = ContainerManager.createContainer(getContainer(), name, title, description, (workbook ? Container.TYPE.workbook : Container.TYPE.normal), getUser());

                String folderTypeName = json.getString("folderType");
                if (folderTypeName == null && workbook)
                {
                    folderTypeName = WorkbookFolderType.NAME;
                }
                if (folderTypeName != null)
                {
                    FolderType folderType = ModuleLoader.getInstance().getFolderType(folderTypeName);
                    if (folderType != null)
                    {
                        newContainer.setFolderType(folderType, getUser());
                    }
                }

                return new ApiSimpleResponse(newContainer.toJSON(getUser()));
            }
            catch (IllegalArgumentException e)
            {
                throw new ApiUsageException(e);
            }
        }
    }

    // Requires at least delete permission. Will check for admin if needed
    @RequiresPermissionClass(DeletePermission.class)
    public class DeleteContainerAction extends ApiAction<SimpleApiJsonForm>
    {
        private Container target;

        @Override
        public void validateForm(SimpleApiJsonForm form, Errors errors)
        {
            target = getContainer();

            if (!ContainerManager.isDeletable(target))
                errors.reject(ERROR_MSG, "The path " + target.getPath() + " is not deletable.");
        }

        @Override
        public ApiResponse execute(SimpleApiJsonForm form, BindException errors) throws Exception
        {
            if (!target.isWorkbook())
            {
                if (!target.hasPermission(getUser(), AdminPermission.class))
                {
                    throw new UnauthorizedException("You must have admin permissions to delete subfolders");
                }
            }

            ContainerManager.deleteAll(target, getUser());

            return new ApiSimpleResponse();
        }
    }

    @RequiresPermissionClass(AdminPermission.class)
    public class MoveContainerAction extends ApiAction<SimpleApiJsonForm>
    {
        private Container target;
        private Container parent;
        
        @Override
        public void validateForm(SimpleApiJsonForm form, Errors errors)
        {
            JSONObject object = form.getJsonObject();
            String targetIdentifier = object.getString("container");

            if (null == targetIdentifier)
            {
                errors.reject(ERROR_MSG, "A target container must be specified for move operation.");
                return;
            }

            String parentIdentifier = object.getString("parent");

            if (null == parentIdentifier)
            {
                errors.reject(ERROR_MSG, "A parent container must be specified for move operation.");
                return;
            }

            // Worry about escaping
            Path path = Path.parse(targetIdentifier);
            target = ContainerManager.getForPath(path);            

            if (null == target)
            {
                target = ContainerManager.getForId(targetIdentifier);
                if (null == target)
                {
                    errors.reject(ERROR_MSG, "Conatiner '" + targetIdentifier + "' does not exist.");
                    return;
                }
            }

            // This covers /home and /shared
            if (target.isProject() || target.isRoot())
            {
                errors.reject(ERROR_MSG, "Cannot move project/root Containers.");
                return;
            }

            Path parentPath = Path.parse(parentIdentifier);
            parent = ContainerManager.getForPath(parentPath);

            if (null == parent)
            {
                parent = ContainerManager.getForId(parentIdentifier);
                if (null == parent)
                {
                    errors.reject(ERROR_MSG, "Parent container '" + parentIdentifier + "' does not exist.");
                    return;
                }
            }

            // Check children
            if (parent.hasChildren())
            {
                List<Container> children = parent.getChildren();
                for (Container child : children)
                {
                    if (child.getName().toLowerCase().equals(target.getName().toLowerCase()))
                    {
                        errors.reject(ERROR_MSG, "Subfolder of '" + parent.getPath() + "' with name '" +
                                target.getName() + "' already exists.");
                        return;
                    }
                }
            }

            // Make sure not attempting to make parent a child. Might need to do this with permission bypass.
            List<Container> children = ContainerManager.getAllChildren(target, getUser()); // assumes read permission
            if (children.contains(parent))
            {
                errors.reject(ERROR_MSG, "The container '" + parentIdentifier + "' is not a valid parent folder.");
                return;
            }
        }

        @Override
        public ApiResponse execute(SimpleApiJsonForm form, BindException errors) throws Exception
        {
            // Check if parent is unchanged
            if (target.getParent().getPath().equals(parent.getPath()))
            {
                return new ApiSimpleResponse("success", true);
            }

            // Prepare aliases
            JSONObject object = form.getJsonObject();
            Boolean addAlias = (Boolean) object.get("addAlias");
            
            List<String> aliasList = new ArrayList<>();
            aliasList.addAll(Arrays.asList(ContainerManager.getAliasesForContainer(target)));
            aliasList.add(target.getPath());
            
            // Perform move
            ContainerManager.move(target, parent, getViewContext().getUser());

            Container afterMoveTarget = ContainerManager.getForId(target.getId());
            if (null != afterMoveTarget)
            {
                // Save aliases
                if (addAlias)
                    ContainerManager.saveAliasesForContainer(afterMoveTarget, aliasList);

                // Prepare response
                Map<String, Object> response = new HashMap<>();
                response.put("success", true);
                response.put("newPath", afterMoveTarget.getPath());
                return new ApiSimpleResponse(response);                
            }
            return new ApiSimpleResponse();
        }
    }

    @RequiresPermissionClass(InsertPermission.class)
    public class CreateWorkbookAction extends SimpleViewAction<CreateWorkbookBean>
    {
        @Override
        public ModelAndView getView(CreateWorkbookBean bean, BindException errors) throws Exception
        {
            if (bean.getTitle() == null)
            {
                //suggest a name
                //per spec it should be "<user-display-name> YYYY-MM-DD"
                bean.setTitle(getViewContext().getUser().getDisplayName(getUser()) + " " + DateUtil.formatDate(new Date()));
            }

            return new JspView<>("/org/labkey/core/workbook/createWorkbook.jsp", bean, errors);
        }

        public NavTree appendNavTrail(NavTree root)
        {
            return root.addChild("Create New Workbook");
        }
    }

    public static class UpdateDescriptionForm
    {
        private String _description;

        public String getDescription()
        {
            return _description;
        }

        public void setDescription(String description)
        {
            _description = description;
        }
    }

    @RequiresPermissionClass(UpdatePermission.class)
    public class UpdateDescriptionAction extends MutatingApiAction<UpdateDescriptionForm>
    {
        public ApiResponse execute(UpdateDescriptionForm form, BindException errors) throws Exception
        {
            String description = StringUtils.trimToNull(form.getDescription());
            ContainerManager.updateDescription(getContainer(), description, getUser());
            return new ApiSimpleResponse("description", description);
        }
    }

    public static class UpdateTitleForm
    {
        private String _title;

        public String getTitle()
        {
            return _title;
        }

        public void setTitle(String title)
        {
            _title = title;
        }
    }

    @RequiresPermissionClass(UpdatePermission.class)
    public class UpdateTitleAction extends MutatingApiAction<UpdateTitleForm>
    {
        public ApiResponse execute(UpdateTitleForm form, BindException errors) throws Exception
        {
            String title = StringUtils.trimToNull(form.getTitle());
            ContainerManager.updateTitle(getContainer(), title, getUser());
            return new ApiSimpleResponse("title", title);
        }
    }

    @RequiresPermissionClass(AdminPermission.class)
    public class MoveWorkbooksAction extends SimpleViewAction
    {
        public ModelAndView getView(Object o, BindException errors) throws Exception
        {
            Container parentContainer = getViewContext().getContainer();
            Set<String> ids = DataRegionSelection.getSelected(getViewContext(), true);
            if (null == ids || ids.size() == 0)
                throw new RedirectException(parentContainer.getStartURL(getViewContext().getUser()));

            MoveWorkbooksBean bean = new MoveWorkbooksBean();
            for (String id : ids)
            {
                Container wb = ContainerManager.getForId(id);
                if (null != wb)
                    bean.addWorkbook(wb);
            }

            return new JspView<>("/org/labkey/core/workbook/moveWorkbooks.jsp", bean, errors);
        }

        public NavTree appendNavTrail(NavTree root)
        {
            return root.addChild("Move Workbooks");
        }
    }

    public static class ExtContainerTreeForm
    {
        private int _node;
        private boolean _move = false;
        private boolean _showContainerTabs = false;
        private String _requiredPermission;

        public int getNode()
        {
            return _node;
        }

        public void setNode(int node)
        {
            _node = node;
        }

        public boolean getMove()
        {
            return _move;
        }

        public void setMove(boolean move)
        {
            _move = move;
        }
        
        public String getRequiredPermission()
        {
            return _requiredPermission;
        }

        public void setRequiredPermission(String requiredPermission)
        {
            _requiredPermission = requiredPermission;
        }

        public boolean getShowContainerTabs()
        {
            return _showContainerTabs;
        }

        public void setShowContainerTabs(boolean showContainerTabs)
        {
            _showContainerTabs = showContainerTabs;
        }
    }

    private enum AccessType
    {
        /** User shouldn't see the folder at all */
        none,
        /** User has permission to access the folder itself */
        direct,
        /** User doesn't have permission to access the folder, but it still needs to be displayed because they have access to a subfolder */
        indirect
    }

    @RequiresPermissionClass(ReadPermission.class)
    public class GetExtContainerTreeAction extends ApiAction<ExtContainerTreeForm>
    {
        protected Class<? extends Permission> _reqPerm = ReadPermission.class;
        protected boolean _move = false;
        
        public ApiResponse execute(ExtContainerTreeForm form, BindException errors) throws Exception
        {
            User user = getViewContext().getUser();
            JSONArray children = new JSONArray();
            _move = form.getMove();

            Container parent = ContainerManager.getForRowId(form.getNode());
            if (null != parent)
            {
                if (!form.getShowContainerTabs() && parent.isContainerTab())
                    parent = parent.getParent();            // Don't show container tab, show parent

                //determine which permission should be required for a child to show up
                if (null != form.getRequiredPermission())
                {
                    Permission perm = RoleManager.getPermission(form.getRequiredPermission());
                    if (null != perm)
                        _reqPerm = perm.getClass();
                }

                for (Container child : parent.getChildren())
                {
                    // Don't show workbook and don't show containerTabs if we're told not to
                    if (!child.isWorkbook() && (form.getShowContainerTabs() || !child.isContainerTab()))
                    {
                        AccessType accessType = getAccessType(child, user, _reqPerm);
                        if (accessType != AccessType.none)
                        {
                            JSONObject childProps = getContainerProps(child, form.getShowContainerTabs());
                            if (accessType == AccessType.indirect)
                            {
                                // Disable so they can't act on it directly, since they have no permission
                                childProps.put("disabled", true);
                            }
                            children.put(childProps);
                        }
                    }
                }
            }

            HttpServletResponse resp = getViewContext().getResponse();
            resp.setContentType("application/json");
            resp.getWriter().write(children.toString());

            return null;
        }

        /**
         * Determine if the user can access the folder directly, or only because they have permission to a subfolder,
         * or not at all
         */
        protected AccessType getAccessType(Container container, User user, Class<? extends Permission> perm)
        {
            if (container.hasPermission(user, perm))
            {
                return AccessType.direct;
            }
            // If no direct permission, check if they have permission to a subfolder
            for (Container child : container.getChildren())
            {
                AccessType childAccess = getAccessType(child, user, perm);
                if (childAccess == AccessType.direct || childAccess == AccessType.indirect)
                {
                    // They can access a subfolder, so give them indirect access so they can see but not use it
                    return AccessType.indirect;
                }
            }
            // No access to the folder or any of its subfolders
            return AccessType.none;
        }

        protected JSONObject getContainerProps(Container c, boolean showContainerTabs)
        {
            JSONObject props = new JSONObject();
            props.put("id", c.getRowId());
            props.put("text", PageFlowUtil.filter(c.getName()));
            props.put("containerPath", c.getPath());
            props.put("expanded", false);
//            props.put("leaf", !c.hasChildren());  // commented out because you cannot 'drop' on a leaf as an append action
            props.put("iconCls", "x4-tree-icon-parent");
            props.put("isContainerTab", c.isContainerTab());
            props.put("folderTypeHasContainerTabs", c.getFolderType().hasContainerTabs());
            props.put("containerTabTypeOveridden", ContainerManager.getContainerTabTypeOverridden(c));
            return props;
        }
    }

    @RequiresPermissionClass(ReadPermission.class)
    public class GetExtSecurityContainerTreeAction extends GetExtContainerTreeAction
    {
        @Override
        protected JSONObject getContainerProps(Container c, boolean showContainerTabs)
        {
            JSONObject props = super.getContainerProps(c, showContainerTabs);
            String text = PageFlowUtil.filter(c.getName());
            if (!c.getPolicy().getResourceId().equals(c.getResourceId()))
                text += "*";
            if (c.equals(getViewContext().getContainer()))
                props.put("cls", "x-tree-node-current");

            props.put("text", text);

            ActionURL url = new ActionURL(SecurityController.ProjectAction.class, c);
            props.put("href", url.getLocalURIString());

            //if the current container is an ancestor of the request container
            //recurse into the children so that we can show the request container
            if (getViewContext().getContainer().isDescendant(c))
            {
                JSONArray childrenProps = new JSONArray();
                for (Container child : c.getChildren())
                {
                    if (!child.isWorkbook() && (showContainerTabs || !child.isContainerTab()))
                    {
                        AccessType accessType = getAccessType(child, getUser(), _reqPerm);
                        if (accessType != AccessType.none)
                        {
                            JSONObject childProps = getContainerProps(child, showContainerTabs);
                            if (accessType == AccessType.indirect)
                            {
                                // Disable so they can't act on it directly, since they have no permission
                                childProps.put("disabled", true);
                            }
                            childProps.put("expanded", getViewContext().getContainer().isDescendant(child));
                            childrenProps.put(childProps);
                        }
                    }
                }
                props.put("children", childrenProps);
                props.put("expanded", true);
            }
            
            return props;
        }
    }

    @RequiresPermissionClass(ReadPermission.class)
    public class GetExtMWBContainerTreeAction extends GetExtContainerTreeAction
    {
        @Override
        protected JSONObject getContainerProps(Container c, boolean showContainerTabs)
        {
            JSONObject props = super.getContainerProps(c, showContainerTabs);
            if (c.equals(getViewContext().getContainer()))
                props.put("disabled", true);
            return props;
        }
    }

    @RequiresPermissionClass(ReadPermission.class)
    public class GetExtContainerAdminTreeAction extends GetExtContainerTreeAction
    {
        @Override
        protected JSONObject getContainerProps(Container c, boolean showContainerTabs)
        {
            JSONObject props = super.getContainerProps(c, showContainerTabs);
            if (c.equals(getViewContext().getContainer()))
            {
                props.put("cls", "x-tree-node-current");
                if (_move)
                    props.put("hidden", true);
            }

            props.put("isProject", c.isProject());

            if (ContainerManager.getHomeContainer().equals(c) || ContainerManager.getSharedContainer().equals(c) ||
                    ContainerManager.getRoot().equals(c))
            {
                props.put("notModifiable", true);
            }

            //if the current container is an ancestor of the request container
            //recurse into the children so that we can show the request container
            if (getViewContext().getContainer().isDescendant(c))
            {
                JSONArray childrenProps = new JSONArray();
                for (Container child : c.getChildren())
                {
                    if (!child.isWorkbook() && (showContainerTabs || !child.isContainerTab()))
                    {
                        AccessType accessType = getAccessType(child, getUser(), _reqPerm);
                        if (accessType != AccessType.none)
                        {
                            JSONObject childProps = getContainerProps(child, showContainerTabs);
                            //childProps.put("expanded", true);
                            if (accessType == AccessType.indirect)
                            {
                                // Disable so they can't act on it directly, since they have no permission
                                childProps.put("disabled", true);
                            }
                            childrenProps.put(childProps);
                        }
                    }
                }
                props.put("children", childrenProps);
                props.put("expanded", true);
            }

            return props;
        }
    }
    
    public static class MoveWorkbookForm
    {
        public int _workbookId = -1;
        public int _newParentId = -1;

        public int getNewParentId()
        {
            return _newParentId;
        }

        public void setNewParentId(int newParentId)
        {
            _newParentId = newParentId;
        }

        public int getWorkbookId()
        {

            return _workbookId;
        }

        public void setWorkbookId(int workbookId)
        {
            _workbookId = workbookId;
        }
    }

    @RequiresPermissionClass(AdminPermission.class)
    public class MoveWorkbookAction extends MutatingApiAction<MoveWorkbookForm>
    {
        public ApiResponse execute(MoveWorkbookForm form, BindException errors) throws Exception
        {
            if (form.getWorkbookId() < 0)
                throw new IllegalArgumentException("You must supply a workbookId parameter!");
            if (form.getNewParentId() < 0)
                throw new IllegalArgumentException("You must specify a newParentId parameter!");

            Container wb = ContainerManager.getForRowId(form.getWorkbookId());
            if (null == wb || !(wb.isWorkbook()) || !(wb.isDescendant(getViewContext().getContainer())))
                throw new IllegalArgumentException("No workbook found with id '" + form.getWorkbookId() + "'");

            Container newParent = ContainerManager.getForRowId(form.getNewParentId());
            if (null == newParent || newParent.isWorkbook())
                throw new IllegalArgumentException("No folder found with id '" + form.getNewParentId() + "'");

            if (wb.getParent().equals(newParent))
                throw new IllegalArgumentException("Workbook is already in the target folder.");

            //user must be allowed to create workbooks in the new parent folder
            if (!newParent.hasPermission(getViewContext().getUser(), InsertPermission.class))
                throw new UnauthorizedException("You do not have permission to move workbooks to the folder '" + newParent.getName() + "'.");

            //workbook name must be unique within parent
            if (newParent.hasChild(wb.getName()))
                throw new RuntimeException("Can't move workbook '" + wb.getTitle() + "' because another workbook or subfolder in the target folder has the same name.");

            ContainerManager.move(wb, newParent, getViewContext().getUser());

            return new ApiSimpleResponse("moved", true);
        }
    }

    @RequiresPermissionClass(ReadPermission.class)
    public class GetFolderTypesAction extends ApiAction<Object>
    {
        @Override
        public ApiResponse execute(Object form, BindException errors) throws Exception
        {
            Map<String, Object> folderTypes = new HashMap<>();
            for (FolderType folderType : ModuleLoader.getInstance().getEnabledFolderTypes())
            {
                Map<String, Object> folderTypeJSON = new HashMap<>();
                folderTypeJSON.put("name", folderType.getName());
                folderTypeJSON.put("description", folderType.getDescription());
                folderTypeJSON.put("defaultModule", folderType.getDefaultModule() == null ? null : folderType.getDefaultModule().getName());
                folderTypeJSON.put("label", folderType.getLabel());
                folderTypeJSON.put("workbookType", folderType.isWorkbookType());
                List<String> activeModulesJSON = new ArrayList<>();
                for (Module module : folderType.getActiveModules())
                {
                    activeModulesJSON.add(module.getName());
                }
                folderTypeJSON.put("activeModules", activeModulesJSON);
                folderTypeJSON.put("requiredWebParts", toJSON(folderType.getRequiredWebParts()));
                folderTypeJSON.put("preferredWebParts", toJSON(folderType.getPreferredWebParts()));
                folderTypes.put(folderType.getName(), folderTypeJSON);
            }
            return new ApiSimpleResponse(folderTypes);
        }

        private List<Map<String, Object>> toJSON(List<Portal.WebPart> webParts)
        {
            List<Map<String, Object>> result = new ArrayList<>();
            for (Portal.WebPart webPart : webParts)
            {
                Map<String, Object> webPartJSON = new HashMap<>();
                webPartJSON.put("name", webPart.getName());
                webPartJSON.put("properties", webPart.getPropertyMap());
                result.add(webPartJSON);
            }
            return result;
        }
    }

    @RequiresPermissionClass(ReadPermission.class)
    public class StyleOverviewAction extends SimpleViewAction
    {
        @Override
        public ModelAndView getView(Object o, BindException errors) throws Exception
        {
            return new JspView("/org/labkey/core/styling.jsp");
        }

        @Override
        public NavTree appendNavTrail(NavTree root)
        {
            return root.addChild("Styling Overview");
        }
    }

    @RequiresPermissionClass(UpdatePermission.class) @RequiresLogin
    public class GetModulePropertiesAction extends ApiAction<ModulePropertiesForm>
    {
        @Override
        public ApiResponse execute(ModulePropertiesForm form, BindException errors) throws Exception
        {
            JSONObject ret = new JSONObject();

            if(form.getModuleName() == null)
            {
                errors.reject(ERROR_MSG, "Must provide the name of the module");
                return null;
            }

            Module m = ModuleLoader.getInstance().getModule(form.getModuleName());
            if (m == null)
            {
                errors.reject(ERROR_MSG, "Unknown module: " + form.getModuleName());
                return null;
            }

            List<ModuleProperty> included = new ArrayList<>();
            if(form.getProperties() == null)
            {
                included.addAll(m.getModuleProperties().values());
            }
            else
            {
                for (String name : form.getProperties())
                    included.add(m.getModuleProperties().get(name));
            }

            if(form.isIncludePropertyValues())
            {
                JSONObject siteValues = new JSONObject();
                for (ModuleProperty mp : included)
                {
                    JSONObject record = new JSONObject();

                    Container c = mp.isCanSetPerContainer() ? getContainer() :  ContainerManager.getRoot();
                    User propUser = PropertyManager.SHARED_USER;   //currently user-specific props not supported
                    int propUserId = propUser.getUserId();

                    Map<Container, Map<Integer, String>> propValues = PropertyManager.getPropertyValueAndAncestors(propUser, c, mp.getCategory(), mp.getName(), true);
                    List<JSONObject> containers = new ArrayList<>();
                    for (Container ct : propValues.keySet())
                    {
                        JSONObject o = new JSONObject();
                        o.put("value", propValues.get(ct) != null && propValues.get(ct).get(propUserId) != null ? propValues.get(ct).get(propUserId) : "");
                        o.put("container", ct.toJSON(getUser()));
                        boolean canEdit = true;
                        for (Class<? extends Permission> p : mp.getEditPermissions())
                        {
                            if (!ct.hasPermission(getUser(), p))
                            {
                                canEdit = false;
                                break;
                            }
                        }
                        o.put("canEdit", canEdit);

                        containers.add(o);
                        ct = ct.getParent();
                    }
                    record.put("effectiveValue", mp.getEffectiveValue(getContainer()));
                    Collections.reverse(containers);  //reverse so root first
                    record.put("siteValues", containers);

                    siteValues.put(mp.getName(), record);
                }
                ret.put("values", siteValues);
            }

            if(form.isIncludePropertyDescriptors())
            {
                Map<String, JSONObject> pds = new HashMap<>();
                for (ModuleProperty mp : included)
                {
                    pds.put(mp.getName(), mp.toJson());
                }

                ret.put("properties", pds);
            }

            return new ApiSimpleResponse(ret);
        }
    }

    static class ModulePropertiesForm
    {
        private String _moduleName;
        private String[] _properties;
        private boolean _includePropertyDescriptors;
        private boolean _includePropertyValues;

        public String getModuleName()
        {
            return _moduleName;
        }

        public void setModuleName(String moduleName)
        {
            _moduleName = moduleName;
        }

        public String[] getProperties()
        {
            return _properties;
        }

        public void setProperties(String[] properties)
        {
            _properties = properties;
        }

        public boolean isIncludePropertyDescriptors()
        {
            return _includePropertyDescriptors;
        }

        public void setIncludePropertyDescriptors(boolean includePropertyDescriptors)
        {
            _includePropertyDescriptors = includePropertyDescriptors;
        }

        public boolean isIncludePropertyValues()
        {
            return _includePropertyValues;
        }

        public void setIncludePropertyValues(boolean includePropertyValues)
        {
            _includePropertyValues = includePropertyValues;
        }
    }

    @RequiresPermissionClass(ReadPermission.class) @RequiresLogin
    public class SaveModulePropertiesAction extends ApiAction<SaveModulePropertiesForm>
    {
        @Override
        public ApiResponse execute(SaveModulePropertiesForm form, BindException errors) throws Exception
        {
            ViewContext ctx = getViewContext();
            JSONObject formData = form.getJsonObject();
            JSONArray a = formData.getJSONArray("properties");
            try (DbScope.Transaction transaction = ExperimentService.get().ensureTransaction())
            {
                for (int i = 0 ; i < a.length(); i++)
                {
                    JSONObject row = a.getJSONObject(i);
                    String moduleName = row.getString("moduleName");
                    String name = row.getString("propName");
                    if (moduleName == null)
                        throw new IllegalArgumentException("Missing moduleName for property: " + name);
                    if (name == null)
                        throw new IllegalArgumentException("Missing property name");

                    Module m = ModuleLoader.getInstance().getModule(moduleName);
                    if (m == null)
                        throw new IllegalArgumentException("Unknown module: " + moduleName);

                    ModuleProperty mp = m.getModuleProperties().get(name);
                    if (mp == null)
                        throw new IllegalArgumentException("Invalid module property: " + name);

                    Container ct = ContainerManager.getForId(row.getString("container"));
                    if (ct == null)
                        throw new IllegalArgumentException("Invalid container: " + row.getString("container"));

                    User saveUser = UserManager.getUser(row.getInt("userId"));
                    if (saveUser == null)
                        throw new IllegalArgumentException("Invalid user: " + row.getInt("userId"));

                    mp.saveValue(ctx.getUser(), ct, row.getString("value"));
                }
                transaction.commit();
            }
            catch (IllegalArgumentException e)
            {
                errors.reject(e.getMessage());
            }

            JSONObject ret = new JSONObject();
            ret.put("success", errors.getErrorCount() == 0);
            return new ApiSimpleResponse(ret);
        }
    }

    public static class SaveModulePropertiesForm extends SimpleApiJsonForm
    {
        String moduleName;
        String properties;

        public String getModuleName()
        {
            return moduleName;
        }

        public void setModuleName(String moduleName)
        {
            this.moduleName = moduleName;
        }

        public String getProperties()
        {
            return properties;
        }

        public void setProperties(String properties)
        {
            this.properties = properties;
        }
    }
}
