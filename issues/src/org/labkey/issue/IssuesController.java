/*
 * Copyright (c) 2004-2011 Fred Hutchinson Cancer Research Center
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

package org.labkey.issue;

import org.apache.commons.collections15.BeanMap;
import org.apache.commons.lang.BooleanUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.math.NumberUtils;
import org.apache.log4j.Logger;
import org.jetbrains.annotations.NotNull;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Assert;
import org.junit.Test;
import org.labkey.api.action.AjaxCompletionAction;
import org.labkey.api.action.ApiAction;
import org.labkey.api.action.ApiResponse;
import org.labkey.api.action.ApiSimpleResponse;
import org.labkey.api.action.FormHandlerAction;
import org.labkey.api.action.FormViewAction;
import org.labkey.api.action.LabkeyError;
import org.labkey.api.action.SimpleViewAction;
import org.labkey.api.action.SpringActionController;
import org.labkey.api.attachments.AttachmentFile;
import org.labkey.api.attachments.AttachmentParent;
import org.labkey.api.attachments.AttachmentService;
import org.labkey.api.data.AttachmentParentEntity;
import org.labkey.api.data.BeanViewForm;
import org.labkey.api.data.ColumnInfo;
import org.labkey.api.data.Container;
import org.labkey.api.data.ContainerManager;
import org.labkey.api.data.DataRegion;
import org.labkey.api.data.DataRegionSelection;
import org.labkey.api.data.DbScope;
import org.labkey.api.data.ObjectFactory;
import org.labkey.api.data.RenderContext;
import org.labkey.api.data.Sort;
import org.labkey.api.data.dialect.SqlDialect;
import org.labkey.api.data.TSVGridWriter;
import org.labkey.api.data.TableInfo;
import org.labkey.api.issues.IssuesSchema;
import org.labkey.api.issues.IssuesUrls;
import org.labkey.api.query.QueryForm;
import org.labkey.api.query.QueryService;
import org.labkey.api.query.QuerySettings;
import org.labkey.api.query.QueryView;
import org.labkey.api.query.UserSchema;
import org.labkey.api.security.Group;
import org.labkey.api.security.RequiresPermissionClass;
import org.labkey.api.security.SecurityManager;
import org.labkey.api.security.User;
import org.labkey.api.security.UserManager;
import org.labkey.api.security.ValidEmail;
import org.labkey.api.security.permissions.AdminPermission;
import org.labkey.api.security.permissions.InsertPermission;
import org.labkey.api.security.permissions.Permission;
import org.labkey.api.security.permissions.ReadPermission;
import org.labkey.api.security.permissions.UpdatePermission;
import org.labkey.api.security.roles.OwnerRole;
import org.labkey.api.security.roles.RoleManager;
import org.labkey.api.services.ServiceRegistry;
import org.labkey.api.settings.AppProps;
import org.labkey.api.settings.LookAndFeelProperties;
import org.labkey.api.util.ExceptionUtil;
import org.labkey.api.util.GUID;
import org.labkey.api.util.HString;
import org.labkey.api.util.HStringBuilder;
import org.labkey.api.util.HelpTopic;
import org.labkey.api.util.IdentifierString;
import org.labkey.api.util.MailHelper;
import org.labkey.api.util.PageFlowUtil;
import org.labkey.api.util.ResultSetUtil;
import org.labkey.api.util.ReturnURLString;
import org.labkey.api.util.URLHelper;
import org.labkey.api.util.emailTemplate.EmailTemplateService;
import org.labkey.api.view.ActionURL;
import org.labkey.api.view.AjaxCompletion;
import org.labkey.api.view.HtmlView;
import org.labkey.api.view.HttpView;
import org.labkey.api.view.JspView;
import org.labkey.api.view.NavTree;
import org.labkey.api.view.NotFoundException;
import org.labkey.api.view.RedirectException;
import org.labkey.api.view.TermsOfUseException;
import org.labkey.api.view.UnauthorizedException;
import org.labkey.api.view.ViewContext;
import org.labkey.api.view.WebPartView;
import org.labkey.api.view.template.PageConfig;
import org.labkey.api.wiki.WikiRendererType;
import org.labkey.api.wiki.WikiService;
import org.labkey.issue.model.Issue;
import org.labkey.issue.model.IssueManager;
import org.labkey.issue.query.IssuesQuerySchema;
import org.springframework.validation.BindException;
import org.springframework.validation.Errors;
import org.springframework.validation.MapBindingResult;
import org.springframework.validation.ObjectError;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.Controller;
import sun.java2d.pipe.SpanShapeRenderer;

import javax.mail.Address;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;

public class IssuesController extends SpringActionController
{
    private static final Logger _log = Logger.getLogger(IssuesController.class);

    private static final String helpTopic = "issues";

    // keywords enum
    public static final int ISSUE_NONE = 0;
    public static final int ISSUE_AREA = 1;
    public static final int ISSUE_TYPE = 2;
    public static final int ISSUE_MILESTONE = 3;
    public static final int ISSUE_STRING1 = 4;
    public static final int ISSUE_STRING2 = 5;
    public static final int ISSUE_PRIORITY = 6;
    public static final int ISSUE_RESOLUTION = 7;
    public static final int ISSUE_STRING3 = 8;
    public static final int ISSUE_STRING4 = 9;
    public static final int ISSUE_STRING5 = 10;

    public static final String TYPE_STRING = "type";
    public static final String AREA_STRING = "area";
    public static final String PRIORITY_STRING = "priority";
    public static final String MILESTONE_STRING = "milestone";
    public static final String RESOLUTION_STRING = "resolution";
    public static final String STRING_1_STRING = "string1";
    public static final String STRING_2_STRING = "string2";
    public static final String STRING_3_STRING = "string3";
    public static final String STRING_4_STRING = "string4";
    public static final String STRING_5_STRING = "string5";

    private static final DefaultActionResolver _actionResolver = new DefaultActionResolver(IssuesController.class);

    public IssuesController() throws Exception
    {
        setActionResolver(_actionResolver);
    }


    public static class IssuesUrlsImpl implements IssuesUrls
    {
        @Override
        public ActionURL getDetailsURL(Container c)
        {
            return new ActionURL(DetailsAction.class, c);
        }
    }


    public static ActionURL getDetailsURL(Container c, Integer issueId, boolean print)
    {
        ActionURL url = new ActionURL(DetailsAction.class, c);

        if (print)
            url.addParameter("_print", "1");

        if (null != issueId)
            url.addParameter("issueId", issueId.toString());

        return url;
    }


    @Override
    public PageConfig defaultPageConfig()
    {
        PageConfig config = super.defaultPageConfig();
        config.setHelpTopic(new HelpTopic(helpTopic));

        String templateHeader = getViewContext().getRequest().getHeader("X-TEMPLATE");
        if (!StringUtils.isEmpty(templateHeader))
        {
            try { config.setTemplate(PageConfig.Template.valueOf(templateHeader)); } catch (IllegalArgumentException x) { /* */ }
        }

        return config;
    }

    /**
     * @param redirect if the issue isn't in this container, whether to redirect the browser to same URL except in the
     * issue's parent container
     * @throws RedirectException if the issue lives in another container and the user has at least read permission to it
     */
    private Issue getIssue(int issueId, boolean redirect) throws RedirectException
    {
        Issue result = IssueManager.getIssue(redirect ? null : getContainer(), issueId);
        // See if it's from a different container
        if (result != null && redirect && !result.getContainerId().equals(getContainer().getId()))
        {
            Container issueContainer = ContainerManager.getForId(result.getContainerId());
            // Make sure the user has read permission before redirecting
            if (issueContainer.hasPermission(getViewContext().getUser(), ReadPermission.class))
            {
                ActionURL url = getViewContext().getActionURL().clone();
                url.setContainer(issueContainer);
                throw new RedirectException(url);
            }
            return null;
        }
        return result;
    }


    private ActionURL issueURL(Class<? extends Controller> action)
    {
        return new ActionURL(action, getContainer());
    }


    public static ActionURL issueURL(Container c, Class<? extends Controller> action)
    {
        return new ActionURL(action, c);
    }


    @RequiresPermissionClass(ReadPermission.class)
    public class BeginAction extends SimpleViewAction
    {
        public ModelAndView getView(Object o, BindException errors) throws Exception
        {
            return HttpView.redirect(getListURL(getContainer()));
        }

        public NavTree appendNavTrail(NavTree root)
        {
            return root.addChild("Issues", getListURL(getContainer()));
        }
    }


    private IssueManager.CustomColumnConfiguration getCustomColumnConfiguration() throws SQLException, ServletException
    {
        return IssueManager.getCustomColumnConfiguration(getContainer());
    }


    private Map<String, String> getColumnCaptions() throws SQLException, ServletException
    {
        return getCustomColumnConfiguration().getColumnCaptions();
    }


    public static ActionURL getListURL(Container c)
    {
        ActionURL url = new ActionURL(ListAction.class, c);
        url.addParameter(DataRegion.LAST_FILTER_PARAM, "true");
        return url;
    }


    private ResultSet getIssuesResultSet() throws IOException, SQLException, ServletException
    {
        UserSchema schema = QueryService.get().getUserSchema(getUser(), getContainer(), IssuesQuerySchema.SCHEMA_NAME);
        QuerySettings settings = schema.getSettings(getViewContext(), IssuesQuerySchema.TableType.Issues.name());
        settings.setQueryName(IssuesQuerySchema.TableType.Issues.name());

        QueryView queryView = schema.createView(getViewContext(), settings, null);

        return queryView.getResultSet();
    }


    @RequiresPermissionClass(ReadPermission.class)
    public class ListAction extends SimpleViewAction<ListForm>
    {
        public ListAction() {}

        public ListAction(ViewContext ctx)
        {
            setViewContext(ctx);
        }

        public ModelAndView getView(ListForm form, BindException errors) throws Exception
        {
            IssueManager.EntryTypeNames names = IssueManager.getEntryTypeNames(getViewContext().getContainer());

            // convert AssignedTo/Email to AssignedTo/DisplayName: old bookmarks
            // reference Email, which is no longer displayed.
            ActionURL url = getViewContext().cloneActionURL();
            String[] emailFilters = url.getKeysByPrefix(IssuesQuerySchema.TableType.Issues.name() + ".AssignedTo/Email");
            if (emailFilters != null && emailFilters.length > 0)
            {
                for (String emailFilter : emailFilters)
                    url.deleteParameter(emailFilter);
                return HttpView.redirect(url);
            }

            getPageConfig().setRssProperties(new RssAction().getUrl(), names.pluralName.toString());

            return new IssuesListView();
        }

        public NavTree appendNavTrail(NavTree root)
        {
            IssueManager.EntryTypeNames names = IssueManager.getEntryTypeNames(getViewContext().getContainer());
            return root.addChild(names.pluralName + " List", getURL());
        }

        public ActionURL getURL()
        {
            return issueURL(ListAction.class).addParameter(".lastFilter","true");
        }
    }


    @RequiresPermissionClass(ReadPermission.class)
    public class ExportTsvAction extends SimpleViewAction<QueryForm>
    {
        public ModelAndView getView(QueryForm form, BindException errors) throws Exception
        {
            getPageConfig().setTemplate(PageConfig.Template.None);
            QueryView view = QueryView.create(form, errors);
            final TSVGridWriter writer = view.getTsvWriter();
            return new HttpView()
            {
                @Override
                protected void renderInternal(Object model, HttpServletRequest request, HttpServletResponse response) throws Exception
                {
                    writer.setColumnHeaderType(TSVGridWriter.ColumnHeaderType.caption);
                    writer.write(getViewContext().getResponse());
                }
            };
        }

        public NavTree appendNavTrail(NavTree root)
        {
            return null;
        }
    }

    @RequiresPermissionClass(ReadPermission.class)
    public class DetailsAction extends SimpleViewAction<IssueIdForm>
    {
        Issue _issue = null;

        public DetailsAction()
        {
        }

        public DetailsAction(Issue issue, ViewContext context)
        {
            _issue = issue;
            setViewContext(context);
        }

        public ModelAndView getView(IssueIdForm form, BindException errors) throws Exception
        {
            int issueId = form.getIssueId();
            _issue = getIssue(issueId, true);

            IssueManager.EntryTypeNames names = IssueManager.getEntryTypeNames(getViewContext().getContainer());
            if (null == _issue)
            {
                throw new NotFoundException("Unable to find " + names.singularName + " " + form.getIssueId());
            }

            IssuePage page = new IssuePage();
            page.setPrint(isPrint());
            page.setIssue(_issue);
            page.setCustomColumnConfiguration(getCustomColumnConfiguration());
            //pass user's update perms to jsp page to determine whether to show notify list
            page.setUserHasUpdatePermissions(hasUpdatePermission(getUser(), _issue));
            page.setRequiredFields(IssueManager.getRequiredIssueFields(getContainer()));

            return new JspView<IssuePage>("/org/labkey/issue/detailView.jsp", page);
        }

        public NavTree appendNavTrail(NavTree root)
        {
            return new ListAction(getViewContext()).appendNavTrail(root)
                    .addChild(getSingularEntityName() + " " + _issue.getIssueId() + ": " + _issue.getTitle().getSource(), getURL());
        }

        public ActionURL getURL()
        {
            return issueURL(DetailsAction.class).addParameter("issueId", _issue.getIssueId());
        }
    }

    private HString getSingularEntityName()
    {
        return IssueManager.getEntryTypeNames(getContainer()).singularName;
    }


    @RequiresPermissionClass(ReadPermission.class)
    public class DetailsListAction extends SimpleViewAction<ListForm>
    {
        public ModelAndView getView(ListForm listForm, BindException errors) throws Exception
        {
            // convert AssignedTo/Email to AssignedTo/DisplayName: old bookmarks
            // reference Email, which is no longer displayed.
            ActionURL url = getViewContext().cloneActionURL();
            String[] emailFilters = url.getKeysByPrefix(IssuesQuerySchema.TableType.Issues.name() + ".AssignedTo/Email");
            if (emailFilters != null && emailFilters.length > 0)
            {
                for (String emailFilter : emailFilters)
                    url.deleteParameter(emailFilter);
                return HttpView.redirect(url);
            }

            Set<String> issueIds = DataRegionSelection.getSelected(getViewContext(), false);
            ArrayList<Issue> issueList = new ArrayList<Issue>();

            if (!issueIds.isEmpty())
            {
                for (String issueId : issueIds)
                {
                    issueList.add(getIssue(Integer.parseInt(issueId), false));
                }
            }
            else
            {
                ResultSet rs = null;

                try
                {
                    rs = getIssuesResultSet();
                    int issueColumnIndex = rs.findColumn("issueId");

                    while (rs.next())
                    {
                        issueList.add(getIssue(rs.getInt(issueColumnIndex), false));
                    }
                }
                finally
                {
                    ResultSetUtil.close(rs);
                }
            }

            IssuePage page = new IssuePage();
            JspView v = new JspView<IssuePage>(IssuesController.class, "detailList.jsp", page);

            page.setIssueList(issueList);
            page.setCustomColumnConfiguration(getCustomColumnConfiguration());
            page.setRequiredFields(IssueManager.getRequiredIssueFields(getContainer()));
            page.setDataRegionSelectionKey(listForm.getQuerySettings().getSelectionKey());

            return v;
        }

        public NavTree appendNavTrail(NavTree root)
        {
            IssueManager.EntryTypeNames names = IssueManager.getEntryTypeNames(getViewContext().getContainer());
            return new ListAction(getViewContext()).appendNavTrail(root).addChild(names.singularName + " Details");
        }
    }


    @RequiresPermissionClass(InsertPermission.class)
    public class InsertAction extends FormViewAction<IssuesForm>
    {
        private Issue _issue = null;

        public ModelAndView getView(IssuesForm form, boolean reshow, BindException errors) throws Exception
        {
            // if we have errors, then form.getBean() is likely to throw, but try anyway
            if (errors.hasErrors())
            {
                try
                {
                    _issue = reshow ? form.getBean() : new Issue();
                }
                catch (Exception e)
                {
                    _issue = new Issue();
                }
            }
            else
            {
                _issue = reshow ? form.getBean() : new Issue();
            }

            if (_issue.getAssignedTo() != null)
            {
                User user = UserManager.getUser(_issue.getAssignedTo().intValue());

                if (user != null)
                {
                    _issue.setAssignedTo(user.getUserId());
                }
            }

            _issue.open(getContainer(), getUser());
            if (!reshow || form.getSkipPost())
            {
                // Set the defaults if we're not reshowing after an error, or if this is a request to open an issue
                // from a mothership which comes in as a POST and is therefore considered a reshow 
                setNewIssueDefaults(_issue);
            }

            IssuePage page = new IssuePage();
            JspView v = new JspView<IssuePage>(IssuesController.class, "updateView.jsp", page);

            IssueManager.CustomColumnConfiguration ccc = getCustomColumnConfiguration();

            page.setAction(InsertAction.class);
            page.setIssue(_issue);
            page.setPrevIssue(_issue);
            page.setCustomColumnConfiguration(ccc);
            page.setBody(form.getComment() == null ? form.getBody() : form.getComment());
            page.setCallbackURL(form.getCallbackURL());
            page.setEditable(getEditableFields(page.getAction(), ccc));
            page.setRequiredFields(IssueManager.getRequiredIssueFields(getContainer()));
            page.setErrors(errors);

            return v;
        }

        public void validateCommand(IssuesForm form, Errors errors)
        {
            if (!form.getSkipPost())
            {
                validateRequiredFields(form, errors);
                validateNotifyList(form.getBean(), form, errors);
            }
        }

        public boolean handlePost(IssuesForm form, BindException errors) throws Exception
        {
            if (form.getSkipPost())
                return false;

            Container c = getContainer();
            User user = getUser();

            _issue = form.getBean();
            _issue.open(c, user);
            validateNotifyList(_issue, form, errors);

            ChangeSummary changeSummary;

            DbScope scope = IssuesSchema.getInstance().getSchema().getScope();
            try
            {
                scope.ensureTransaction();
                // for new issues, the original is always the default.
                Issue orig = new Issue();
                orig.open(getContainer(), getUser());

                changeSummary = createChangeSummary(_issue, orig, null, user, form.getAction(), form.getComment(), getColumnCaptions(), getUser());
                IssueManager.saveIssue(user, c, _issue);
                AttachmentService.get().addAttachments(changeSummary.getComment(), getAttachmentFileList(), user);
                scope.commitTransaction();
            }
            catch (Exception x)
            {
                Throwable ex = x.getCause() == null ? x : x.getCause();
                String error = ex.getMessage();
                _log.debug("IssuesController.doInsert", x);
                _issue.open(c, user);

                errors.addError(new LabkeyError(error));
                return false;
            }
            finally
            {
                scope.closeConnection();
            }

            ActionURL url = new DetailsAction(_issue, getViewContext()).getURL();

            final String assignedTo = UserManager.getDisplayName(_issue.getAssignedTo(), user);
            if (assignedTo != null)
                sendUpdateEmail(_issue, null, changeSummary.getTextChanges(), changeSummary.getSummary(), form.getComment(), url, "opened and assigned to " + assignedTo, getAttachmentFileList(), form.getAction());
            else
                sendUpdateEmail(_issue, null, changeSummary.getTextChanges(), changeSummary.getSummary(), form.getComment(), url, "opened", getAttachmentFileList(), form.getAction());

            return true;
        }


        public ActionURL getSuccessURL(IssuesForm issuesForm)
        {
            if (!StringUtils.isEmpty(issuesForm.getCallbackURL()))
            {
                ActionURL url = new ActionURL(issuesForm.getCallbackURL());
                url.addParameter("issueId", _issue.getIssueId());
                return url;
            }

            return new DetailsAction(_issue, getViewContext()).getURL();
        }


        public NavTree appendNavTrail(NavTree root)
        {
            IssueManager.EntryTypeNames names = IssueManager.getEntryTypeNames(getViewContext().getContainer());
            return new ListAction(getViewContext()).appendNavTrail(root).addChild("Insert New " + names.singularName);
        }
    }


    private Issue setNewIssueDefaults(Issue issue) throws SQLException, ServletException
    {
        Map<Integer, HString> defaults = IssueManager.getAllDefaults(getContainer());

        issue.setArea(defaults.get(ISSUE_AREA));
        issue.setType(defaults.get(ISSUE_TYPE));
        issue.setMilestone(defaults.get(ISSUE_MILESTONE));
        IssueManager.CustomColumnConfiguration config = IssueManager.getCustomColumnConfiguration(getContainer());
        // For each of the string configurable columns,
        // only set the default if the column is currently configured as a pick list
        if (config.getPickListColumns().contains("string1"))
        {
            issue.setString1(defaults.get(ISSUE_STRING1));
        }
        if (config.getPickListColumns().contains("string2"))
        {
            issue.setString2(defaults.get(ISSUE_STRING2));
        }
        if (config.getPickListColumns().contains("string3"))
        {
            issue.setString3(defaults.get(ISSUE_STRING3));
        }
        if (config.getPickListColumns().contains("string4"))
        {
            issue.setString4(defaults.get(ISSUE_STRING4));
        }
        if (config.getPickListColumns().contains("string5"))
        {
            issue.setString5(defaults.get(ISSUE_STRING5));
        }

        HString priority = defaults.get(ISSUE_PRIORITY);
        issue.setPriority(null != priority ? priority.parseInt() : 3);

        return issue;
    }


    protected abstract class IssueUpdateAction extends FormViewAction<IssuesForm>
    {
        Issue _issue = null;

        public boolean handlePost(IssuesForm form, BindException errors) throws Exception
        {
            Container c = getContainer();
            User user = getUser();

            Issue issue = form.getBean();
            Issue prevIssue = (Issue)form.getOldValues();
            requiresUpdatePermission(user, issue);
            ActionURL detailsUrl;

            // clear resolution, resolvedBy, and duplicate fields
            if (ReopenAction.class.equals(form.getAction()))
                issue.beforeReOpen();

            Issue duplicateOf = null;
            if (ResolveAction.class.equals(form.getAction()) &&
                    issue.getResolution().getSource().equals("Duplicate") &&
                    issue.getDuplicate() != null &&
                    !issue.getDuplicate().equals(prevIssue.getDuplicate()))
            {
                if (issue.getDuplicate().intValue() == issue.getIssueId())
                {
                    errors.rejectValue("Duplicate", ERROR_MSG, "An issue may not be a duplicate of itself");
                    return false;
                }
                duplicateOf = IssueManager.getIssue(c, issue.getDuplicate().intValue());
                if (duplicateOf == null)
                {
                    errors.rejectValue("Duplicate", ERROR_MSG, "Duplicate issue '" + issue.getDuplicate().intValue() + "' not found");
                    return false;
                }
            }

            ChangeSummary changeSummary;
            DbScope scope = IssuesSchema.getInstance().getSchema().getScope();

            try
            {
                scope.ensureTransaction();
                detailsUrl = new DetailsAction(issue, getViewContext()).getURL();

                if (ResolveAction.class.equals(form.getAction()))
                    issue.resolve(user);
                else if (InsertAction.class.equals(form.getAction()) || ReopenAction.class.equals(form.getAction()))
                    issue.open(c, user);
                else if (CloseAction.class.equals(form.getAction()))
                    issue.close(user);
                else
                    issue.change(user);

                changeSummary = createChangeSummary(issue, prevIssue, duplicateOf, user, form.getAction(), form.getComment(), getColumnCaptions(), getUser());
                IssueManager.saveIssue(user, c, issue);
                AttachmentService.get().addAttachments(changeSummary.getComment(), getAttachmentFileList(), user);

                if (duplicateOf != null)
                {
                    HStringBuilder hsb = new HStringBuilder();
                    hsb.append("<em>Issue ").append(issue.getIssueId()).append(" marked as duplicate of this bug.</em>");
                    Issue.Comment dupComment = duplicateOf.addComment(user, hsb.toHString());
                    IssueManager.saveIssue(user, c, duplicateOf);
                }

                scope.commitTransaction();
            }
            catch (IOException x)
            {
                String message = x.getMessage() == null ? x.toString() : x.getMessage();
                errors.addError(new ObjectError("main", new String[] {"Error"}, new Object[] {message}, message));
                return false;
            }
            finally
            {
                scope.closeConnection();
            }

            // Send update email...
            //    ...if someone other than "created by" is closing a bug
            //    ...if someone other than "assigned to" is updating, reopening, or resolving a bug
            String change = ReopenAction.class.equals(form.getAction()) ? "reopened" : getActionName(form.getAction()) + "d";
            if ("resolved".equalsIgnoreCase(change) && issue.getResolution() != null)
            {
                change += " as " + issue.getResolution();
            }
            sendUpdateEmail(issue, prevIssue, changeSummary.getTextChanges(), changeSummary.getSummary(), form.getComment(), detailsUrl, change, getAttachmentFileList(), form.getAction());
            return true;
        }

        public void validateCommand(IssuesForm form, Errors errors)
        {
            validateRequiredFields(form, errors);
            validateNotifyList(form.getBean(), form, errors);
        }

        public ActionURL getSuccessURL(IssuesForm form)
        {
            return form.getForwardURL();
        }
    }



    // SAME as AttachmentForm, just to demonstrate GuidString
    public static class _AttachmentForm
    {
        private GUID _entityId = null;
        private String _name = null;


        public GUID getEntityId()
        {
            return _entityId;
        }


        public void setEntityId(GUID entityId)
        {
            _entityId = entityId;
        }


        public String getName()
        {
            return _name;
        }


        public void setName(String name)
        {
            _name = name;
        }
    }

    


    @RequiresPermissionClass(ReadPermission.class)
    public class DownloadAction extends SimpleViewAction<_AttachmentForm>
    {
        public ModelAndView getView(final _AttachmentForm form, BindException errors) throws Exception
        {
            if (form.getEntityId() != null && form.getName() != null)
            {
                getPageConfig().setTemplate(PageConfig.Template.None);
                final AttachmentParent parent = new IssueAttachmentParent(getContainer(), form.getEntityId());

                return new HttpView()
                {
                    protected void renderInternal(Object model, HttpServletRequest request, HttpServletResponse response) throws Exception
                    {
                        AttachmentService.get().download(response, parent, form.getName());
                    }
                };
            }
            return null;
        }

        public NavTree appendNavTrail(NavTree root)
        {
            return null;
        }
    }


    public class IssueAttachmentParent extends AttachmentParentEntity
    {
        public IssueAttachmentParent(Container c, GUID entityId)
        {
            setContainer(c.getId());
            setEntityId(null==entityId?null:entityId.toString());
        }
    }


    @RequiresPermissionClass(ReadPermission.class)
    public class UpdateAction extends IssueUpdateAction
    {
        public ModelAndView getView(IssuesForm form, boolean reshow, BindException errors) throws Exception
        {
            int issueId = form.getIssueId();
            _issue = getIssue(issueId, true);
            if (_issue == null)
            {
                throw new NotFoundException();
            }

            Issue prevIssue = (Issue)_issue.clone();
            User user = getUser();
            requiresUpdatePermission(user, _issue);

            IssuePage page = new IssuePage();
            JspView v = new JspView<IssuePage>("/org/labkey/issue/updateView.jsp", page);

            IssueManager.CustomColumnConfiguration ccc = getCustomColumnConfiguration();

            page.setAction(UpdateAction.class);
            page.setIssue(_issue);
            page.setPrevIssue(prevIssue);
            page.setCustomColumnConfiguration(ccc);
            page.setBody(form.getComment());
            page.setEditable(getEditableFields(page.getAction(), ccc));
            page.setRequiredFields(IssueManager.getRequiredIssueFields(getContainer()));
            page.setErrors(errors);

            return v;
        }

        public NavTree appendNavTrail(NavTree root)
        {
            return new DetailsAction(_issue, getViewContext()).appendNavTrail(root)
                    .addChild("Update " + getSingularEntityName() + ": " + _issue.getTitle().getSource());
        }
    }


    private Set<String> getEditableFields(Class<? extends Controller> action, IssueManager.CustomColumnConfiguration ccc)
    {
        final Set<String> editable = new HashSet<String>(20);

        editable.add("title");
        editable.add("assignedTo");
        editable.add("type");
        editable.add("area");
        editable.add("priority");
        editable.add("milestone");
        editable.add("comments");
        editable.add("attachments");

        for (String columnName : ccc.getColumnCaptions().keySet())
            editable.add(columnName);

        //if (!"insert".equals(action))
        editable.add("notifyList");

        if (ResolveAction.class.equals(action))
        {
            editable.add("resolution");
            editable.add("duplicate");
        }

        return editable;
    }


    @RequiresPermissionClass(ReadPermission.class)
    public class ResolveAction extends IssueUpdateAction
    {
        public ModelAndView getView(IssuesForm form, boolean reshow, BindException errors) throws Exception
        {
            int issueId = form.getIssueId();
            _issue = getIssue(issueId, true);
            if (null == _issue)
            {
                throw new NotFoundException();
            }

            Issue prevIssue = (Issue)_issue.clone();
            User user = getUser();
            requiresUpdatePermission(user, _issue);

            _issue.beforeResolve(user);

            if (_issue.getResolution().isEmpty())
            {
                Map<Integer, HString> defaults = IssueManager.getAllDefaults(getContainer());

                HString resolution = defaults.get(ISSUE_RESOLUTION);

                if (resolution != null && !resolution.isEmpty())
                    _issue.setResolution(resolution);
            }

            IssuePage page = new IssuePage();
            JspView v = new JspView<IssuePage>(IssuesController.class, "updateView.jsp", page);

            IssueManager.CustomColumnConfiguration ccc = getCustomColumnConfiguration();

            page.setAction(ResolveAction.class);
            page.setIssue(_issue);
            page.setPrevIssue(prevIssue);
            page.setCustomColumnConfiguration(ccc);
            page.setBody(form.getComment());
            page.setEditable(getEditableFields(page.getAction(), ccc));
            page.setRequiredFields(IssueManager.getRequiredIssueFields(getContainer()));
            page.setErrors(errors);

            return v;
        }

        public NavTree appendNavTrail(NavTree root)
        {
            IssueManager.EntryTypeNames names = IssueManager.getEntryTypeNames(getViewContext().getContainer());
            return (new DetailsAction(_issue, getViewContext()).appendNavTrail(root)).addChild("Resolve " + names.singularName);
        }
    }


    @RequiresPermissionClass(ReadPermission.class)
    public class CloseAction extends IssueUpdateAction
    {
        public ModelAndView getView(IssuesForm form, boolean reshow, BindException errors) throws Exception
        {
            int issueId = form.getIssueId();
            _issue = getIssue(issueId, true);
            if (null == _issue)
            {
                throw new NotFoundException();
            }

            Issue prevIssue = (Issue)_issue.clone();
            User user = getUser();
            requiresUpdatePermission(user, _issue);

            _issue.close(user);

            IssuePage page = new IssuePage();
            JspView v = new JspView<IssuePage>(IssuesController.class, "updateView.jsp",page);

            IssueManager.CustomColumnConfiguration ccc = getCustomColumnConfiguration();

            page.setAction(CloseAction.class);
            page.setIssue(_issue);
            page.setPrevIssue(prevIssue);
            page.setCustomColumnConfiguration(ccc);
            page.setBody(form.getComment());
            page.setEditable(getEditableFields(page.getAction(), ccc));
            page.setRequiredFields(IssueManager.getRequiredIssueFields(getContainer()));
            page.setErrors(errors);

            return v;
        }

        public NavTree appendNavTrail(NavTree root)
        {
            IssueManager.EntryTypeNames names = IssueManager.getEntryTypeNames(getViewContext().getContainer());
            return (new DetailsAction(_issue, getViewContext()).appendNavTrail(root)).addChild("Close " + names.singularName);
        }
    }


    @RequiresPermissionClass(ReadPermission.class)
    public class ReopenAction extends IssueUpdateAction
    {
        public ModelAndView getView(IssuesForm form, boolean reshow, BindException errors) throws Exception
        {
            int issueId = form.getIssueId();
            _issue = getIssue(issueId, true);
            if (_issue == null)
            {
                throw new NotFoundException();
            }

            Issue prevIssue = (Issue)_issue.clone();

            User user = getUser();
            requiresUpdatePermission(user, _issue);

            _issue.beforeReOpen(true);
            _issue.open(getContainer(), user);

            IssuePage page = new IssuePage();
            JspView v = new JspView<IssuePage>(IssuesController.class, "updateView.jsp",page);

            IssueManager.CustomColumnConfiguration ccc = getCustomColumnConfiguration();

            page.setAction(ReopenAction.class);
            page.setIssue(_issue);
            page.setPrevIssue(prevIssue);
            page.setCustomColumnConfiguration(ccc);
            page.setBody(form.getComment());
            page.setEditable(getEditableFields(page.getAction(), ccc));
            page.setRequiredFields(IssueManager.getRequiredIssueFields(getContainer()));
            page.setErrors(errors);

            return v;
            //return _renderInTemplate(v, "(open) " + issue.getTitle(), null);
        }

        public NavTree appendNavTrail(NavTree root)
        {
            IssueManager.EntryTypeNames names = IssueManager.getEntryTypeNames(getViewContext().getContainer());
            return (new DetailsAction(_issue, getViewContext()).appendNavTrail(root)).addChild("Reopen " + names.singularName);
        }
    }
    
    private void validateRequiredFields(IssuesForm form, Errors errors)
    {
        HString requiredFields = IssueManager.getRequiredIssueFields(getContainer());
        final Map<String, String> newFields = form.getStrings();
        if (!"0".equals(newFields.get("issueId")) && requiredFields.indexOf("comment") != -1)
        {
            // When updating an existing issue (which will have a unique IssueId), never require a comment
            requiredFields = requiredFields.replace("comment", "");
        }
        if (requiredFields.isEmpty())
            return;

        MapBindingResult requiredErrors = new MapBindingResult(newFields, errors.getObjectName());
        if (newFields.containsKey("title"))
            validateRequired("title", newFields.get("title"), requiredFields, requiredErrors);
        if (newFields.containsKey("assignedTo") && !(Issue.statusCLOSED.equals(form.getBean().getStatus())))
            validateRequired("assignedto", newFields.get("assignedTo"), requiredFields, requiredErrors);
        if (newFields.containsKey("type"))
            validateRequired("type", newFields.get("type"), requiredFields, requiredErrors);
        if (newFields.containsKey("area"))
            validateRequired("area", newFields.get("area"), requiredFields, requiredErrors);
        if (newFields.containsKey("priority"))
            validateRequired("priority", newFields.get("priority"), requiredFields, requiredErrors);
        if (newFields.containsKey("milestone"))
            validateRequired("milestone", newFields.get("milestone"), requiredFields, requiredErrors);
        if (newFields.containsKey("notifyList"))
            validateRequired("notifylist", newFields.get("notifyList"), requiredFields, requiredErrors);
        if (newFields.containsKey("int1"))
            validateRequired("int1", newFields.get("int1"), requiredFields, requiredErrors);
        if (newFields.containsKey("int2"))
            validateRequired("int2", newFields.get("int2"), requiredFields, requiredErrors);
        if (newFields.containsKey("string1"))
            validateRequired("string1", newFields.get("string1"), requiredFields, requiredErrors);
        if (newFields.containsKey("string2"))
            validateRequired("string2", newFields.get("string2"), requiredFields, requiredErrors);
        if (newFields.containsKey("string3"))
            validateRequired("string3", newFields.get("string3"), requiredFields, requiredErrors);
        if (newFields.containsKey("string4"))
            validateRequired("string4", newFields.get("string4"), requiredFields, requiredErrors);
        if (newFields.containsKey("string5"))
            validateRequired("string5", newFields.get("string5"), requiredFields, requiredErrors);
        if (newFields.containsKey("comment"))
            validateRequired("comment", newFields.get("comment"), requiredFields, requiredErrors);

        // When resolving Duplicate, the 'duplicate' field should be set.
        if ("Duplicate".equals(newFields.get("resolution")))
            validateRequired("duplicate", newFields.get("duplicate"), new HString("duplicate"), requiredErrors);

        errors.addAllErrors(requiredErrors);
    }


    private void validateRequired(String columnName, String value, HString requiredFields, Errors errors)
    {
        if (requiredFields != null)
        {
            if (requiredFields.indexOf(columnName) != -1)
            {
                if (StringUtils.isEmpty(value))
                {
                    final IssueManager.CustomColumnConfiguration ccc = IssueManager.getCustomColumnConfiguration(getContainer());
                    String name = null;
                    if (ccc.getColumnCaptions().containsKey(columnName))
                        name = ccc.getColumnCaptions().get(columnName);
                    else
                    {
                        ColumnInfo column = IssuesSchema.getInstance().getTableInfoIssues().getColumn(columnName);
                        if (column != null)
                            name = column.getName();
                    }
                    String display = name == null ? columnName : name;
                    errors.rejectValue(columnName, "NullError", new Object[] {display}, display + " is required.");
                }
            }
        }
    }
    

    private void validateNotifyList(Issue issue, IssuesForm form, Errors errors)
    {
        String[] rawEmails = _toString(form.getNotifyList()).split("\n");
        List<String> invalidEmails = new ArrayList<String>();
        List<ValidEmail> emails = SecurityManager.normalizeEmails(rawEmails, invalidEmails);

        StringBuilder message = new StringBuilder();

        for (String rawEmail : invalidEmails)
        {
            rawEmail = rawEmail.trim();
            // Ignore lines of all whitespace, otherwise show an error.
            if (!"".equals(rawEmail))
            {
                message.append("Failed to add user ").append(rawEmail).append(": Invalid email address");
                errors.rejectValue("notifyList","Error",new Object[] {message.toString()}, message.toString());
            }
        }
    }

    public static class CompleteUserForm
    {
        private String _prefix;
        private String _issueId;

        public String getPrefix(){return _prefix;}
        public void setPrefix(String prefix){_prefix = prefix;}

        public String getIssueId(){return _issueId;}
        public void setIssueId(String issueId){_issueId = issueId;}
    }


    @RequiresPermissionClass(InsertPermission.class)
    public class CompleteUserAction extends AjaxCompletionAction<CompleteUserForm>
    {
        public List<AjaxCompletion> getCompletions(CompleteUserForm form, BindException errors) throws Exception
        {
            List<User> possibleUsers = SecurityManager.getUsersWithPermissions(getViewContext().getContainer(), Collections.<Class<? extends Permission>>singleton(ReadPermission.class));
            return UserManager.getAjaxCompletions(form.getPrefix(), possibleUsers, getViewContext().getUser());
        }
    }

    public class UpdateEmailPage
    {
        public UpdateEmailPage(String url, Issue issue, boolean isPlain)
        {
            this.url = url;
            this.issue = issue;
            this.isPlain = isPlain;
        }
        public String url;
        public Issue issue;
        public boolean isPlain;
    }


    private void sendUpdateEmail(Issue issue, Issue prevIssue, String fieldChanges, String summary, String comment, ActionURL detailsURL, String change, List<AttachmentFile> attachments, Class<? extends Controller> action) throws ServletException
    {
        final Set<String> allAddresses = getEmailAddresses(issue, prevIssue, action);

        for (String to : allAddresses)
        {
            try
            {
                Issue.Comment lastComment = issue.getLastComment();
                String messageId = "<" + issue.getEntityId() + "." + lastComment.getCommentId() + "@" + AppProps.getInstance().getDefaultDomain() + ">";
                String references = messageId + " <" + issue.getEntityId() + "@" + AppProps.getInstance().getDefaultDomain() + ">";
                MailHelper.ViewMessage m = MailHelper.createMessage(LookAndFeelProperties.getInstance(getContainer()).getSystemEmailAddress(), to);
                Address[] addresses = m.getAllRecipients();
                if (addresses != null && addresses.length > 0)
                {
                    IssueUpdateEmailTemplate template = EmailTemplateService.get().getEmailTemplate(IssueUpdateEmailTemplate.class, getContainer());
                    template.init(issue, detailsURL, change, comment, fieldChanges, allAddresses, attachments);

                    m.setSubject(template.renderSubject(getContainer()));
                    m.setHeader("References", references);
                    String body = template.renderBody(getContainer());
                    m.setText(body);

                    MailHelper.send(m, getUser(), getContainer());
                }
            }
            catch (Exception e)
            {
                _log.error("error sending update email to " + to, e);
                ExceptionUtil.logExceptionToMothership(null, e);
            }
        }
    }

    /**
     * Builds the list of email addresses for notification based on the user
     * preferences and the explicit notification list.
     */
    private Set<String> getEmailAddresses(Issue issue, Issue prevIssue, Class<? extends Controller> action) throws ServletException
    {
        final Set<String> emailAddresses = new HashSet<String>();
        final Container c = getContainer();
        int assignedToPref = IssueManager.getUserEmailPreferences(c, issue.getAssignedTo());
        int assignedToPrev = prevIssue != null && prevIssue.getAssignedTo() != null ? prevIssue.getAssignedTo() : 0;
        int assignedToPrevPref = assignedToPrev != 0 ? IssueManager.getUserEmailPreferences(c, prevIssue.getAssignedTo()) : 0;
        int createdByPref = IssueManager.getUserEmailPreferences(c, issue.getCreatedBy());

        if (InsertAction.class.equals(action))
        {
            if ((assignedToPref & IssueManager.NOTIFY_ASSIGNEDTO_OPEN) != 0)
                emailAddresses.add(UserManager.getEmailForId(issue.getAssignedTo()));
        }
        else
        {
            if ((assignedToPref & IssueManager.NOTIFY_ASSIGNEDTO_UPDATE) != 0)
                emailAddresses.add(UserManager.getEmailForId(issue.getAssignedTo()));

            if ((assignedToPrevPref & IssueManager.NOTIFY_ASSIGNEDTO_UPDATE) != 0)
                emailAddresses.add(UserManager.getEmailForId(prevIssue.getAssignedTo()));

            if ((createdByPref & IssueManager.NOTIFY_CREATED_UPDATE) != 0)
                emailAddresses.add(UserManager.getEmailForId(issue.getCreatedBy()));
        }

        // add any explicit notification list addresses
        final HString notify = issue.getNotifyList();

        if (notify != null)
        {
            StringTokenizer tokenizer = new StringTokenizer(notify.getSource(), ";\n\r\t");

            while (tokenizer.hasMoreTokens())
            {
                emailAddresses.add((String)tokenizer.nextElement());
            }
        }

        final String current = getUser().getEmail();

        boolean selfSpam = !((IssueManager.NOTIFY_SELF_SPAM & IssueManager.getUserEmailPreferences(c, getUser().getUserId())) == 0);
        if (selfSpam)
            emailAddresses.add(current);
        else
            emailAddresses.remove(current);

        return emailAddresses;
    }

    @RequiresPermissionClass(ReadPermission.class)
    public class EmailPrefsAction extends FormViewAction<EmailPrefsForm>
    {
        String _message = null;

        public ModelAndView getView(EmailPrefsForm form, boolean reshow, BindException errors) throws Exception
        {
            if (getViewContext().getUser().isGuest())
            {
                throw new UnauthorizedException();
            }

            int emailPrefs = IssueManager.getUserEmailPreferences(getContainer(), getUser().getUserId());
            int issueId = form.getIssueId() == null ? 0 : form.getIssueId().intValue();
            return new JspView<EmailPrefsBean>(IssuesController.class, "emailPreferences.jsp",
                new EmailPrefsBean(emailPrefs, errors, _message, issueId));
        }

        public boolean handlePost(EmailPrefsForm form, BindException errors) throws Exception
        {
            int emailPref = 0;
            for (int pref : form.getEmailPreference())
            {
                emailPref |= pref;
            }
            IssueManager.setUserEmailPreferences(getContainer(), getUser().getUserId(),
                    emailPref, getUser().getUserId());
            _message = "Settings updated successfully";
            return true;
        }

        public NavTree appendNavTrail(NavTree root)
        {
            return (new ListAction(getViewContext())).appendNavTrail(root).addChild("Email preferences");
        }


        public void validateCommand(EmailPrefsForm emailPrefsForm, Errors errors)
        {
        }

        public ActionURL getSuccessURL(EmailPrefsForm emailPrefsForm)
        {
            return null;
        }
    }


    public static final String REQUIRED_FIELDS_COLUMNS = "Title,AssignedTo,Type,Area,Priority,Milestone,NotifyList";
    public static final String DEFAULT_REQUIRED_FIELDS = "title;assignedto";


    @RequiresPermissionClass(AdminPermission.class)
    public class AdminAction extends FormViewAction<AdminForm>
    {
        public ModelAndView getView(AdminForm form, boolean reshow, BindException errors) throws Exception
        {
            // TODO: This hack ensures that priority & resolution option defaults get populated if first reference is the admin page.  Fix this.
            IssuePage page = new IssuePage()
            {
                public void _jspService(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws ServletException, IOException
                {
                }
            };
            page.getPriorityOptions(getContainer());
            page.getResolutionOptions(getContainer());
            // </HACK>

            return new AdminView(getContainer(), getCustomColumnConfiguration(), errors);
        }

        public NavTree appendNavTrail(NavTree root)
        {
            IssueManager.EntryTypeNames names = IssueManager.getEntryTypeNames(getViewContext().getContainer());
            return (new ListAction(getViewContext())).appendNavTrail(root).addChild(names.pluralName + " Admin Page", getUrl());
        }

        public ActionURL getUrl()
        {
            return issueURL(AdminAction.class);
        }


        @Override
        public void validateCommand(AdminForm target, Errors errors)
        {
        }

        @Override
        public boolean handlePost(AdminForm adminForm, BindException errors) throws Exception
        {
            return false;
        }

        @Override
        public URLHelper getSuccessURL(AdminForm adminForm)
        {
            return getUrl();
        }
    }


    public abstract class AdminFormAction extends FormHandlerAction<AdminForm>
    {
        public void validateCommand(AdminForm adminForm, Errors errors)
        {
        }

        public ActionURL getSuccessURL(AdminForm adminForm)
        {
            return issueURL(AdminAction.class);
        }
    }


    @RequiresPermissionClass(AdminPermission.class)
    public class AddKeywordAction extends AdminAction
    {
        @Override
        public void validateCommand(AdminForm form, Errors errors)
        {
            int type = form.getType();
            HString keyword = form.getKeyword();
            if (null == keyword || StringUtils.isBlank(keyword.getSource()))
            {
                errors.reject(ERROR_MSG, "Enter a value in the text box before clicking any of the \"Add <Keyword>\" buttons");
            }
            else
            {
                if (ISSUE_PRIORITY == type)
                {
                    try
                    {
                        Integer.parseInt(keyword.getSource());
                    }
                    catch (NumberFormatException e)
                    {
                        errors.reject(ERROR_MSG, "Priority must be an integer");
                    }
                }
                else
                {
                    if(keyword.length() > 200)
                            errors.reject(ERROR_MSG, "The keyword is too long, it must be under 200 characters.");

                    IssueManager.Keyword[] keywords = IssueManager.getKeywords(getContainer().getId(), type);
                    for (IssueManager.Keyword word : keywords)
                    {
                        if (word.getKeyword().compareToIgnoreCase(keyword)== 0)
                            errors.reject(ERROR_MSG, "\"" + word.getKeyword() + "\" already exists");
                    }
                }
            }
        }

        public boolean handlePost(AdminForm form, BindException errors) throws Exception
        {
            try
            {
                IssueManager.addKeyword(getContainer(), form.getType(), form.getKeyword());
            }
            catch (SQLException e)
            {
                if (SqlDialect.isConstraintException(e))
                {
                    errors.reject(ERROR_MSG, "\"" + form.getKeyword() + "\" already exists");
                    return false;
                }

                throw e;
            }

            return true;
        }
    }

    @RequiresPermissionClass(AdminPermission.class)
    public class DeleteKeywordAction extends AdminFormAction
    {
        public boolean handlePost(AdminForm form, BindException errors) throws Exception
        {
            IssueManager.deleteKeyword(getContainer(), form.getType(), form.getKeyword());
            return true;
        }
    }

    @RequiresPermissionClass(AdminPermission.class)
    public class SetKeywordDefaultAction extends AdminFormAction
    {
        public boolean handlePost(AdminForm form, BindException errors) throws Exception
        {
            IssueManager.setKeywordDefault(getContainer(), form.getType(), form.getKeyword());
            return true;
        }
    }

    @RequiresPermissionClass(AdminPermission.class)
    public class ClearKeywordDefaultAction extends AdminFormAction
    {
        public boolean handlePost(AdminForm form, BindException errors) throws Exception
        {
            IssueManager.clearKeywordDefault(getContainer(), form.getType());
            return true;
        }
    }

    public static class ConfigureIssuesForm
    {
        public static enum ParamNames
        {
            entrySingularName,
            entryPluralName,
            direction
        }

        private String _direction;
        private String _assignedToMethod = null;
        private int _assignedToGroup = 0;

        private HString[] _requiredFields = new HString[0];

        private HString _entrySingularName;
        private HString _entryPluralName;

        public String getDirection()
        {
            return _direction;
        }

        public void setDirection(String direction)
        {
            _direction = direction;
        }

        public String getAssignedToMethod()
        {
            return _assignedToMethod;
        }

        public void setAssignedToMethod(String assignedToMethod)
        {
            _assignedToMethod = assignedToMethod;
        }

        public int getAssignedToGroup()
        {
            return _assignedToGroup;
        }

        public void setAssignedToGroup(int assignedToGroup)
        {
            _assignedToGroup = assignedToGroup;
        }

        public HString getEntrySingularName()
        {
            return _entrySingularName;
        }

        public void setEntrySingularName(HString entrySingularName)
        {
            _entrySingularName = entrySingularName;
        }

        public HString getEntryPluralName()
        {
            return _entryPluralName;
        }

        public void setEntryPluralName(HString entryPluralName)
        {
            _entryPluralName = entryPluralName;
        }

        public void setRequiredFields(HString[] requiredFields){_requiredFields = requiredFields;}
        public HString[] getRequiredFields(){return _requiredFields;}
    }

    @RequiresPermissionClass(AdminPermission.class)
    public class ConfigureIssuesAction extends FormHandlerAction<ConfigureIssuesForm>
    {
        private Group _group = null;
        private Sort.SortDirection _direction = Sort.SortDirection.ASC;

        public void validateCommand(ConfigureIssuesForm form, Errors errors)
        {
            checkPickLists(form, errors);
            
            IssueManager.CustomColumnConfiguration ccc = new IssueManager.CustomColumnConfiguration(getViewContext());
            String defaultCols[] = {"Milestone", "Area", "Type", "Priority", "Resolution"};
            Map<String, String> captions = ccc.getColumnCaptions(); //All of the custom captions
            for (String column : defaultCols)
            {
                //Here we add the default captions if the user hasn't changed them.
                if (captions.get(column.toLowerCase()) == null)
                {
                    captions.put(column.toLowerCase(), column);
                }
            }

            HashSet<String> uniqueCaptions = new HashSet<String>(captions.values());
            if (captions.size() > uniqueCaptions.size())
            {
                errors.reject(ERROR_MSG, "Custom field names must be unique.");
            }

            if (form.getAssignedToMethod().equals("ProjectUsers"))
            {
                if (form.getAssignedToGroup() != 0)
                    errors.reject("assignedToGroup", "Project users setting shouldn't include a group!");
            }
            else if (form.getAssignedToMethod().equals("Group"))
            {
                int groupId = form.getAssignedToGroup();
                _group = SecurityManager.getGroup(groupId);

                if (null == _group)
                    errors.reject("assignedToGroup", "Group does not exist!");
            }
            else
            {
                errors.reject("assignedToGroup", "Invalid assigned to setting!");
            }

            if (form.getEntrySingularName().trimToEmpty().length() == 0)
                errors.reject(ConfigureIssuesForm.ParamNames.entrySingularName.name(), "You must specify a value for the entry type singular name!");
            if (form.getEntryPluralName().trimToEmpty().length() == 0)
                errors.reject(ConfigureIssuesForm.ParamNames.entryPluralName.name(), "You must specify a value for the entry type plural name!");

            try
            {
                if (form.getDirection() == null)
                {
                    errors.reject(ConfigureIssuesForm.ParamNames.direction.name(), "You must specify a comment sort direction!");
                }
                _direction = Sort.SortDirection.valueOf(form.getDirection());
            }
            catch (IllegalArgumentException e)
            {
                errors.reject(ConfigureIssuesForm.ParamNames.direction.name(), "You must specify a valid comment sort direction!");
            }
        }

        private void checkPickLists(ConfigureIssuesForm form, Errors errors)
        {
            ArrayList<HString> newRequiredFields = new ArrayList<HString>();
             /**
             * You have to make the required fields all lower case to compare them to the STRING_#_STRING constants.
             * I made the mistake of trying to make the field use lowercase names but it ruins the camelcasing when
             * you ouput the form on the JSP, which then breaks the tests.
             */
            for(HString required : form.getRequiredFields())
            {
                newRequiredFields.add(required.toLowerCase());
            }
            Set<String> newPickLists = new IssueManager.CustomColumnConfiguration(getViewContext()).getPickListColumns();
            Set<String> oldPickLists = IssueManager.getCustomColumnConfiguration(getContainer()).getPickListColumns();

            for (HString required : form.getRequiredFields())
            {
                /**
                 * If the required field is one of the custom string fields, and it has no keywords, and it has just been
                 * selected (in the new picklist, but not old), then we remove it from the required fields. This way you
                 * don't have a required field with no keywords.
                 */
               if (required.toString().equalsIgnoreCase(STRING_1_STRING) && IssueManager.getKeywords(getContainer().getId(), ISSUE_STRING1).length < 1 && newPickLists.contains(STRING_1_STRING) && !oldPickLists.contains(STRING_1_STRING))
                {
                        newRequiredFields.remove(new HString(STRING_1_STRING));
                }
                else if (required.toString().equalsIgnoreCase(STRING_2_STRING) && IssueManager.getKeywords(getContainer().getId(), ISSUE_STRING2).length < 1 && newPickLists.contains(STRING_2_STRING)&& !oldPickLists.contains(STRING_2_STRING))
                {
                        newRequiredFields.remove(new HString(STRING_2_STRING));
                }
                else if (required.toString().equalsIgnoreCase(STRING_3_STRING) && IssueManager.getKeywords(getContainer().getId(), ISSUE_STRING3).length < 1 && newPickLists.contains(STRING_3_STRING) && !oldPickLists.contains(STRING_3_STRING))
                {
                        newRequiredFields.remove(new HString(STRING_3_STRING));
                }
                else if (required.toString().equalsIgnoreCase(STRING_4_STRING) && IssueManager.getKeywords(getContainer().getId(), ISSUE_STRING4).length < 1 && newPickLists.contains(STRING_4_STRING) && !oldPickLists.contains(STRING_4_STRING))
                {
                        newRequiredFields.remove(new HString(STRING_4_STRING));
                }
                else if (required.toString().equalsIgnoreCase(STRING_5_STRING) && IssueManager.getKeywords(getContainer().getId(), ISSUE_STRING5).length < 1 && newPickLists.contains(STRING_5_STRING) && !oldPickLists.contains(STRING_5_STRING))
                {
                        newRequiredFields.remove(new HString(STRING_5_STRING));
                }
            }

            form.setRequiredFields((HString[])newRequiredFields.toArray(new HString[newRequiredFields.size()]));
        }

        public boolean handlePost(ConfigureIssuesForm form, BindException errors) throws Exception
        {
            IssueManager.EntryTypeNames names = new IssueManager.EntryTypeNames();

            names.singularName = form.getEntrySingularName();
            names.pluralName = form.getEntryPluralName();

            IssueManager.saveEntryTypeNames(getContainer(), names);
            IssueManager.saveAssignedToGroup(getContainer(), _group);
            IssueManager.saveCommentSortDirection(getContainer(), _direction);

            IssueManager.CustomColumnConfiguration ccc = new IssueManager.CustomColumnConfiguration(getViewContext());
            IssueManager.saveCustomColumnConfiguration(getContainer(), ccc);

            IssueManager.setRequiredIssueFields(getContainer(), form.getRequiredFields());
            return true;
        }

        public ActionURL getSuccessURL(ConfigureIssuesForm form)
        {
            return issueURL(AdminAction.class);
        }
    }


    @RequiresPermissionClass(ReadPermission.class)
    public class RssAction extends SimpleViewAction
    {
        @Override
        public void checkPermissions() throws TermsOfUseException, UnauthorizedException
        {
            setUseBasicAuthentication(true);
            super.checkPermissions();
        }

        public ModelAndView getView(Object o, BindException errors) throws Exception
        {
            getPageConfig().setTemplate(PageConfig.Template.None);
            ResultSet rs = null;
            try
            {
                DataRegion r = new DataRegion();
                TableInfo tinfo = IssuesSchema.getInstance().getTableInfoIssues();
                List<ColumnInfo> cols = tinfo.getColumns("IssueId,Created,CreatedBy,Area,Type,Title,AssignedTo,Priority,Status,Milestone");
                r.addColumns(cols);

                rs = r.getResultSet(new RenderContext(getViewContext()));
                ObjectFactory f = ObjectFactory.Registry.getFactory(Issue.class);
                Issue[] issues = (Issue[]) f.handleArray(rs);

                ActionURL url = getDetailsURL(getContainer(), 1, isPrint());
                String filteredURLString = PageFlowUtil.filter(url);
                String detailsURLString = filteredURLString.substring(0, filteredURLString.length() - 1);

                WebPartView v = new JspView<RssBean>("/org/labkey/issue/rss.jsp", new RssBean(issues, detailsURLString));
                v.setFrame(WebPartView.FrameType.NONE);

                return v;
            }
            catch (SQLException x)
            {
                x.printStackTrace();
                throw new ServletException(x);
            }
            finally
            {
                ResultSetUtil.close(rs);
            }
        }

        public NavTree appendNavTrail(NavTree root)
        {
            return null;
        }

        private ActionURL getUrl()
        {
            return issueURL(RssAction.class);
        }
    }


    public static class RssBean
    {
        public Issue[] issues;
        public String filteredURLString;

        private RssBean(Issue[] issues, String filteredURLString)
        {
            this.issues = issues;
            this.filteredURLString = filteredURLString;
        }
    }


    @RequiresPermissionClass(AdminPermission.class)
    public class PurgeAction extends SimpleViewAction
    {
        public ModelAndView getView(Object o, BindException errors) throws Exception
        {
            if (!getUser().isAdministrator())   // GLOBAL
            {
                throw new UnauthorizedException();
            }
            String message = IssueManager.purge();
            return new HtmlView(message);
        }

        public NavTree appendNavTrail(NavTree root)
        {
            return null;
        }
    }


    @RequiresPermissionClass(ReadPermission.class)
    public class JumpToIssueAction extends SimpleViewAction
    {
        public ModelAndView getView(Object o, BindException errors) throws Exception
        {
            String issueId = (String)getProperty("issueId");
            if (issueId != null)
            {
                issueId = issueId.trim();
                try
                {
                    int id = Integer.parseInt(issueId);
                    Issue issue = getIssue(id, true);
                    if (issue != null)
                    {
                        ActionURL url = getDetailsURL(getContainer(), issue.getIssueId(), false);
                        return HttpView.redirect(url);
                    }
                }
                catch (NumberFormatException e)
                {
                    // fall through
                }
            }
            ActionURL url = getViewContext().cloneActionURL();
            url.deleteParameters();
            url.addParameter("error", "Invalid issue id '" + issueId + "'");
            url.setAction(ListAction.class);
            url.addParameter(".lastFilter", "true");
            return HttpView.redirect(url);
        }

        public NavTree appendNavTrail(NavTree root)
        {
            return null;
        }
    }


    @RequiresPermissionClass(ReadPermission.class)
    public class SearchAction extends SimpleViewAction
    {
        private String _status;

        public ModelAndView getView(Object o, BindException errors) throws Exception
        {
            Container c = getContainer();
            Object q = getProperty("q", "");
            String searchTerm = (q instanceof String) ? (String)q : StringUtils.join((String[])q," ");

            _status = (String)getProperty("status");

            getPageConfig().setHelpTopic(new HelpTopic("luceneSearch"));

            return new SearchResultsView(c, searchTerm, _status, isPrint());
        }

        public NavTree appendNavTrail(NavTree root)
        {
            String title = "Search " + (null != _status ? _status + " " : "") + "Issues";
            return new ListAction(getViewContext()).appendNavTrail(root).addChild(title);
        }
    }


    public static class SearchResultsView extends JspView<SearchResultsView>
    {
        public Container _c;
        public String _query;
        public boolean _print;
        public String _status;
        
        SearchResultsView(Container c, String query, String status, boolean isPrint)
        {
            super(IssuesController.class, "search.jsp", null);
            _c = c;
            _query = query;
            _status = status;
            _print = isPrint;
            setModelBean(this);
        }
    }


    @RequiresPermissionClass(ReadPermission.class)
    public class GetIssueAction extends ApiAction<IssueIdForm>
    {
        @Override
        public ApiResponse execute(IssueIdForm issueIdForm, BindException errors) throws Exception
        {
            User user = getUser();
            Issue issue = getIssue(issueIdForm.getIssueId(), false);
            //IssuePage page = new IssuePage();

            BeanMap wrapper = new BeanMap(issue);
            JSONObject jsonIssue = new JSONObject(wrapper);
            jsonIssue.remove("lastComment");
            jsonIssue.remove("class");

            Map<String,String> captions = getColumnCaptions();
            for (Map.Entry<String,String> e : captions.entrySet())
            {
                jsonIssue.remove(e.getKey());
                jsonIssue.put(e.getValue(), wrapper.get(e.getKey()));
            }

            JSONArray comments = new JSONArray();
            jsonIssue.put("comments", comments);
            for (Issue.Comment c : issue.getComments())
            {
                JSONObject jsonComment = new JSONObject(new BeanMap(c));
                jsonComment.put("createdByName", c.getCreatedByName(user));
                jsonComment.put("comment", c.getComment().getSource());
                comments.put(comments.length(),  jsonComment);
                // ATTACHMENTS
            }
            jsonIssue.put("success", Boolean.TRUE);
            return new ApiSimpleResponse(jsonIssue);
        }
    }


    @RequiresPermissionClass(ReadPermission.class)
    public class AppAction extends SimpleViewAction<Object>
    {
        @Override
        public ModelAndView getView(Object o, BindException errors) throws Exception
        {
            getPageConfig().setTemplate(PageConfig.Template.Print);
            return new JspView(IssuesController.class, "extjs4.jsp", null);
        }

        @Override
        public NavTree appendNavTrail(NavTree root)
        {
            return root;
        }
    }


    static String _toString(Object a)
    {
        return null == a ? "" : a.toString();
    }


    static void _appendChange(StringBuilder sbHTML, StringBuilder sbText, String field, HString from, HString to, boolean newIssue)
    {
        from = from == null ? HString.EMPTY : from;
        to = to == null ? HString.EMPTY : to;
        if (!from.equals(to))
        {
            sbText.append(field);
            if (newIssue)
            {
                sbText.append(" set");
            }
            else
            {
                sbText.append(" changed from ");
                sbText.append(HString.EMPTY.equals(from) ? "blank" : "\"" + from.getSource() + "\"");
            }
            sbText.append(" to ");
            sbText.append(HString.EMPTY.equals(to) ? "blank" : "\"" + to.getSource() + "\"");
            sbText.append("\n");
            HString encFrom = PageFlowUtil.filter(from);
            HString encTo = PageFlowUtil.filter(to);
            sbHTML.append("<tr><td>").append(field).append("</td><td>").append(encFrom).append("</td><td>&raquo;</td><td>").append(encTo).append("</td></tr>\n");
        }
    }

    private static class ChangeSummary
    {
        private Issue.Comment _comment;
        private String _textChanges;
        private String _summary;

        private ChangeSummary(Issue.Comment comment, String textChanges, String summary)
        {
            _comment = comment;
            _textChanges = textChanges;
            _summary = summary;
        }

        public Issue.Comment getComment()
        {
            return _comment;
        }

        public String getTextChanges()
        {
            return _textChanges;
        }

        public String getSummary()
        {
            return _summary;
        }
    }

    static ChangeSummary createChangeSummary(Issue issue, Issue previous, Issue duplicateOf, User user, Class<? extends Controller> action, String comment, Map<String, String> customColumns, User currentUser)
    {
        StringBuilder sbHTMLChanges = new StringBuilder();
        StringBuilder sbTextChanges = new StringBuilder();
        String summary = null;

        if (!action.equals(InsertAction.class) && !action.equals(UpdateAction.class))
        {
            summary = getActionName(action).toLowerCase();

            if (action.equals(ResolveAction.class))
            {
                // Add the resolution; e.g. "resolve as Fixed"
                summary += " as " + issue.getResolution();
                if (duplicateOf != null)
                    summary += " of " + duplicateOf.getIssueId();
            }

            sbHTMLChanges.append("<b>").append(summary);
            sbHTMLChanges.append("</b><br>\n");
        }
        
        // CONSIDER: write changes in wiki
        // CONSIDER: and postpone formatting until render
        if (null != previous)
        {
            // Keep track of whether this issue is new
            boolean newIssue = previous.getIssueId() == 0;
            // issueChanges is not defined yet, but it leaves things flexible
            sbHTMLChanges.append("<table class=issues-Changes>");
            _appendChange(sbHTMLChanges, sbTextChanges, "Title", previous.getTitle(), issue.getTitle(), newIssue);
            _appendChange(sbHTMLChanges, sbTextChanges, "Status", previous.getStatus(), issue.getStatus(), newIssue);
            _appendChange(sbHTMLChanges, sbTextChanges, "Assigned To", previous.getAssignedToName(currentUser), issue.getAssignedToName(currentUser), newIssue);
            _appendChange(sbHTMLChanges, sbTextChanges, "Notify", previous.getNotifyList(), issue.getNotifyList(), newIssue);
            _appendChange(sbHTMLChanges, sbTextChanges, "Type", previous.getType(), issue.getType(), newIssue);
            _appendChange(sbHTMLChanges, sbTextChanges, "Area", previous.getArea(), issue.getArea(), newIssue);
            _appendChange(sbHTMLChanges, sbTextChanges, "Priority", HString.valueOf(previous.getPriority()), HString.valueOf(issue.getPriority()), newIssue);
            _appendChange(sbHTMLChanges, sbTextChanges, "Milestone", previous.getMilestone(), issue.getMilestone(), newIssue);

            _appendCustomColumnChange(sbHTMLChanges, sbTextChanges, "int1", HString.valueOf(previous.getInt1()), HString.valueOf(issue.getInt1()), customColumns, newIssue);
            _appendCustomColumnChange(sbHTMLChanges, sbTextChanges, "int2", HString.valueOf(previous.getInt2()), HString.valueOf(issue.getInt2()), customColumns, newIssue);
            _appendCustomColumnChange(sbHTMLChanges, sbTextChanges, "string1", previous.getString1(), issue.getString1(), customColumns, newIssue);
            _appendCustomColumnChange(sbHTMLChanges, sbTextChanges, "string2", previous.getString2(), issue.getString2(), customColumns, newIssue);
            _appendCustomColumnChange(sbHTMLChanges, sbTextChanges, "string3", previous.getString3(), issue.getString3(), customColumns, newIssue);
            _appendCustomColumnChange(sbHTMLChanges, sbTextChanges, "string4", previous.getString4(), issue.getString4(), customColumns, newIssue);
            _appendCustomColumnChange(sbHTMLChanges, sbTextChanges, "string5", previous.getString5(), issue.getString5(), customColumns, newIssue);

            sbHTMLChanges.append("</table>\n");
        }

        //why we are wrapping issue comments in divs???
        HStringBuilder formattedComment = new HStringBuilder();
        formattedComment.append("<div class=\"wiki\">");
        formattedComment.append(sbHTMLChanges);
        //render issues as plain text with links
        WikiService wikiService = ServiceRegistry.get().getService(WikiService.class);
        if (null != wikiService)
        {
            String html = wikiService.getFormattedHtml(WikiRendererType.TEXT_WITH_LINKS, comment);
            formattedComment.append(html);
        }
        else
            formattedComment.append(comment);

        formattedComment.append("</div>");

        return new ChangeSummary(issue.addComment(user, formattedComment.toHString()), sbTextChanges.toString(), summary);
    }

    private static void _appendCustomColumnChange(StringBuilder sbHtml, StringBuilder sbText, String field, HString from, HString to, Map<String, String> columnCaptions, boolean newIssue)
    {
        String caption = columnCaptions.get(field);

        if (null != caption)
            _appendChange(sbHtml, sbText, caption, from, to, newIssue);
    }


    //
    // VIEWS
    //
    public static class AdminView extends JspView<AdminBean>
    {
        public AdminView(Container c, IssueManager.CustomColumnConfiguration ccc, BindException errors)
        {
            super("/org/labkey/issue/admin.jsp", null, errors);

            KeywordAdminView keywordView = new KeywordAdminView(c, ccc);
            keywordView.addKeyword("Type", ISSUE_TYPE);
            keywordView.addKeyword("Area", ISSUE_AREA);
            keywordView.addKeyword("Priority", ISSUE_PRIORITY);
            keywordView.addKeyword("Milestone", ISSUE_MILESTONE);
            keywordView.addKeyword("Resolution", ISSUE_RESOLUTION);
            keywordView.addCustomColumn("string1", ISSUE_STRING1);
            keywordView.addCustomColumn("string2", ISSUE_STRING2);
            keywordView.addCustomColumn("string3", ISSUE_STRING3);
            keywordView.addCustomColumn("string4", ISSUE_STRING4);
            keywordView.addCustomColumn("string5", ISSUE_STRING5);

            List<String> columnNames = new ArrayList<String>();
            columnNames.addAll(Arrays.asList(REQUIRED_FIELDS_COLUMNS.split(",")));
            columnNames.addAll(IssueManager.getCustomColumnConfiguration(c).getColumnCaptions().keySet());
            List<ColumnInfo> cols = IssuesSchema.getInstance().getTableInfoIssues().getColumns(columnNames.toArray(new String[columnNames.size()]));

            AdminBean bean = new AdminBean(cols, IssueManager.getRequiredIssueFields(c), IssueManager.getEntryTypeNames(c));

            bean.ccc = ccc;
            bean.keywordView = keywordView;
            bean.entryTypeNames = IssueManager.getEntryTypeNames(c);
            bean.assignedToGroup = IssueManager.getAssignedToGroup(c);
            bean.commentSort = IssueManager.getCommentSortDirection(c);
            setModelBean(bean);
        }
    }


    public static class AdminBean
    {
        private List<ColumnInfo> _columns;
        private HString _requiredFields;
        private IssueManager.EntryTypeNames _entryTypeNames;

        public IssueManager.CustomColumnConfiguration ccc;
        public KeywordAdminView keywordView;
        public IssueManager.EntryTypeNames entryTypeNames;
        public Group assignedToGroup;
        public Sort.SortDirection commentSort;

        public AdminBean(List<ColumnInfo> columns, HString requiredFields, IssueManager.EntryTypeNames typeNames)
        {
            _columns = columns;
            _requiredFields = requiredFields;
            _entryTypeNames = typeNames;
        }

        public List<ColumnInfo> getColumns(){return _columns;}
        public HString getRequiredFields(){return _requiredFields;}
        public IssueManager.EntryTypeNames getEntryTypeNames() {return _entryTypeNames;}
    }


    // Renders the pickers for all keywords; would be nice to render each picker independently, but that makes it hard to align
    // all the top and bottom sections with each other.
    public static class KeywordAdminView extends JspView<List<KeywordPicker>>
    {
        private Container _c;
        private List<KeywordPicker> _keywordPickers = new ArrayList<KeywordPicker>(5);
        public IssueManager.CustomColumnConfiguration _ccc;

        public KeywordAdminView(Container c, IssueManager.CustomColumnConfiguration ccc)
        {
            super("/org/labkey/issue/keywordAdmin.jsp");
            setModelBean(_keywordPickers);
            _c = c;
            _ccc = ccc;
        }

        // Add keyword admin for custom columns with column picker enabled
        private void addCustomColumn(String tableColumn, int type)
        {
            if (_ccc.getPickListColumns().contains(tableColumn))
            {
                String caption = _ccc.getColumnCaptions().get(tableColumn);
                _keywordPickers.add(new KeywordPicker(_c, caption, type));
            }
        }

        private void addKeyword(String name, int type)
        {
            String caption = _ccc.getColumnCaptions().get(name);
            if (caption == null)
            {
                caption = name;
            }
            _keywordPickers.add(new KeywordPicker(_c, caption, type));
        }
    }


    public static class KeywordPicker
    {
        public String name;
        public String plural;
        public int type;
        public IssueManager.Keyword[] keywords;

        KeywordPicker(Container c, String name, int type)
        {
            this.name = name;
            this.plural = name.endsWith("y") ? name.substring(0, name.length() - 1) + "ies" : name + "s";
            this.type = type;
            this.keywords = IssueManager.getKeywords(c.getId(), type);
        }
    }


    public static class EmailPrefsBean
    {
        private int _emailPrefs;
        private BindException _errors;
        private String _message;
        private Integer _issueId;

        public EmailPrefsBean(int emailPreference, BindException errors, String message, Integer issueId)
        {
            _emailPrefs = emailPreference;
            _errors = errors;
            _message = message;
            _issueId = issueId;
        }

        public int getEmailPreference()
        {
            return _emailPrefs;
        }

        public BindException getErrors()
        {
            return _errors;
        }

        public String getMessage()
        {
            return _message;
        }

        public int getIssueId()
        {
            return _issueId.intValue();
        }
    }

    public static class EmailPrefsForm
    {
        private Integer[] _emailPreference = new Integer[0];
        private Integer _issueId;

        public Integer[] getEmailPreference()
        {
            return _emailPreference;
        }

        public void setEmailPreference(Integer[] emailPreference)
        {
            _emailPreference = emailPreference;
        }

        public Integer getIssueId()
        {
            return _issueId;
        }

        public void setIssueId(Integer issueId)
        {
            _issueId = issueId;
        }
    }

    public static class AdminForm
    {
        private int type;
        private HString keyword;


        public int getType()
        {
            return type;
        }


        public void setType(int type)
        {
            this.type = type;
        }


        public HString getKeyword()
        {
            return keyword;
        }


        public void setKeyword(HString keyword)
        {
            this.keyword = keyword;
        }
    }

    public static class IssuesForm extends BeanViewForm<Issue>
    {
        public IssuesForm()
        {
            super(Issue.class, IssuesSchema.getInstance().getTableInfoIssues(), extraProps());
            setValidateRequired(false);
        }

        private static Map<String, Class> extraProps()
        {
            Map<String, Class> map = new LinkedHashMap<String, Class>();
            map.put("action", HString.class);
            map.put("comment", HString.class);
            map.put("callbackURL", ReturnURLString.class);
            return map;
        }

        public Class<? extends Controller> getAction()
        {
            String className = _stringValues.get("action");
            if (className == null)
            {
                throw new NotFoundException("No action specified");
            }
            try
            {
                Class result = Class.forName(className);
                if (Controller.class.isAssignableFrom(result))
                {
                    return result;
                }
                throw new NotFoundException("Resolved class but it was not an action: " + className);
            }
            catch (ClassNotFoundException e)
            {
                throw new NotFoundException("Could not find action " + className);
            }
        }

        // XXX: change return value to typed HString
        public String getComment()
        {
            return _stringValues.get("comment");
        }

        public String getNotifyList()
        {
            return _stringValues.get("notifyList");
        }

        // XXX: change return value to typed ReturnURLString
        public String getCallbackURL()
        {
            return _stringValues.get("callbackURL");
        }

        public String getBody()
        {
            return _stringValues.get("body");
        }

        /**
         * A bit of a hack but to allow the mothership controller to continue to create issues
         * in the way that it previously did, we need to be able to tell the issues controller
         * to not handle the post, and just get the view.
         */
        public boolean getSkipPost()
        {
            return BooleanUtils.toBoolean(_stringValues.get("skipPost"));
        }

        public ActionURL getForwardURL()
        {
            ActionURL url;
            String callbackURL = getCallbackURL();
            if (callbackURL != null)
            {
                url = new ActionURL(callbackURL).addParameter("issueId", "" + getBean().getIssueId());
                return url;
            }
            else
            {
                return getDetailsURL(getViewContext().getContainer(), getBean().getIssueId(), false);
            }
        }

        public int getIssueId()
        {
            return NumberUtils.toInt(_stringValues.get("issueId"));
        }
    }


    public static class SummaryWebPart extends JspView<SummaryBean>
    {
        public SummaryWebPart()
        {
            super("/org/labkey/issue/summaryWebpart.jsp", new SummaryBean());

            SummaryBean bean = getModelBean();

            ViewContext context = getViewContext();
            Container c = context.getContainer();

            //set specified web part title
            Object title = context.get("title");
            if (title == null)
                title = IssueManager.getEntryTypeNames(getViewContext().getContainer()).pluralName + " Summary";
            setTitle(title.toString());

            User u = context.getUser();
            bean.hasPermission = c.hasPermission(u, ReadPermission.class);
            if (!bean.hasPermission)
                return;

            setTitleHref(getListURL(c));

            bean.listURL = getListURL(c).deleteParameters();

            bean.insertURL = IssuesController.issueURL(context.getContainer(), InsertAction.class);

            try
            {
                bean.bugs = IssueManager.getSummary(c);
            }
            catch (SQLException x)
            {
                setVisible(false);
            }
        }
    }


    public static class SummaryBean
    {
        public boolean hasPermission;
        public Map[] bugs;
        public ActionURL listURL;
        public ActionURL insertURL;
    }


    public static class TestCase extends Assert
    {
        @Test
        public void testIssue() throws SQLException, ServletException
        {
        }
    }


    protected synchronized void afterAction(Throwable t)
    {
        super.afterAction(t);
    }

    /**
     * Does this user have permission to update this issue?
     */
    private boolean hasUpdatePermission(User user, Issue issue)
    {
        return getContainer().hasPermission(user, UpdatePermission.class,
                (issue.getCreatedBy() == user.getUserId() ? RoleManager.roleSet(OwnerRole.class) : null));
    }


    /**
     * Throw an exception if user does not have permission to update issue
     */
    private void requiresUpdatePermission(User user, Issue issue)
            throws ServletException
    {
        if (!hasUpdatePermission(user, issue))
        {
            throw new UnauthorizedException();
        }
    }


    public static class ListForm extends QueryForm
    {
        @NotNull
        @Override
        public IdentifierString getSchemaName()
        {
            return new IdentifierString(IssuesQuerySchema.SCHEMA_NAME, false);
        }

        @Override
        protected UserSchema createSchema()
        {
            return new IssuesQuerySchema(getUser(), getContainer());
        }

    }

    public static class IssueIdForm
    {
        private int issueId = -1;

        public int getIssueId()
        {
            return issueId;
        }

        public void setIssueId(int issueId)
        {
            this.issueId = issueId;
        }
    }
}
