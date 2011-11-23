/*
 * Copyright (c) 2006-2011 LabKey Corporation
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

package org.labkey.mothership;

import org.apache.commons.beanutils.ConversionException;
import org.apache.log4j.Logger;
import org.jfree.chart.ChartColor;
import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartUtilities;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.axis.NumberAxis;
import org.jfree.chart.plot.XYPlot;
import org.jfree.chart.renderer.xy.XYItemRenderer;
import org.jfree.chart.renderer.xy.XYLineAndShapeRenderer;
import org.jfree.data.time.Day;
import org.jfree.data.time.TimeSeries;
import org.jfree.data.time.TimeSeriesCollection;
import org.jfree.data.xy.XYDataset;
import org.labkey.api.action.FormHandlerAction;
import org.labkey.api.action.SimpleViewAction;
import org.labkey.api.action.SpringActionController;
import org.labkey.api.data.*;
import org.labkey.api.data.Container;
import org.labkey.api.query.DetailsURL;
import org.labkey.api.query.QuerySettings;
import org.labkey.api.query.QueryView;
import org.labkey.api.security.*;
import org.labkey.api.security.permissions.DeletePermission;
import org.labkey.api.security.permissions.InsertPermission;
import org.labkey.api.security.permissions.ReadPermission;
import org.labkey.api.security.permissions.UpdatePermission;
import org.labkey.api.util.MothershipReport;
import org.labkey.api.util.PageFlowUtil;
import org.labkey.api.view.*;
import org.labkey.mothership.query.MothershipSchema;
import org.springframework.validation.BindException;
import org.springframework.validation.Errors;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.ServletException;
import java.awt.*;
import java.io.IOException;
import java.io.Writer;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.*;
import java.util.List;

/**
 * User: jeckels
 * Date: Apr 19, 2006
 */
public class MothershipController extends SpringActionController
{
    private static DefaultActionResolver _actionResolver = new DefaultActionResolver(MothershipController.class);

    private static Logger _log = Logger.getLogger(MothershipController.class);

    public MothershipController()
    {
        setActionResolver(_actionResolver);
    }

    @RequiresPermissionClass(ReadPermission.class)
    public class BeginAction extends SimpleViewAction
    {
        public ModelAndView getView(Object o, BindException errors) throws Exception
        {
            ActionURL url = new ActionURL(ShowExceptionsAction.class, getContainer());
            url.addParameter(DataRegion.LAST_FILTER_PARAM, "true");
            throw new RedirectException(url);
        }

        public NavTree appendNavTrail(NavTree root)
        {
            return null;
        }
    }

    @RequiresPermissionClass(UpdatePermission.class)
    public class ShowUpdateAction extends SimpleViewAction<SoftwareReleaseForm>
    {
        public ModelAndView getView(SoftwareReleaseForm form, BindException errors) throws Exception
        {
            return new UpdateView(form, errors);
        }

        public NavTree appendNavTrail(NavTree root)
        {
            return root.addChild("Update Release Info");
        }
    }

    @RequiresPermissionClass(UpdatePermission.class)
    public class UpdateAction extends FormHandlerAction<SoftwareReleaseForm>
    {
        public void validateCommand(SoftwareReleaseForm target, Errors errors)
        {
        }

        public boolean handlePost(SoftwareReleaseForm form, BindException errors) throws Exception
        {
            SoftwareRelease release = form.getBean();
            MothershipManager.get().updateSoftwareRelease(getContainer(), getUser(), release);
            return true;
        }

        public ActionURL getSuccessURL(SoftwareReleaseForm softwareReleaseForm)
        {
            return new ActionURL(ShowReleasesAction.class, getContainer());
        }
    }

    @RequiresPermissionClass(ReadPermission.class)
    public class ShowReleasesAction extends SimpleViewAction
    {
        public ModelAndView getView(Object o, BindException errors) throws Exception
        {
            HtmlView linkView = new HtmlView(getLinkBarHTML());

            MothershipSchema schema = new MothershipSchema(getUser(), getContainer());
            QuerySettings settings = schema.getSettings(getViewContext(), "softwareReleases", MothershipSchema.SOFTWARE_RELEASES_TABLE_NAME);
            settings.setAllowChooseQuery(false);
            settings.getBaseSort().insertSortColumn("-SVNRevision");
            
            QueryView queryView = schema.createView(getViewContext(), settings, errors);

            return new VBox(linkView, queryView);
        }

        public NavTree appendNavTrail(NavTree root)
        {
            return root.addChild("Installations");
        }
    }

    @RequiresPermissionClass(ReadPermission.class)
    public class ShowRegistrationInstallationGraphAction extends SimpleViewAction
    {
        public ModelAndView getView(Object o, BindException errors) throws Exception
        {
            Calendar start = new GregorianCalendar();
            start.add(Calendar.DATE, -2);
            Calendar cal = new GregorianCalendar();
            cal.set(2006, 6, 1, 0, 0);

            TimeSeries runningTotal = new TimeSeries("Total installations");
            TimeSeries registrations = new TimeSeries("Registered users");

            while(cal.compareTo(start) < 0)
            {
                registrations.add(new Day(cal.getTime()), UserManager.getUserCount(cal.getTime()));

                int totalExternalCount = 0;
                for (ServerInstallation installation : MothershipManager.get().getServerInstallationsActiveBefore(cal))
                {
                    if (!installation.getServerIP().startsWith("140.107"))
                    {
                        totalExternalCount++;
                    }
                }
                runningTotal.add(new Day(cal.getTime()), totalExternalCount);

                cal.add(Calendar.DATE, 7);
            }
            TimeSeriesCollection dataset = new TimeSeriesCollection();
            dataset.addSeries(runningTotal);
            dataset.addSeries(registrations);
            JFreeChart chart = createChart(dataset, "Total Users and Total Installations", "Count");
            XYPlot plot = chart.getXYPlot();

            XYItemRenderer renderer = plot.getRenderer();
            renderer.setSeriesPaint(0, ChartColor.RED);
            renderer.setSeriesPaint(1, ChartColor.BLUE);

            getViewContext().getResponse().setContentType("image/png");
            ChartUtilities.writeChartAsPNG(getViewContext().getResponse().getOutputStream(), chart, 800, 400);
            return null;
        }

        public NavTree appendNavTrail(NavTree root)
        {
            return null;
        }
    }

    @RequiresPermissionClass(ReadPermission.class)
    public class ShowActiveInstallationGraphAction extends SimpleViewAction
    {
        public ModelAndView getView(Object o, BindException errors) throws Exception
        {
            Calendar start = new GregorianCalendar();
            start.add(Calendar.DATE, -2);
            Calendar cal = new GregorianCalendar();
            cal.set(2006, 6, 1, 0, 0);

            TimeSeries externalPings = new TimeSeries("External active");
            TimeSeries repeatPings = new TimeSeries("External that also pinged the previous week");
            Set<String> repeatServerGUIDs = new HashSet<String>();

            while(cal.compareTo(start) < 0)
            {
                ServerInstallation[] installations = MothershipManager.get().getServerInstallationsActiveOn(cal);
                int externalCount = 0;
                int repeatCount = 0;
                for (ServerInstallation installation : installations)
                {
                    if (!installation.getServerIP().startsWith("140.107"))
                    {
                        externalCount++;
                    }

                    if (repeatServerGUIDs.contains(installation.getServerInstallationGUID()))
                    {
                        repeatCount++;
                    }
                }
                externalPings.add(new Day(cal.getTime()), externalCount);
                repeatPings.add(new Day(cal.getTime()), repeatCount);

                repeatServerGUIDs.clear();
                for (ServerInstallation installation : installations)
                {
                    if (!installation.getServerIP().startsWith("140.107"))
                    {
                        repeatServerGUIDs.add(installation.getServerInstallationGUID());
                    }
                }

                cal.add(Calendar.DATE, 7);
            }
            TimeSeriesCollection dataset = new TimeSeriesCollection();
            dataset.addSeries(externalPings);
            dataset.addSeries(repeatPings);
            JFreeChart chart = createChart(dataset, "Active External Installations", "Count");

            XYPlot plot = chart.getXYPlot();

            XYItemRenderer renderer = plot.getRenderer();
            renderer.setSeriesPaint(0, ChartColor.RED);
            renderer.setSeriesPaint(1, ChartColor.BLUE);

            getViewContext().getResponse().setContentType("image/png");
            ChartUtilities.writeChartAsPNG(getViewContext().getResponse().getOutputStream(), chart, 800, 400);
            return null;
        }

        public NavTree appendNavTrail(NavTree root)
        {
            return null;
        }
    }

    private JFreeChart createChart(final XYDataset dataset, String title, String label) {

        // create the chart...
        final JFreeChart chart = ChartFactory.createTimeSeriesChart(
            title,      // chart title
            "Date",                      // x axis label
            label,                      // y axis label
            dataset,                  // data
            true,                     // include legend
            true,                     // tooltips
            false                     // urls
        );
        
        // NOW DO SOME OPTIONAL CUSTOMISATION OF THE CHART...
        chart.setBackgroundPaint(Color.white);

//        final StandardLegend legend = (StandardLegend) chart.getLegend();
  //      legend.setDisplaySeriesShapes(true);

        // get a reference to the plot for further customisation...
        final XYPlot plot = chart.getXYPlot();
        plot.setBackgroundPaint(Color.lightGray);
    //    plot.setAxisOffset(new Spacer(Spacer.ABSOLUTE, 5.0, 5.0, 5.0, 5.0));
        plot.setDomainGridlinePaint(Color.white);
        plot.setRangeGridlinePaint(Color.white);
        plot.getRangeAxis().setLowerBound(0.0);

        final XYLineAndShapeRenderer renderer = new XYLineAndShapeRenderer();
        renderer.setLinesVisible(true);
        renderer.setShapesVisible(false);
        renderer.setStroke(new BasicStroke(2.0f));
        plot.setRenderer(renderer);

        // change the auto tick unit selection to integer units only...
        final NumberAxis rangeAxis = (NumberAxis) plot.getRangeAxis();
        rangeAxis.setStandardTickUnits(NumberAxis.createIntegerTickUnits());
        // OPTIONAL CUSTOMISATION COMPLETED.

        return chart;
    }
    
    @RequiresPermissionClass(DeletePermission.class)
    public class DeleteAction extends FormHandlerAction
    {
        public void validateCommand(Object target, Errors errors)
        {
        }

        public boolean handlePost(Object o, BindException errors) throws Exception
        {
            Set<String> releaseIds = DataRegionSelection.getSelected(getViewContext(), true);
            if (releaseIds != null)
            {
                for (String releaseId : releaseIds)
                    MothershipManager.get().deleteSoftwareRelease(getContainer(), Integer.parseInt(releaseId));
            }
            return true;
        }

        public ActionURL getSuccessURL(Object o)
        {
            return new ActionURL(ShowReleasesAction.class, getContainer());
        }
    }

    @RequiresPermissionClass(ReadPermission.class)
    public class ShowExceptionsAction extends SimpleViewAction
    {
        public ModelAndView getView(Object o, BindException errors) throws Exception
        {
            HtmlView linkView = new HtmlView(getLinkBarHTML());

            MothershipSchema schema = new MothershipSchema(getUser(), getContainer());
            QuerySettings settings = schema.getSettings(getViewContext(), "ExceptionSummary", MothershipSchema.EXCEPTION_STACK_TRACE_TABLE_NAME);
            settings.setAllowChooseQuery(false);
            settings.getBaseSort().insertSortColumn("-ExceptionStackTraceId");

            QueryView queryView = schema.createView(getViewContext(), settings, errors);
            queryView.setShowDetailsColumn(false);
            queryView.setShadeAlternatingRows(true);
            queryView.setShowBorders(true);

            return new VBox(linkView, queryView);
        }

        public NavTree appendNavTrail(NavTree root)
        {
            return root.addChild("Exceptions");
        }
    }

    @RequiresPermissionClass(InsertPermission.class)
    public class ShowInsertAction extends SimpleViewAction
    {
        public ModelAndView getView(Object o, BindException errors) throws Exception
        {
            DataRegion region = new DataRegion();
            region.addColumns(MothershipManager.get().getTableInfoSoftwareRelease(), "SVNRevision,Description");
            return new InsertView(region, errors);
        }

        public NavTree appendNavTrail(NavTree root)
        {
            return root.addChild("Insert Software Release");
        }
    }

    @RequiresPermissionClass(InsertPermission.class)
    public class InsertAction extends FormHandlerAction<SoftwareReleaseForm>
    {
        public void validateCommand(SoftwareReleaseForm target, Errors errors)
        {}

        public boolean handlePost(SoftwareReleaseForm form, BindException errors) throws Exception
        {
            MothershipManager.get().insertSoftwareRelease(getContainer(), getUser(), form.getBean());
            return true;
        }

        public ActionURL getSuccessURL(SoftwareReleaseForm softwareReleaseForm)
        {
            return new ActionURL(ShowReleasesAction.class, getContainer());
        }
    }

    @RequiresPermissionClass(ReadPermission.class)
    public class ShowInstallationsAction extends SimpleViewAction
    {
        public ModelAndView getView(Object o, BindException errors) throws Exception
        {
            HtmlView linkView = new HtmlView(getLinkBarHTML());

            MothershipSchema schema = new MothershipSchema(getUser(), getContainer());
            QuerySettings settings = schema.getSettings(getViewContext(), "serverInstallations", MothershipSchema.SERVER_INSTALLATIONS_TABLE_NAME);
            settings.setSchemaName(schema.getSchemaName());
            settings.setAllowChooseQuery(false);
            settings.getBaseSort().insertSortColumn("-LastPing");

            List<Aggregate> aggregates = new ArrayList<Aggregate>();
            aggregates.add(new Aggregate("DaysActive", Aggregate.Type.AVG));
            aggregates.add(new Aggregate("ExceptionCount", Aggregate.Type.AVG));
            settings.setAggregates(aggregates);

            QueryView gridView = schema.createView(getViewContext(), settings, errors);

            return new VBox(linkView, gridView);
        }

        public NavTree appendNavTrail(NavTree root)
        {
            return root.addChild("Installations");
        }
    }

    @RequiresPermissionClass(UpdatePermission.class)
    public class CreateIssueFinishedAction extends SimpleViewAction<CreateIssueFinishedForm>
    {
        public ModelAndView getView(CreateIssueFinishedForm form, BindException errors) throws Exception
        {
            ExceptionStackTrace stackTrace = MothershipManager.get().getExceptionStackTrace(form.getExceptionStackTraceId(), getContainer());
            stackTrace.setBugNumber(form.getIssueId());
            MothershipManager.get().updateExceptionStackTrace(stackTrace, getUser());
            throw new RedirectException(new ActionURL(BeginAction.class, getContainer()));
        }

        public NavTree appendNavTrail(NavTree root)
        {
            throw new UnsupportedOperationException();
        }
    }

    @RequiresPermissionClass(UpdatePermission.class)
    public class EditUpgradeMessageAction extends SimpleViewAction
    {
        public ModelAndView getView(Object o, BindException errors) throws Exception
        {
            UpgradeMessageForm form = new UpgradeMessageForm();

            form.setCurrentRevision(MothershipManager.get().getCurrentRevision(getContainer()));
            form.setMessage(MothershipManager.get().getUpgradeMessage(getContainer()));
            form.setCreateIssueURL(MothershipManager.get().getCreateIssueURL(getContainer()));
            form.setIssuesContainer(MothershipManager.get().getIssuesContainer(getContainer()));

            HtmlView linkView = new HtmlView(getLinkBarHTML());
            return new VBox(linkView, new JspView<UpgradeMessageForm>("/org/labkey/mothership/editUpgradeMessage.jsp", form));
        }

        public NavTree appendNavTrail(NavTree root)
        {
            return root.addChild("Upgrade Message");
        }
    }

    @RequiresPermissionClass(UpdatePermission.class)
    public class SaveUpgradeMessageAction extends FormHandlerAction<UpgradeMessageForm>
    {
        public void validateCommand(UpgradeMessageForm target, Errors errors)
        {}

        public boolean handlePost(UpgradeMessageForm form, BindException errors) throws Exception
        {
            MothershipManager.get().setCurrentRevision(getContainer(), form.getCurrentRevision());
            MothershipManager.get().setUpgradeMessage(getContainer(), form.getMessage());
            MothershipManager.get().setCreateIssueURL(getContainer(), form.getCreateIssueURL());
            MothershipManager.get().setIssuesContainer(getContainer(), form.getIssuesContainer());
            return true;
        }

        public ActionURL getSuccessURL(UpgradeMessageForm upgradeMessageForm)
        {
            return new ActionURL(BeginAction.class, getContainer());
        }
    }

    @RequiresPermissionClass(ReadPermission.class)
    public class ShowServerSessionDetailAction extends SimpleViewAction<ServerSessionForm>
    {
        public ModelAndView getView(ServerSessionForm form, BindException errors) throws Exception
        {
            ServerSession session = form.getBean();
            if (session == null)
            {
                throw new NotFoundException();
            }
            ServerSessionDetailView detailView = new ServerSessionDetailView(form);
            
            MothershipSchema schema = new MothershipSchema(getUser(), getContainer());
            QuerySettings settings = new QuerySettings(getViewContext(), "ExceptionReports", MothershipSchema.EXCEPTION_REPORT_WITH_STACK_TABLE_NAME);
            settings.setAllowChooseQuery(false);
            settings.getBaseSort().insertSortColumn("-Created");
            settings.getBaseFilter().addCondition("ServerSessionId", session.getServerSessionId());

            QueryView exceptionGridView = new QueryView(schema, settings, errors);
            exceptionGridView.setShadeAlternatingRows(true);
            exceptionGridView.setShowBorders(true);
            exceptionGridView.setButtonBarPosition(DataRegion.ButtonBarPosition.TOP);
            exceptionGridView.setShowExportButtons(false);

            return new VBox(detailView, exceptionGridView);
        }

        public NavTree appendNavTrail(NavTree root)
        {
            return root.addChild("Server Session");
        }
    }

    @RequiresPermissionClass(ReadPermission.class)
    public class ShowInstallationDetailAction extends SimpleViewAction<ServerInstallationForm>
    {
        public ModelAndView getView(ServerInstallationForm form, BindException errors) throws Exception
        {
            ServerInstallation installation = form.getBean();
            if (installation == null)
            {
                throw new NotFoundException();
            }
            ServerInstallationUpdateView updateView = new ServerInstallationUpdateView(form, getViewContext().getActionURL(), errors);

            MothershipSchema schema = new MothershipSchema(MothershipController.this.getUser(), MothershipController.this.getContainer());
            QuerySettings settings = schema.getSettings(getViewContext(), "ServerSessions", "ServerSessions");
            settings.setAllowChooseQuery(false);
            settings.getBaseSort().insertSortColumn("-ServerSessionId");
            settings.getBaseFilter().addCondition("ServerInstallationId", installation.getServerInstallationId());

            QueryView sessionGridView = schema.createView(getViewContext(), settings, errors);
            sessionGridView.setShowExportButtons(false);
            
            return new VBox(updateView, sessionGridView);
        }

        public NavTree appendNavTrail(NavTree root)
        {
            return root.addChild("Server Installation");
        }
    }

    @RequiresPermissionClass(ReadPermission.class)
    public class ShowStackTraceDetailAction extends SimpleViewAction<ExceptionStackTraceForm>
    {
        public ModelAndView getView(ExceptionStackTraceForm form, BindException errors) throws Exception
        {
            ExceptionStackTrace stackTrace;
            try
            {
                stackTrace = form.getBean();
                stackTrace = MothershipManager.get().getExceptionStackTrace(stackTrace.getExceptionStackTraceId(), getContainer());
            }
            catch (ConversionException e)
            {
                throw new NotFoundException();
            }
            if (stackTrace == null)
            {
                throw new NotFoundException();
            }
            ExceptionStackTraceUpdateView updateView = new ExceptionStackTraceUpdateView(form, getViewContext().getActionURL(), getContainer(), errors);

            MothershipSchema schema = new MothershipSchema(getUser(), getContainer());
            QuerySettings settings = new QuerySettings(getViewContext(), "ExceptionReports", MothershipSchema.EXCEPTION_REPORT_TABLE_NAME);
            settings.setAllowChooseQuery(false);
            settings.getBaseSort().insertSortColumn("-Created");
            settings.getBaseFilter().addCondition("ExceptionStackTraceId", stackTrace.getExceptionStackTraceId());

            QueryView summaryGridView = new QueryView(schema, settings, errors);
            summaryGridView.setShowBorders(true);
            summaryGridView.setShadeAlternatingRows(true);
            summaryGridView.setButtonBarPosition(DataRegion.ButtonBarPosition.BOTH);
            return new VBox(updateView, summaryGridView);
        }

        public NavTree appendNavTrail(NavTree root)
        {
            return root.addChild("Exception Reports");
        }
    }

    @RequiresPermissionClass(UpdatePermission.class)
    public class UpdateStackTraceAction extends FormHandlerAction<ExceptionStackTraceForm>
    {
        public void validateCommand(ExceptionStackTraceForm target, Errors errors)
        {}

        public boolean handlePost(ExceptionStackTraceForm form, BindException errors) throws Exception
        {
            form.doUpdate();
            return true;
        }

        public ActionURL getSuccessURL(ExceptionStackTraceForm exceptionStackTraceForm)
        {
            return new ActionURL(ShowExceptionsAction.class, getContainer()).addParameter(DataRegion.LAST_FILTER_PARAM, "true");
        }
    }

    @RequiresPermissionClass(UpdatePermission.class)
    public class UpdateInstallationAction extends FormHandlerAction<ServerInstallationForm>
    {
        public void validateCommand(ServerInstallationForm target, Errors errors)
        {}

        public boolean handlePost(ServerInstallationForm form, BindException errors) throws Exception
        {
            form.doUpdate();
            return true;
        }

        public ActionURL getSuccessURL(ServerInstallationForm form)
        {
            return new ActionURL(ShowInstallationDetailAction.class, getContainer()).addParameter("serverInstallationId", form.getPkVal().toString());
        }
    }

    @RequiresNoPermission
    public class ReportExceptionAction extends SimpleViewAction<ExceptionForm>
    {
        public ModelAndView getView(ExceptionForm form, BindException errors) throws Exception
        {
            try
            {
                ExceptionStackTrace stackTrace = new ExceptionStackTrace();
                stackTrace.setStackTrace(form.getStackTrace());
                stackTrace.setContainer(getContainer().getId());

                ServerSession session = form.toSession(getContainer());

                ServerInstallation installation = new ServerInstallation();
                installation.setServerIP(getViewContext().getRequest().getRemoteAddr());
                installation.setServerInstallationGUID(form.getServerGUID());

                session = MothershipManager.get().updateServerSession(session, installation, getContainer());
                if (form.getSvnRevision() != null && form.getSvnURL() != null)
                {
                    ExceptionReport report = new ExceptionReport();
                    report.setExceptionMessage(form.getExceptionMessage());
                    if (null == form.getExceptionMessage() && stackTrace.getStackTrace() != null)
                    {
                        // Grab the first line of the exception report so that we don't lose things like
                        // file paths or other unique info that's thrown away as part of the de-dupe process
                        // for otherwise identical stacks
                        report.setExceptionMessage(stackTrace.getStackTrace().split("[\\r\\n]")[0]);
                    }
                    report.setURL(form.getRequestURL());
                    report.setUsernameform(form.getUsername());
                    report.setReferrerURL(form.getReferrerURL());
                    report.setSQLState(form.getSqlState());
                    report.setPageflowAction(form.getPageflowAction());
                    report.setPageflowName(form.getPageflowName());
                    report.setBrowser(form.getBrowser());
                    report.setServerSessionId(session.getServerSessionId());
                    
                    MothershipManager.get().insertException(stackTrace, report);
                }
                setSuccessHeader();
            }
            catch (Exception e)
            {
                // Need to catch and not rethrow or this failure might submit
                // an exception report, which would fail and report an exception,
                // and continue infinitely.
                _log.error("Failed to log exception report", e);
            }
            return null;
        }

        public NavTree appendNavTrail(NavTree root)
        {
            return null;
        }
    }

    @RequiresPermissionClass(ReadPermission.class)
    public class ThrowExceptionAction extends SimpleViewAction
    {
        public ModelAndView getView(Object o, BindException errors) throws Exception
        {
//            throw new UnsupportedOperationException("Intentional exception for testing purposes");
            throw new SQLException("Intentional exception for testing purposes", "400");
        }

        public NavTree appendNavTrail(NavTree root)
        {
            throw new UnsupportedOperationException("Intentional exception for testing purposes");
        }
    }

    @RequiresNoPermission
    public class CheckForUpdatesAction extends SimpleViewAction<UpdateCheckForm>
    {
        public ModelAndView getView(UpdateCheckForm form, BindException errors) throws Exception
        {
            // First log this installation and session
            ServerSession session = form.toSession(getContainer());
            ServerInstallation installation = new ServerInstallation();
            if (form.getServerGUID() != null)
            {
                installation.setServerInstallationGUID(form.getServerGUID());
                installation.setLogoLink(form.getLogoLink());
                installation.setOrganizationName(form.getOrganizationName());
                installation.setServerIP(getViewContext().getRequest().getRemoteAddr());
                installation.setSystemDescription(form.getSystemDescription());
                installation.setSystemShortName(form.getSystemShortName());
                installation.setContainer(getContainer().getId());
                MothershipManager.get().updateServerSession(session, installation, getContainer());
                setSuccessHeader();
                getViewContext().getResponse().getWriter().print(getUpgradeMessage(form.parseSvnRevision()));
            }

            return null;
        }


        public NavTree appendNavTrail(NavTree root)
        {
            return null;
        }
    }

    private void setSuccessHeader()
    {
        getViewContext().getResponse().setHeader(MothershipReport.MOTHERSHIP_STATUS_HEADER_NAME, MothershipReport.MOTHERSHIP_STATUS_SUCCESS);
    }

    @RequiresPermissionClass(ReadPermission.class)
    public class ReportsAction extends SimpleViewAction
    {
        public NavTree appendNavTrail(NavTree root)
        {
            return root.addChild("Mothership Reports");
        }

        public ModelAndView getView(Object o, BindException errors) throws Exception
        {
            HtmlView linkView = new HtmlView(getLinkBarHTML());
            HtmlView graphView = new HtmlView("Installations", "<img src=\"showActiveInstallationGraph.view\" height=\"400\" width=\"800\" /><br/><br/><img src=\"showRegistrationInstallationGraph.view\" height=\"400\" width=\"800\" />");
            return new VBox(linkView, new UnbuggedExceptionsGridView(), new UnassignedExceptionsGridView(), graphView);
        }
    }

    private class ResultSetGridView extends GridView
    {
        public ResultSetGridView(String title, String sql) throws SQLException
        {
            super(new DataRegion(), (BindException)null);
            setTitle(title);
            TableInfo exceptionTableInfo = MothershipManager.get().getTableInfoServerInstallation();
            getDataRegion().setTable(exceptionTableInfo);
            ResultSet rs = Table.executeQuery(exceptionTableInfo.getSchema(), sql, null);
            setResultSet(rs);
            getDataRegion().setColumns(DataRegion.colInfosFromMetaData(rs.getMetaData()));
            getDataRegion().setSortable(false);
            getDataRegion().setShowFilters(false);
            getDataRegion().setButtonBar(ButtonBar.BUTTON_BAR_EMPTY);
            getDataRegion().setShowPagination(false);
        }
    }

    private class UnbuggedExceptionsGridView extends ResultSetGridView
    {
        public UnbuggedExceptionsGridView() throws SQLException
        {
            super("\"Unbugged\" Exceptions by Owner",
                    "SELECT core.usersdata.displayname as Owner, count(*) as ExceptionCount \n" +
                    "FROM mothership.exceptionstacktrace, core.principals, core.usersdata\n" +
                    "WHERE assignedto IS NOT NULL AND bugnumber IS NULL\n" +
                    "and core.principals.userid = assignedto\n" +
                    "and core.principals.userid = core.usersdata.userid\n" +
                    "group by core.usersdata.displayname order by ExceptionCount DESC");
            getDataRegion().getDisplayColumn("Owner").setURL("mothership/showExceptions.view?ExceptionSummary.BugNumber~isblank=&ExceptionSummary.AssignedTo/DisplayName~eq=${Owner}");
            getDataRegion().getDisplayColumn("Owner").setWidth("200");
            getDataRegion().getDisplayColumn("ExceptionCount").setCaption("Exception Count");
        }
    }

    private class UnassignedExceptionsGridView extends ResultSetGridView
    {
        public UnassignedExceptionsGridView() throws SQLException
        {
            super("Unassigned Exceptions",
                    "SELECT COUNT(ExceptionStackTraceId) AS TotalCount\n" +
                            "FROM Mothership.ExceptionStackTrace AS Trace\n" +
                            "WHERE Trace.AssignedTo IS NULL AND Trace.BugNumber IS NULL");
            getDataRegion().getDisplayColumn("TotalCount").setURL("mothership/showExceptions.view?ExceptionSummary.AssignedTo/DisplayName~isblank&ExceptionSummary.BugNumber~isblank");
        }
    }

    private String getUpgradeMessage(Integer rev) throws ServletException, SQLException
    {
        int currentRevision = MothershipManager.get().getCurrentRevision(getContainer());

        if (rev != null && rev.intValue() < currentRevision)
        {
            return MothershipManager.get().getUpgradeMessage(getContainer());
        }
        return "";
    }

    private String getLinkBarHTML()
    {
        StringBuilder builder = new StringBuilder();
        builder.append(PageFlowUtil.textLink("View Exceptions", "showExceptions.view?" + DataRegion.LAST_FILTER_PARAM + "=true") + " " +
            PageFlowUtil.textLink("View All Installations", "showInstallations.view") + " " +
            PageFlowUtil.textLink("Configure Mothership", "editUpgradeMessage.view") + " " +
            PageFlowUtil.textLink("List of Releases", "showReleases.view") + " " +
            PageFlowUtil.textLink("Reports", "reports.view") + " ");

        if (getUser() != null && !getUser().isGuest())
        {
            String link = "showExceptions.view?ExceptionSummary.BugNumber~isblank=&ExceptionSummary.AssignedTo~eq=" + getUser().getUserId();
            builder.append(PageFlowUtil.textLink("My Exceptions", link));
        }

        return builder.toString();
    }

    public static abstract class ServerInfoForm
    {
        private String _svnRevision;
        private String _svnURL;
        private String _runtimeOS;
        private String _javaVersion;
        private String _databaseProductName;
        private String _databaseProductVersion;
        private String _databaseDriverName;
        private String _databaseDriverVersion;
        private String _serverSessionGUID;
        private String _serverGUID;

        private Integer _userCount;
        private Integer _activeUserCount;
        private Integer _projectCount;
        private Integer _containerCount;
        private Integer _heapSize;
        private String _administratorEmail;
        private boolean _ldapEnabled;
        private boolean _enterprisePipelineEnabled;

        public String getSvnURL()
        {
            return _svnURL;
        }

        public void setSvnURL(String svnURL)
        {
            _svnURL = svnURL;
        }

        public String getRuntimeOS()
        {
            return _runtimeOS;
        }

        public void setRuntimeOS(String runtimeOS)
        {
            _runtimeOS = runtimeOS;
        }

        public String getJavaVersion()
        {
            return _javaVersion;
        }

        public void setJavaVersion(String javaVersion)
        {
            _javaVersion = javaVersion;
        }

        public String getDatabaseProductName()
        {
            return _databaseProductName;
        }

        public void setDatabaseProductName(String databaseProductName)
        {
            _databaseProductName = databaseProductName;
        }

        public String getDatabaseProductVersion()
        {
            return _databaseProductVersion;
        }

        public void setDatabaseProductVersion(String databaseProductVersion)
        {
            _databaseProductVersion = databaseProductVersion;
        }

        public String getDatabaseDriverName()
        {
            return _databaseDriverName;
        }

        public void setDatabaseDriverName(String databaseDriverName)
        {
            _databaseDriverName = databaseDriverName;
        }

        public String getDatabaseDriverVersion()
        {
            return _databaseDriverVersion;
        }

        public void setDatabaseDriverVersion(String databaseDriverVersion)
        {
            _databaseDriverVersion = databaseDriverVersion;
        }

        public String getServerSessionGUID()
        {
            return _serverSessionGUID;
        }

        public void setServerSessionGUID(String serverSessionGUID)
        {
            _serverSessionGUID = serverSessionGUID;
        }

        public String getServerGUID()
        {
            return _serverGUID;
        }

        public void setServerGUID(String serverGUID)
        {
            _serverGUID = serverGUID;
        }

        public String getSvnRevision()
        {
            return _svnRevision;
        }

        public Integer parseSvnRevision()
        {
            try
            {
                return new Integer(getSvnRevision());
            }
            catch (NumberFormatException e)
            {
                // Probably not built from an SVN enlistment
                return null;
            }
        }

        public void setSvnRevision(String svnRevision)
        {
            _svnRevision = svnRevision;
        }

        public Integer getUserCount()
        {
            return _userCount;
        }

        public void setUserCount(Integer userCount)
        {
            _userCount = userCount;
        }

        public Integer getActiveUserCount()
        {
            return _activeUserCount;
        }

        public void setActiveUserCount(Integer activeUserCount)
        {
            _activeUserCount = activeUserCount;
        }

        public Integer getProjectCount()
        {
            return _projectCount;
        }

        public void setProjectCount(Integer projectCount)
        {
            _projectCount = projectCount;
        }

        public Integer getContainerCount()
        {
            return _containerCount;
        }

        public void setContainerCount(Integer containerCount)
        {
            _containerCount = containerCount;
        }

        public String getAdministratorEmail()
        {
            return _administratorEmail;
        }

        public void setAdministratorEmail(String administratorEmail)
        {
            _administratorEmail = administratorEmail;
        }

        public Integer getHeapSize()
        {
            return _heapSize;
        }

        public void setHeapSize(Integer heapSize)
        {
            _heapSize = heapSize;
        }

        public ServerSession toSession(Container container)
        {
            ServerSession session = new ServerSession();
            SoftwareRelease release = MothershipManager.get().ensureSoftwareRelease(container, parseSvnRevision(), getSvnURL());
            session.setSoftwareReleaseId(release.getSoftwareReleaseId());

            session.setServerSessionGUID(getServerSessionGUID());
            session.setDatabaseDriverName(getDatabaseDriverName());
            session.setDatabaseDriverVersion(getDatabaseDriverVersion());
            session.setDatabaseProductName(getDatabaseProductName());
            session.setDatabaseProductVersion(getDatabaseProductVersion());
            session.setRuntimeOS(getRuntimeOS());
            session.setJavaVersion(getJavaVersion());
            session.setContainer(container.getId());
            session.setActiveUserCount(getActiveUserCount());
            session.setUserCount(getUserCount());
            session.setProjectCount(getProjectCount());
            session.setContainerCount(getContainerCount());
            session.setAdministratorEmail(getAdministratorEmail());
            session.setLdapEnabled(isLDAPEnabled());
            session.setEnterprisePipelineEnabled(isEnterprisePipelineEnabled());
            session.setHeapSize(getHeapSize());

            return session;
        }

        public boolean isLDAPEnabled()
        {
            return _ldapEnabled;
        }

        public boolean isEnterprisePipelineEnabled()
        {
            return _enterprisePipelineEnabled;
        }

        public void setLdapEnabled(boolean ldapEnabled)
        {
            _ldapEnabled = ldapEnabled;
        }

        public void setEnterprisePipelineEnabled(boolean enterprisePipelineEnabled)
        {
            _enterprisePipelineEnabled = enterprisePipelineEnabled;
        }
    }

    public static class UpdateCheckForm extends ServerInfoForm
    {
        private String _systemDescription;
        private String _logoLink;
        private String _organizationName;
        private String _systemShortName;

        public String getLogoLink()
        {
            return _logoLink;
        }

        public void setLogoLink(String logoLink)
        {
            _logoLink = logoLink;
        }

        public String getOrganizationName()
        {
            return _organizationName;
        }

        public void setOrganizationName(String organizationName)
        {
            _organizationName = organizationName;
        }

        public String getSystemShortName()
        {
            return _systemShortName;
        }

        public void setSystemShortName(String systemShortName)
        {
            _systemShortName = systemShortName;
        }

        public String getSystemDescription()
        {
            return _systemDescription;
        }

        public void setSystemDescription(String systemDescription)
        {
            _systemDescription = systemDescription;
        }
    }

    public static class ExceptionForm extends ServerInfoForm
    {
        private String _stackTrace;
        private String _requestURL;
        private String _browser;
        private String _username;
        private String _referrerURL;
        private String _pageflowName;
        private String _pageflowAction;
        private String _sqlState;

        public String getExceptionMessage()
        {
            return _exceptionMessage;
        }

        public void setExceptionMessage(String exceptionMessage)
        {
            _exceptionMessage = exceptionMessage;
        }

        private String _exceptionMessage;

        public String getUsername()
        {
            return _username;
        }

        public void setUsername(String username)
        {
            _username = username;
        }

        public String getStackTrace()
        {
            return _stackTrace;
        }

        public void setStackTrace(String stackTrace)
        {
            _stackTrace = stackTrace;
        }

        public String getRequestURL()
        {
            return _requestURL;
        }

        public void setRequestURL(String requestURL)
        {
            _requestURL = requestURL;
        }

        public String getBrowser()
        {
            return _browser;
        }

        public void setBrowser(String browser)
        {
            _browser = browser;
        }


        public String getPageflowAction()
        {
            return _pageflowAction;
        }

        public void setPageflowAction(String pageflowAction)
        {
            _pageflowAction = pageflowAction;
        }

        public String getPageflowName()
        {
            return _pageflowName;
        }

        public void setPageflowName(String pageflowName)
        {
            _pageflowName = pageflowName;
        }

        public String getReferrerURL()
        {
            return _referrerURL;
        }

        public void setReferrerURL(String referrerURL)
        {
            _referrerURL = referrerURL;
        }

        public String getSqlState()
        {
            return _sqlState;
        }

        public void setSqlState(String sqlState)
        {
            _sqlState = sqlState;
        }
    }

    public static class ServerSessionDetailView extends DetailsView
    {
        public ServerSessionDetailView(final ServerSessionForm form)
        {
            super(new DataRegion(), form);
            getDataRegion().setTable(MothershipManager.get().getTableInfoServerSession());
            getDataRegion().addColumns(MothershipManager.get().getTableInfoServerSession(), "ServerSessionId,ServerSessionGUID,ServerInstallationId,EarliestKnownTime,LastKnownTime,DatabaseProductName,DatabaseProductVersion,DatabaseDriverName,DatabaseDriverVersion,RuntimeOS,JavaVersion,SoftwareReleaseId,UserCount,ActiveUserCount,ProjectCount,ContainerCount,AdministratorEmail,EnterprisePipelineEnabled,LDAPEnabled");
            final DisplayColumn defaultServerInstallationColumn = getDataRegion().getDisplayColumn("ServerInstallationId");
            defaultServerInstallationColumn.setVisible(false);
            DataColumn replacementServerInstallationColumn = new DataColumn(defaultServerInstallationColumn.getColumnInfo())
            {
                public void renderDetailsCellContents(RenderContext ctx, Writer out) throws IOException
                {
                    Map<String, Object> row = ctx.getRow();

                    ColumnInfo displayColumn = defaultServerInstallationColumn.getColumnInfo().getDisplayField();

                    ServerInstallation si = MothershipManager.get().getServerInstallation(((Integer)row.get("ServerInstallationId")).intValue(), ctx.getContainer().getId());
                    if (si != null && si.getNote() != null && si.getNote().trim().length() > 0)
                    {
                        row.put(displayColumn.getAlias(), si.getNote());
                    }
                    else
                    {
                        Object displayValue = displayColumn.getValue(ctx);
                        if (displayValue == null || "".equals(displayValue))
                        {
                            if (si != null && si.getServerHostName() != null && si.getServerHostName().trim().length() > 0)
                            {
                                row.put(displayColumn.getAlias(), si.getServerHostName());
                            }
                            else
                            {
                                row.put(displayColumn.getAlias(), "[Unnamed]");
                            }
                        }
                    }
                    super.renderDetailsCellContents(ctx, out);
                }
            };

            replacementServerInstallationColumn.setCaption("Server Installation");
            replacementServerInstallationColumn.setURLExpression(new DetailsURL(
                    new ActionURL(ShowInstallationDetailAction.class, getViewContext().getContainer()),
                    Collections.singletonMap("serverInstallationId", "ServerInstallationId")));
            getDataRegion().addDisplayColumn(3, replacementServerInstallationColumn);

            ButtonBar bb = new ButtonBar();
            getDataRegion().setButtonBar(bb);
            setTitle("Server Session Details");
        }
    }

    public static class ExceptionStackTraceUpdateView extends UpdateView
    {
        public ExceptionStackTraceUpdateView(ExceptionStackTraceForm form, ActionURL url, Container c, BindException errors)
        {
            super(new DataRegion(), form, errors);

            ButtonBar bb = new ButtonBar();
            bb.setStyle(ButtonBar.Style.separateButtons);
            ActionURL saveURL = new ActionURL(UpdateStackTraceAction.class, c);
            ActionButton b = new ActionButton(saveURL, "Save");
            b.setDisplayPermission(UpdatePermission.class);
            bb.add(b);

            getDataRegion().setButtonBar(bb);
            getDataRegion().setFormActionUrl(saveURL);
            getDataRegion().setTable(MothershipManager.get().getTableInfoExceptionStackTrace());
            getDataRegion().addColumns(MothershipManager.get().getTableInfoExceptionStackTrace(), "ExceptionStackTraceId,StackTrace,BugNumber,Comments");
            getDataRegion().addHiddenFormField("exceptionStackTraceId", Integer.toString(form.getBean().getExceptionStackTraceId()));
            getDataRegion().addDisplayColumn(new AssignedToDisplayColumn(MothershipManager.get().getTableInfoExceptionStackTrace().getColumn("AssignedTo"), c));
            getDataRegion().getDisplayColumn(1).setVisible(false);
            getDataRegion().addDisplayColumn(new CreateIssueDisplayColumn(MothershipManager.get().getTableInfoExceptionStackTrace().getColumn("StackTrace"), b));
            getDataRegion().addDisplayColumn(new StackTraceDisplayColumn(MothershipManager.get().getTableInfoExceptionStackTrace().getColumn("StackTrace")));

            setTitle("Exception Stack Trace Details");
        }
    }

    public static class ServerInstallationUpdateView extends UpdateView
    {
        public ServerInstallationUpdateView(ServerInstallationForm form, ActionURL url, BindException errors)
        {
            super(new DataRegion(), form, errors);

            getDataRegion().setTable(MothershipManager.get().getTableInfoServerInstallation());
            getDataRegion().addColumns(MothershipManager.get().getTableInfoServerInstallation(), "ServerInstallationId,ServerInstallationGUID,Note,OrganizationName,ServerHostName,ServerIP,LogoLink,SystemDescription,SystemShortName");
            getDataRegion().addHiddenFormField("ServerInstallationId", form.getPkVal().toString());
            ButtonBar bb = new ButtonBar();
            bb.setStyle(ButtonBar.Style.separateButtons);
            ActionButton b = new ActionButton(new ActionURL(UpdateInstallationAction.class, getViewContext().getContainer()), "Save");
            b.setDisplayPermission(UpdatePermission.class);
            bb.add(b);
            getDataRegion().setButtonBar(bb);

            setTitle("Server Installation Details");
        }
    }

    public static class ExceptionStackTraceForm extends BeanViewForm<ExceptionStackTrace>
    {
        public ExceptionStackTraceForm()
        {
            super(ExceptionStackTrace.class, MothershipManager.get().getTableInfoExceptionStackTrace());
        }

        public ExceptionStackTraceForm(ExceptionStackTrace stackTrace)
        {
            this();
            setBean(stackTrace);
        }
    }

    public static class ServerInstallationForm extends BeanViewForm<ServerInstallation>
    {
        public ServerInstallationForm(ServerInstallation installation)
        {
            this();
            setBean(installation);
        }

        public ServerInstallationForm()
        {
            super(ServerInstallation.class, MothershipManager.get().getTableInfoServerInstallation());
        }
    }

    public static class ServerSessionForm extends BeanViewForm<ServerSession>
    {
        public ServerSessionForm(ServerSession session)
        {
            this();
            setBean(session);
        }

        public ServerSessionForm()
        {
            super(ServerSession.class, MothershipManager.get().getTableInfoServerSession());
        }
    }

    public static class CreateIssueFinishedForm
    {
        private int _exceptionStackTraceId;
        private int _issueId;

        public int getExceptionStackTraceId()
        {
            return _exceptionStackTraceId;
        }

        public void setExceptionStackTraceId(int exceptionStackTraceId)
        {
            _exceptionStackTraceId = exceptionStackTraceId;
        }

        public int getIssueId()
        {
            return _issueId;
        }

        public void setIssueId(int issueId)
        {
            _issueId = issueId;
        }
    }

    public static class SoftwareReleaseForm extends BeanViewForm<SoftwareRelease>
    {
        public SoftwareReleaseForm(SoftwareRelease release)
        {
            this();
            setBean(release);
        }

        public SoftwareReleaseForm()
        {
            super(SoftwareRelease.class, MothershipManager.get().getTableInfoSoftwareRelease());
        }
    }


    public static class UpgradeMessageForm
    {
        private int _currentRevision;
        private String _message;
        private String _createIssueURL;
        private String _issuesContainer;

        public int getCurrentRevision()
        {
            return _currentRevision;
        }

        public void setCurrentRevision(int currentRevision)
        {
            _currentRevision = currentRevision;
        }

        public String getMessage()
        {
            return _message;
        }

        public void setMessage(String message)
        {
            _message = message;
        }

        public void setCreateIssueURL(String createIssueURL)
        {
            _createIssueURL = createIssueURL;
        }

        public String getCreateIssueURL()
        {
            return _createIssueURL;
        }

        public void setIssuesContainer(String issuesContainer)
        {
            _issuesContainer = issuesContainer;
        }

        public String getIssuesContainer()
        {
            return _issuesContainer;
        }
    }
}

