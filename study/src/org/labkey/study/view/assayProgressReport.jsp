<%
    /*
     * Copyright (c) 2017 LabKey Corporation
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
%>

<%@ page import="org.labkey.api.util.UniqueID"%>
<%@ page import="org.labkey.api.view.HttpView" %>
<%@ page import="org.labkey.api.view.JspView" %>
<%@ page import="org.labkey.api.view.template.ClientDependencies" %>
<%@ page import="org.labkey.study.controllers.reports.ReportsController" %>
<%@ page extends="org.labkey.study.view.BaseStudyPage" %>
<%@ taglib prefix="labkey" uri="http://www.labkey.org/taglib" %>
<%!
    @Override
    public void addClientDependencies(ClientDependencies dependencies)
    {
        dependencies.add("progress-report");
    }
%>

<%
    JspView<ReportsController.ProgressReportForm> me = (JspView<ReportsController.ProgressReportForm>)HttpView.currentView();
    ReportsController.ProgressReportForm form = me.getModelBean();

    String renderId = "participant-report-div-" + UniqueID.getRequestScopedUID(HttpView.currentRequest());
%>

<h1>Create Assay Progress Report</h1>
<div id=<%=h(renderId)%>></div>

<script type="text/javascript">
    Ext4.onReady(function(){

        new LABKEY.ext4.ProgressReportConfig({
            renderTo    : <%=q(renderId)%>
        });
    });
</script>