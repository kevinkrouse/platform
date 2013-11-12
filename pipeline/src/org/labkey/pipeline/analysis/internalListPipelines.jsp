<%
/*
 * Copyright (c) 2013 LabKey Corporation
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
<%@ page import="org.labkey.api.pipeline.PipelineJobService" %>
<%@ page import="org.labkey.api.pipeline.TaskPipeline" %>
<%@ page import="org.labkey.api.pipeline.TaskId" %>
<%@ page import="java.util.Collection" %>
<%@ taglib prefix="labkey" uri="http://www.labkey.org/taglib" %>
<%@ page extends="org.labkey.api.jsp.JspBase" %>
<%
    Collection<TaskPipeline> pipelines = PipelineJobService.get().getTaskPipelines(null);
%>

<labkey:errors />

<p>Registered Pipelines:</p>

<table>

<% for (TaskPipeline pipeline : pipelines) { %>
    <tr>
        <td><b>Module</b></td>
        <td><%=h(pipeline.getDeclaringModule().getName())%></td>
    </tr>
    <tr>
        <td><b>Task Id</b></td>
        <td><%=h(pipeline.getId())%></td>
    </tr>
    <tr>
        <td><b>Protocol Id</b></td>
        <td><%=h(pipeline.getProtocolIdentifier())%></td>
    </tr>
    <tr>
        <td><b>Protocol Description</b></td>
        <td><%=h(pipeline.getProtocolShortDescription())%></td>
    </tr>
    <tr>
        <td><b>Description</b></td>
        <td colspan=4><%=h(pipeline.getDescription())%></td>
    </tr>
    <tr>
        <td valign=top><b>Tasks</b></td>
        <td colspan=4>
            <%
                TaskId[] tasks = pipeline.getTaskProgression();
                if (tasks != null) {
                    for (TaskId task : pipeline.getTaskProgression()) {
                        %><%=h(task)%><br/><%
                    }
                }
            %>
        </td>
    </tr>
    <tr>
        <td colspan=5>&nbsp;</td>
    </tr>
<% } %>

</table>

