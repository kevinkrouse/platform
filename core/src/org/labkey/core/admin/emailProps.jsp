<%
/*
 * Copyright (c) 2008-2010 LabKey Corporation
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
<%@ page import="org.labkey.api.util.MailHelper" %>
<%@ page import="org.labkey.api.util.PageFlowUtil" %>
<%@ page import="java.util.Properties" %>
<%
    Properties emailProps = MailHelper.getSession().getProperties();
%>

<table>
    <% for(Object key : emailProps.keySet()) { %>
    <tr>
        <td class="labkey-form-label"><%=PageFlowUtil.filter(key.toString())%></td>
        <td><%=PageFlowUtil.filter(emailProps.get(key))%></td>
    </tr>
    <% } %>
</table>
