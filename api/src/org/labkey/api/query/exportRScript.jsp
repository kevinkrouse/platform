<%
/*
 * Copyright (c) 2008 LabKey Corporation
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
%><%@ page import="org.labkey.api.query.ExportRScriptModel" %><%@ page import="org.labkey.api.view.JspView" %><%@ page import="org.labkey.api.view.HttpView" %><%
    JspView<ExportRScriptModel> me = (JspView<ExportRScriptModel>) HttpView.currentView();
    ExportRScriptModel model = me.getModelBean();
    me.getViewContext().getResponse().setContentType("text/plain");
%>## R Script generated by <%=model.getInstallationName()%> on <%=model.getCreatedOn()%>
# Note that this script makes use of the LabKey Remote API for R package (Rlabkey),
# which can be obtained via CRAN using the package name "Rlabkey".
# This package also depends upon the "rjson" and "rCurl" packages.

library(Rlabkey)

# Select rows into a data frame called 'mydata'

mydata <- labkey.selectRows(baseUrl="<%=model.getBaseUrl()%>",
                            folderPath="<%=model.getFolderPath()%>",
                            schemaName="<%=model.getSchemaName()%>",
                            queryName="<%=model.getQueryName()%>",
                            viewName="<%=model.getViewName()%>",
                            colSort=<%=model.getSort()%>,
                            colFilter=<%=model.getFilters()%>)
