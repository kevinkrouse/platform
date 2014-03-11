<%
/*
 * Copyright (c) 2009-2013 LabKey Corporation
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
<%@ page import="org.labkey.api.util.PageFlowUtil" %>
<%@ page import="org.labkey.api.query.QueryView" %>
<%@ page import="org.labkey.api.view.HttpView" %>
<%@ page import="org.labkey.api.util.GUID" %>
<%@ page import="org.json.JSONObject" %>
<%@ page extends="org.labkey.api.jsp.JspBase" %>
<%
    QueryView.ExcelExportOptionsBean model = (QueryView.ExcelExportOptionsBean) HttpView.currentModel();
    String guid = GUID.makeGUID();
    String xlsxGUID = "xlsx_" + guid;
    String xlsGUID = "xls_" + guid;
    String iqyGUID = "iqy_" + guid;
    String exportSelectedId = "exportSelected_" + guid;
    String exportButtonId = "export_" + guid;

    boolean hasSelected = model.hasSelected(getViewContext());
%>
<table class="labkey-export-tab-contents">
    <tr>
        <td valign="center"><input type="radio" id="<%=h(xlsxGUID)%>" name="excelExportType" checked/></td>
        <td valign="center"><label for="<%=h(xlsxGUID)%>">Excel 2007 File (.xlsx)</label> <span style="font-size: smaller">Maximum 1,048,576 rows and 16,384 columns.</span></td>
    </tr>
    <tr>
        <td valign="center"><input type="radio" id="<%=h(xlsGUID)%>" name="excelExportType" /></td>
        <td valign="center"><label for="<%=h(xlsGUID)%>">Excel 97 File (.xls)</label> <span style="font-size: smaller">Maximum 65,536 rows and 256 columns.</span></td>
    </tr>
    <% if (model.getIqyURL() != null) { %>
        <tr>
            <td valign="center"><input type="radio" id="<%=h(iqyGUID)%>" name="excelExportType"/></td>
            <td valign="center"><label for="<%=h(iqyGUID)%>">Refreshable Web Query (.iqy)</label></td>
        </tr>
    <% } %>
    <tr><td colspan="2"></td></tr>
    <tr>
        <td valign="center"><input type="checkbox" id="<%=h(exportSelectedId)%>" value="exportSelected" <%=checked(hasSelected)%> <%=disabled(!hasSelected)%>/></td>
        <td valign="center"><label class="<%=text(hasSelected ? "" : "labkey-disabled")%>" id="<%=h(exportSelectedId + "_label")%>" for="<%=h(exportSelectedId)%>">Export selected rows</label></td>
    </tr>
    <tr>
        <td colspan="2">
            <%= button("Export to Excel").id(exportButtonId) %>
        </td>
    </tr>
</table>

<script type="text/javascript">
Ext.onReady(function () {
    var xlsExportEl = document.getElementById("<%=h(xlsGUID)%>");
    var xlsxExportEl = document.getElementById("<%=h(xlsxGUID)%>");
    var iqyExportEl = document.getElementById("<%=h(iqyGUID)%>");

    var exportSelectedEl = document.getElementById("<%=h(exportSelectedId)%>");
    var exportSelectedLabelEl = document.getElementById("<%=h(exportSelectedId + "_label")%>");

    <%-- CONSIDER: Add a universal export function to LABKEY.DataRegion clientapi --%>
    function doExcelExport()
    {
        var dr = LABKEY.DataRegions[<%=PageFlowUtil.jsString(model.getDataRegionName())%>];
        var exportUrl;
        var exportParams;

        if (xlsxExportEl.checked) {
            exportUrl = <%=PageFlowUtil.jsString(model.getXlsxURL().getFullParsedPath().toString())%>;
            exportParams = <%=text( new JSONObject(model.getXlsxURL().getParameterMap()).toString(2) )%>;
        }
        else if (xlsExportEl.checked) {
            exportUrl = <%=PageFlowUtil.jsString(model.getXlsURL().getFullParsedPath().toString())%>;
            exportParams = <%=text( new JSONObject(model.getXlsURL().getParameterMap()).toString(2) )%>;
        <% if (model.getIqyURL() != null) { %>
        } else if (iqyExportEl.checked) {
            <%-- Excel Web Query doesn't work with POSTs, so always do it as a GET.  It also is not supported for all tables. --%>
            window.location = <%=PageFlowUtil.jsString(model.getIqyURL().toString())%>;
            return false;
        <% } %>
        }

        if (!exportSelectedEl.disabled && exportSelectedEl.checked) {
            // Replace 'showRows=ALL' parameter with 'showRows=SELECTED'
            exportParams['<%=text(QueryView.DATAREGIONNAME_DEFAULT)%>.showRows'] = 'SELECTED';
            exportParams['<%=text(QueryView.DATAREGIONNAME_DEFAULT)%>.selectionKey'] = dr.selectionKey;
        }

        dr.addMessage({
            html: '<div class=\"labkey-message\"><strong>Excel export started.</strong></div>',
            part: 'excelExport', hideButtonPanel: true, duration:5000
        });

        <%-- Sometimes the GET URL gets too long, so use a POST instead. We have to create a separate <form> since we might --%>
        <%-- already be inside a form for the DataRegion itself. --%>
        var newForm = document.createElement('form');
        LABKEY.Ajax.request({
            url: exportUrl,
            method: 'POST',
            form: newForm,
            isUpload: true,
            params: exportParams,
            callback: function (options, success, response) {
                if (!success) {
                    dr.showErrorMessage("Error exporting to Excel.");
                }
            }
        });

        return false;
    }

    function enableExportSelected()
    {
        if (exportSelectedEl.disabled) {
            exportSelectedEl.checked = true;
            exportSelectedEl.disabled = false;
            exportSelectedLabelEl.className = "";
        }
    }

    // TODO: disable exportSelectedEl when iqy is chosen
    function disableExportSelected()
    {
        exportSelectedEl.checked = false;
        exportSelectedEl.disabled = true;
        exportSelectedLabelEl.className = "labkey-disabled";
    }

    var exportButtonEl = document.getElementById("<%=h(exportButtonId)%>");
    if (exportButtonEl.addEventListener)
        exportButtonEl.addEventListener('click', doExcelExport, false);
    else if (exportButtonEl.attachEvent)
        exportButtonEl.addEventListener('onclick', doExcelExport);

    Ext.ComponentMgr.onAvailable(<%=PageFlowUtil.jsString(model.getDataRegionName())%>, function (dr) {
        dr.on('selectchange', function (dr, selectedCount) {
            if (selectedCount > 0) {
                enableExportSelected();
            } else {
                disableExportSelected();
            }
        });
    });
});
</script>

