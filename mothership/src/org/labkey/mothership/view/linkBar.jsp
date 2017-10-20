<%@ page import="org.labkey.api.data.Container" %>
<%@ page import="org.labkey.api.data.DataRegion" %>
<%@ page import="org.labkey.api.view.ActionURL" %>
<%@ page import="org.labkey.mothership.MothershipController" %>
<%@ taglib prefix="labkey" uri="http://www.labkey.org/taglib" %>
<%@ page extends="org.labkey.api.jsp.JspBase" %>
<%
    Container c = getContainer();
%>
<div>

    <%= textLink("View Exceptions", new ActionURL(MothershipController.ShowExceptionsAction.class, c).addParameter(DataRegion.LAST_FILTER_PARAM, "true")) %>
    <%= textLink("View All Installations", new ActionURL(MothershipController.ShowInstallationsAction.class, c)) %>
    <%= textLink("Configure Mothership", new ActionURL(MothershipController.EditUpgradeMessageAction.class, c)) %>
    <%= textLink("List of Releases", new ActionURL(MothershipController.ShowReleasesAction.class, c)) %>
    <%= textLink("Reports", new ActionURL(MothershipController.ReportsAction.class, c)) %>
    <% if (getUser() != null && !getUser().isGuest()) {
            String link = "mothership-showExceptions.view?ExceptionSummary.BugNumber~isblank=&ExceptionSummary.AssignedTo/DisplayName~eq=" + getUser().getDisplayName(getUser());
        %>
        <%= textLink("My Exceptions", link)%>
    <%}%>
    <labkey:form name="jumpToErrorCode" action="<%= new ActionURL(MothershipController.JumpToErrorCodeAction.class, c) %>" layout="inline" style="display:inline-block;margin-left:20px;margin-bottom:10px;">
        <div class="input-group">
            <labkey:input name="errorCode" formGroup="false" placeholder="Find Error Code"/>
            <div class="input-group-btn">
                <%= button("Search").addClass("btn btn-default").iconCls("search").submit(true) %>
            </div>
        </div>
    </labkey:form>
</div>