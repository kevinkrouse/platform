<%
/*
 * Copyright (c) 2010-2012 LabKey Corporation
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
<%@ page import="org.labkey.api.data.Container" %>
<%@ page import="org.labkey.api.study.StudyService" %>
<%@ page import="org.labkey.api.view.ActionURL" %>
<%@ page import="org.labkey.api.view.HttpView" %>
<%@ page import="org.labkey.api.view.JspView" %>
<%@ page import="org.labkey.study.controllers.StudyController" %>
<%@ page import="org.labkey.study.view.SubjectsWebPart" %>
<%@ page import="org.labkey.study.StudySchema" %>
<%@ page import="org.labkey.api.data.DbSchema" %>
<%@ page import="org.labkey.api.data.SqlSelector" %>
<%@ page import="org.labkey.api.data.Selector" %>
<%@ page import="java.sql.SQLException" %>
<%@ page import="java.io.IOException" %>
<%@ page import="java.sql.ResultSet" %>
<%@ page import="java.util.HashMap" %>
<%@ page import="java.util.BitSet" %>
<%@ page import="org.labkey.study.model.ParticipantCategory" %>
<%@ page import="org.labkey.study.model.ParticipantGroupManager" %>
<%@ page import="org.labkey.api.security.User" %>
<%@ page import="org.labkey.study.model.ParticipantGroup" %>
<%@ page import="org.labkey.api.study.Cohort" %>
<%@ page import="org.labkey.study.model.CohortImpl" %>
<%@ page import="org.labkey.study.model.StudyManager" %>
<%@ page import="org.labkey.api.view.WebThemeManager" %>
<%@ page import="org.labkey.api.view.WebTheme" %>
<%@ page extends="org.labkey.api.jsp.JspBase" %>
<%
    JspView<SubjectsWebPart.SubjectsBean> me = (JspView<SubjectsWebPart.SubjectsBean>) HttpView.currentView();
    SubjectsWebPart.SubjectsBean bean = me.getModelBean();

    Container container  = bean.getViewContext().getContainer();
    User user            = bean.getViewContext().getUser();

    String singularNoun  = StudyService.get().getSubjectNounSingular(container);
    String pluralNoun    = StudyService.get().getSubjectNounPlural(container);
    String colName       = StudyService.get().getSubjectColumnName(container);

    ActionURL subjectUrl = new ActionURL(StudyController.ParticipantAction.class, container);
    subjectUrl.addParameter("participantId", "");
    String urlTemplate   = subjectUrl.getEncodedLocalURIString();
    DbSchema dbschema    = StudySchema.getInstance().getSchema();
    final JspWriter _out = out;

    String divId        = "participantsDiv" + getRequestScopedUID();
    String listDivId    = "listDiv" + getRequestScopedUID();
    String groupsDivId  = "groupsDiv" + getRequestScopedUID();

    String viewObject = "subjectHandler" + bean.getIndex();
    WebTheme theme    = WebThemeManager.getTheme(container);
%>
<style type="text/css">
ul.subjectlist li
{
    list-style-type: none;
}

ul.subjectlist
{
    padding-left: 0em;
    padding-right: 1em;
}

li.ptid a.highlight
{
}

li.ptid a.unhighlight
{
    color:#dddddd;
}

.participant-filter-panel .filter-description {
    font-size: smaller;
}

.participant-filter-panel div.x4-panel-header {
    background-color: #E0E6EA;
    background-image: none;
    color: black;
}

.participant-filter-panel div.x4-panel-default,
.participant-filter-panel div.x4-panel-header-default,
.participant-filter-panel div.x4-panel-body-default {
    border-color: #d3d3d3;
    box-shadow: none;
}

.participant-filter-panel span.x4-panel-header-text-default {
    color: black;
}

.report-filter-panel div.x4-panel-body-default:hover {
    overflow-y: auto;
}

.participant-filter-panel .x4-grid-row-over div:hover {
    cursor: pointer;
}

.participant-filter-panel .x4-grid-cell-inner {
    padding: 3px 3px;
}


</style>
<script type="text/javascript">
    LABKEY.requiresExt4Sandbox(true);
<% if (bean.getWide()) { %>
    LABKEY.requiresCss('study/DataViewsPanel.css');
    LABKEY.requiresScript("study/ParticipantFilterPanel.js");
<% } %>
</script>
<script type="text/javascript">
<%=viewObject%> = (function()
{
    var X = Ext4;
    var $h = X.util.Format.htmlEncode;
    var first = true;

    var _urlTemplate = '<%= urlTemplate %>';
    var _subjectColName = '<%= colName %>';
    var _singularNoun = '<%= singularNoun %>';
    var _pluralNoun = '<%= pluralNoun %>';
    var _divId = '<%= divId %>';

    // filters
    var _filterSubstring;
    var _filterSubstringMap;
    var _filterGroupMap;



    var _initialRenderComplete = false;
    var _ptids = [<%
        final String[] commas = new String[]{"\n"};
        final HashMap<String,Integer> ptidMap = new HashMap<String,Integer>();
        (new SqlSelector(dbschema, "SELECT participantId FROM study.participant WHERE container=? ORDER BY 1", container)).forEach(new Selector.ForEachBlock<ResultSet>()
        {
            public void exec(ResultSet rs) throws SQLException
            {
                String ptid = rs.getString(1);
                ptidMap.put(ptid,ptidMap.size());
                try { _out.write(commas[0]); _out.write(q(ptid)); commas[0]=",\n"; } catch (IOException x) {}
            }
        });
        %>];
    var _groups = [<%
        commas[0] = "\n";
        int index = 0;

        // cohorts
        final HashMap<Integer,Integer> cohortMap = new HashMap<Integer,Integer>();
        CohortImpl[] cohorts = new CohortImpl[0];
        if (StudyManager.getInstance().showCohorts(container, user))
            cohorts = StudyManager.getInstance().getCohorts(container, user);
        boolean hasCohorts = cohorts.length > 0;
        if (hasCohorts)
        {
            for (Cohort co : cohorts)
            {
                cohortMap.put(((CohortImpl)co).getRowId(), index);
                %><%=commas[0]%>{id:<%=((CohortImpl)co).getRowId()%>, index:<%=index%>, type:'cohort', label:<%=q(co.getLabel())%>}<%
                commas[0]=",\n";
                index++;
            }
            cohortMap.put(-1, index); // 'no cohort place holder
            %><%=commas[0]%>{id:-1, index:<%=index%>, type:'cohort', label:'{no cohort}'}<%
            commas[0]=",\n";
            index++;
        }

        // groups/categories
        final HashMap<Integer,Integer> groupMap = new HashMap<Integer,Integer>();
        ParticipantGroupManager m = ParticipantGroupManager.getInstance();
        ParticipantCategory[] categories = m.getParticipantCategories(container, user);
        boolean hasGroups = categories.length > 0;
        if (hasGroups)
        {
            for (int isShared=1 ; isShared>=0 ; isShared--)
            {
                for (ParticipantCategory cat : categories)
                {
                    if ((isShared==1) == cat.isShared())
                    {
                        for (ParticipantGroup g : m.getParticipantGroups(container, user, cat))
                        {
                            groupMap.put(g.getRowId(), index);
                            // UNDONE: groupid vs categoryid???
                            %><%=commas[0]%>{categoryId:<%=cat.getRowId()%>, id:<%=g.getRowId()%>, index:<%=index%>, shared:true, type:'participantGroup', label:<%=q(g.getLabel())%>}<%
                            commas[0]=",\n";
                            index++;
                        }
                    }
                }
            }
            groupMap.put(-1, index);
            // UNDONE: groupid vs categoryid???
            %><%=commas[0]%>{categoryId:-1, id:-1, index:<%=index%>, shared:false, type:'participantGroup', label:'{no group}'}<%
            commas[0]=",\n";
            index++;
        }
        %>];
<%
        final BitSet[] memberSets = new BitSet[index];
        for (int i=0 ; i<memberSets.length ; i++)
            memberSets[i] = new BitSet();
        if (hasCohorts)
        {
            final int nocohort = cohorts.length;
            memberSets[nocohort].flip(0,ptidMap.size());
            (new SqlSelector(dbschema, "SELECT currentcohortid, participantid FROM study.participant WHERE container=?", container)).forEach(new Selector.ForEachBlock<ResultSet>()
            {
                public void exec(ResultSet rs) throws SQLException
                {
                    Integer icohortid = cohortMap.get(rs.getInt(1));
                    Integer iptid = ptidMap.get(rs.getString(2));
                    if (null!=icohortid && null!=iptid)
                    {
                        memberSets[icohortid].set(iptid);
                        memberSets[nocohort].clear(iptid);
                    }
                }
            });
        }
        if (hasGroups)
        {
            final int nogroup = memberSets.length-1;
            memberSets[nogroup].flip(0,ptidMap.size());
            (new SqlSelector(dbschema, "SELECT groupid, participantid FROM study.participantgroupmap WHERE container=?", container)).forEach(new Selector.ForEachBlock<ResultSet>()
            {
                public void exec(ResultSet rs) throws SQLException
                {
                    Integer igroup = groupMap.get(rs.getInt(1));
                    Integer iptid = ptidMap.get(rs.getString(2));
                    if (null!=igroup && null!=iptid)
                    {
                        memberSets[igroup].set(iptid);
                        memberSets[nogroup].clear(iptid);
                    }
                }
            });
        }
%>
    var _ptidGroupMap = [<%
        String comma = "\n";
        for (BitSet bs : memberSets)
        {
            %><%=comma%>"<%
            int s = bs.length();
            for (int i=0 ; i<s; i+=16)
            {
                int u = 0;
                for (int b=0 ; b<16 ; b++)
                    u |= (bs.get(i+b)?1:0) << b;
                writeUnicodeChar(_out,u);
            }
            %>"<%
            comma = ",\n";
        }
    %>];
    <% int ptidsPerCol = Math.min(Math.max(20,groupMap.size()), Math.max(6, ptidMap .size()/6));%>
    <% if (!bean.getWide()) {
        ptidsPerCol = ptidMap.size()/2;
    } %>
    var _ptidPerCol = <%=ptidsPerCol%>;

    var h, i, ptid;
    for (i=0 ; i<_ptids.length ; i++)
    {
        ptid = _ptids[i];
        h = $h(ptid);
        _ptids[i] = {index:i, ptid:ptid, html:(h==ptid?ptid:h)};
    }

    function test(s, p)
    {
        if (p<0 || p/16 >= s.length)
            return false;
        var i = (typeof s == "string") ? s.charCodeAt(p/16) : s[p/16];
        return i >> (p%16) & 1;
    }

    function testGroupPtid(g,p)
    {
        if (g<0||g>=_ptidGroupMap.length||p<0)
            return false;
        var s=_ptidGroupMap[g];
        return test(s,p);
    }

    var _highlightGroup = -1;
    var _highlightGroupTask = null;

    function highlightPtidsInGroup(index)
    {
        if (index == _highlightGroup) return;
        _highlightGroup = index;
        if (null == _highlightGroupTask)
            _highlightGroupTask = new X.util.DelayedTask(_highlightPtidsInGroup);
        _highlightGroupTask.delay(50);
    }

    function _highlightPtidsInGroup()
    {
        var list = X.DomQuery.select("LI.ptid",_divId);
        <%-- note removeClass() and addClass() are pretty expensive when used on a lot of elements --%>
        X.Array.each(list, function(li){
            var a = li.firstChild;
            if (_highlightGroup == -1)
                a.className = '';
            else if (testGroupPtid(_highlightGroup,parseInt(li.attributes.index.value)))
                a.className = 'highlight';
            else
                a.className = 'unhighlight';
        });
    }

    var _highlightPtid = -1;
    var _highlightPtidTask = null;

    function highlightGroupsForPart(index)
    {
        if (index == _highlightPtid) return;
        _highlightPtid = index;
        if (null == _highlightPtidTask)
            _highlightPtidTask = new X.util.DelayedTask(_highlightGroupsForPart);
        _highlightPtidTask.delay(50);
    }

    function _highlightGroupsForPart()
    {
        var p = _highlightPtid;
        var list = X.DomQuery.select("DIV.group",'<%=groupsDivId%>');
        for (var i=0 ; i<list.length ; i++)
        {
            var div = X.get(list[i]);
            div.removeCls(['highlight', 'unhighlight']);
            if (p == -1) continue;
            g = parseInt(div.dom.attributes.index.value);
            var inGroup = testGroupPtid(g,p);
            if (inGroup)
                div.addCls('highlight');
            else
                div.addCls('unhighlight');
        }
    }

    function filter(selected)
    {
        X.Ajax.request({
            url      : LABKEY.ActionURL.buildURL('participant-group', 'getSubjectsFromGroups.api'),
            method   : 'POST',
            jsonData : X.encode({
                groups : selected
            }),
            success  : function(response)
            {
                var json = X.decode(response.responseText);
                _filterGroupMap = {};
                for (var i=0; i < json.subjects.length; i++)
                    _filterGroupMap[json.subjects[i]] = true;
                renderSubjects();
            },
            failure  : function(response){
                X.Msg.alert('Failure', X.decode(response.responseText));
            },
            scope : this
        });
    }

    function renderGroups()
    {
        var filterTask = new X.util.DelayedTask(filter);

        <% if (bean.getWide()) { %>
        var ptidPanel = X.create('LABKEY.study.ParticipantFilterPanel',
        {
            renderTo  : X.get('<%=groupsDivId%>'),
            title     : 'Show',
            border    : true,
            width     : 260,
            height    : 400,
            overCls   : 'iScroll',
            layout    : 'fit',
            bodyStyle : 'padding: 8px',
            listeners : {
                itemmouseenter : function(v,r,item,idx)
                {
                    var g=-1;
                    for (var i=0 ; i<_groups.length ; i++)
                        if (_groups[i].id==r.data.id && _groups[i].type==r.data.type)
                            g = i;
                    highlightPtidsInGroup(g);
                },
                itemmouseleave : function()
                {
                    highlightPtidsInGroup(-1);
                },
                selectionchange : function(model, selected)
                {
                    var json = [], filters = ptidPanel.getFilterPanel().getSelection(true);
                    for (var f=0; f < filters.length; f++) {
                        json.push(filters[f].data);
                    }
                    filterTask.delay(400, null, null, [json]);
                }
            }
        });

        Ext4.create('Ext.resizer.Resizer', {
            target: ptidPanel,
            handles: 'e',
            minWidth: 260
        });
        <% } %>

        function scrollHorizontal(evt) {
            X.get(<%=q(listDivId)%>).scroll((evt.getWheelDeltas().y > 0) ? 'r' : 'l', 20);
            evt.stopEvent();
        }

        X.get(<%=q(listDivId)%>).on(X.supports.MouseWheel ? 'mousewheel' : 'DOMMouseScroll', scrollHorizontal);
    }


    function renderSubjects()
    {
        if (_ptids.length == 0 && first)
        {
            document.getElementById(_divId).innerHTML = 'No ' + _pluralNoun.toLowerCase() + " were found in this study.  " +
                    _singularNoun + " IDs will appear here after specimens or datasets are imported.";
            first = false;
            return;
        }
        first = false;

        var html = [];
        html.push('<table><tr><td valign="top"><ul class="subjectlist">');
        var count = 0;
        for (var subjectIndex = 0; subjectIndex < _ptids.length; subjectIndex++)
        {
            var p = _ptids[subjectIndex];
            if ((!_filterSubstringMap || test(_filterSubstringMap,subjectIndex)) && (!_filterGroupMap || _filterGroupMap[p.ptid]))
            {
                if (++count > 1 && count % _ptidPerCol == 1)
                    html.push('</ul></td><td valign="top"><ul class="subjectlist">');
                html.push('<li class="ptid" index=' + subjectIndex + ' ptid="' + p.html + '" style="white-space:nowrap;"><a href="' + _urlTemplate + p.html + '">' + (LABKEY.demoMode?LABKEY.id(p.ptid):p.html) + '</a></li>\n');
            }
        }

        html.push('</ul></td></tr></table>');
        html.push('<div style="clear:both;">');
        var message = "";
        if (count > 0)
        {
            if (_filterSubstringMap || _filterGroupMap)
                message = 'Found ' + count + ' ' + (count > 1 ? _pluralNoun.toLowerCase() : _singularNoun.toLowerCase()) + ' of ' + _ptids.length + '.';
            else
                message = 'Showing all ' + count + ' ' + (count > 1 ? _pluralNoun.toLowerCase() : _singularNoun.toLowerCase()) + '.';
        }
        else {
            if (_filterSubstring && _filterSubstring.length > 0)
                message = 'No ' + _singularNoun.toLowerCase() + ' IDs contain \"' + _filterSubstring + '\".';
            else
                message = 'No matching ' + _pluralNoun + '.';
        }
        html.push('</div>');

        X.get(<%=q(listDivId)%>).update(html.join(''));
        X.get(<%=q(divId + ".status")%>).update(message);
    }


    function filterPtidContains(substring)
    {
        _filterSubstring = substring;
        if (!substring)
        {
            _filterSubstringMap = null;
        }
        else
        {
            var a = new Array(Math.floor((_ptids.length+15)/16));
            for (var i=0 ; i<_ptids.length ; i++)
            {
                var ptid = _ptids[i].ptid;
                if (ptid.indexOf(_filterSubstring) >= 0)
                    a[i/16] |= 1 << (i%16);
            }
            _filterSubstringMap = a;
        }
        renderSubjects();
    }


    function generateToolTip(p)
    {
        var part = _ptids[p];
        var html = ["<div>" + part.html + "</div>"];
        for (var g=0 ; g<_groups.length ; g++)
        {
            if (_groups[g].id != -1 && testGroupPtid(g,p))
                html.push('<div style="white-space:nowrap;">' + $h(_groups[g].label) + '</div>');
        }
        return html.join("");
    }


    function render()
    {
        doAdjustSize(); // get close
        renderGroups();
        renderSubjects();

        X.create('Ext.tip.ToolTip',
        {
            target     : <%=q(listDivId)%>,
            delegate   : "LI.ptid",
            trackMouse : true,
            listeners  :
            {
                beforeshow: function(tip)
                {
                    var dom = tip.triggerElement || tip.target;
                    var indexAttr = dom.attributes.index || dom.parentNode.attributes.index;
                    if (!X.isDefined(indexAttr))
                        return false;
                    var html = generateToolTip(parseInt(indexAttr.value));
                    tip.update(html);
                }
            }
        });

        /* filter events */

        var inp = X.get('<%=divId%>.filter');
        inp.on('keyup', function(a){filterPtidContains(a.target.value);}, null, {buffer:200});
        inp.on('change', function(a){filterPtidContains(a.target.value);}, null, {buffer:200});

        /* ptids events */

        var ptidDiv = X.get(<%=q(listDivId)%>);
        ptidDiv.on('mouseover', function(e,dom)
        {
            var indexAttr = dom.attributes.index || dom.parentNode.attributes.index;
            if (X.isDefined(indexAttr))
                highlightGroupsForPart(parseInt(indexAttr.value));
        });
        ptidDiv.on('mouseout', function(e,dom)
        {
            highlightGroupsForPart(-1);
        });

        /* groups events * /

        var groupsDiv = X.get(<%=q(groupsDivId)%>);
        groupsDiv.on('mouseover', function(e,dom)
        {
            var indexAttr = dom.attributes.index || dom.parentNode.attributes.index;
            if (X.isDefined(indexAttr))
                highlightPtidsInGroup(parseInt(indexAttr.value));
        });
        groupsDiv.on('mouseout', function(e,dom)
        {
            highlightPtidsInGroup(-1);
        });
        groupsDiv.on('click', function(e,dom)
        {
            var indexAttr = dom.attributes.index || dom.parentNode.attributes.index;
            if (X.isDefined(indexAttr))
                filterGroup(parseInt(indexAttr.value));
        }); */

        // we don't want ptidDiv to change height as it filters, so set height explicitly after first layout
        ptidDiv.setHeight(ptidDiv.getHeight());

        X.EventManager.onWindowResize(doAdjustSize);
        doAdjustSize();
    }

    function doAdjustSize()
    {
        // CONSIDER: register for window resize
        var listDiv = X.get(<%=q(listDivId)%>);
        if (!listDiv) return;
        var rightAreaWidth = 15;
        try {rightAreaWidth = X.fly(X.select(".labkey-side-panel").elements[0]).getWidth();} catch (x){}
        var padding = 60;
        var viewWidth = X.getBody().getViewSize().width;
        var right = viewWidth - padding - rightAreaWidth;
        var x = listDiv.getXY()[0];
        var width = Math.max(<%=bean.getWide() ? 400 : 200%>, (right-x));
        listDiv.setWidth(width);
    }

    return { render : render };
})();


Ext4.onReady(<%=viewObject%>.render, <%=viewObject%>);
</script>

<div style="">
    <table id="<%= divId %>">
        <tr>
            <% if (bean.getWide()) { %>
            <td style="margin: 5px;" valign=top>
                <div id="<%=groupsDivId%>"></div>
            </td>
            <% } %>
            <td style="margin: 5px;" valign=top class="iScroll">
                <table><tr>
                    <td><div style="" >Filter&nbsp;<input id="<%=divId%>.filter" type="text" size="15" style="border:solid 1px #<%=theme.getWebPartColor()%>"></div></td>
                    <%--<td>&nbsp;<%if (hasCohorts){%><input type=checkbox>&nbsp;by&nbsp;cohort (NYI)<%}%></td>--%>
                </tr></table>
                <hr style="height:1px; border:0; background-color:#<%=theme.getWebPartColor()%>; color:#<%=theme.getWebPartColor()%>;">
                <div><span id="<%=divId%>.status">Loading...</span></div>
                <div style="overflow-x:auto; min-height:<%=Math.round(1.2*(ptidsPerCol+3))%>em;" id="<%= listDivId %>"></div>
            </td>
        </tr>
    </table>
</div>


<%!
void writeUnicodeChar(JspWriter out, int i) throws IOException
{
    if (i==0)
        out.write("\\");
    else if (i<16)
        out.write("\\x0");
    else if (i<256)
        out.write("\\x");
    else if (i<4096)
        out.write("\\u0");
    else
        out.write("\\u");
    out.write(Integer.toHexString(i));
}
%>
