<%
/*
 * Copyright (c) 2009 LabKey Corporation
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
<%@ page import="org.apache.commons.lang.StringUtils" %>
<%@ page import="org.labkey.api.attachments.AttachmentDirectory" %>
<%@ page import="org.labkey.api.data.Container" %>
<%@ page import="org.labkey.api.files.FileContentService" %>
<%@ page import="org.labkey.api.files.FileUrls" %>
<%@ page import="org.labkey.api.files.view.FilesWebPart" %>
<%@ page import="org.labkey.api.pipeline.PipelineUrls" %>
<%@ page import="org.labkey.api.security.permissions.AdminPermission" %>
<%@ page import="org.labkey.api.security.permissions.InsertPermission" %>
<%@ page import="org.labkey.api.services.ServiceRegistry" %>
<%@ page import="org.labkey.api.util.PageFlowUtil" %>
<%@ page import="org.labkey.api.view.ActionURL" %>
<%@ page import="org.labkey.api.view.HttpView" %>
<%@ page import="org.labkey.api.view.ViewContext" %>
<%@ page extends="org.labkey.api.jsp.JspBase" %>

<script type="text/javascript">
    LABKEY.requiresClientAPI(true);
    LABKEY.requiresScript("applet.js");
    LABKEY.requiresScript("fileBrowser.js");
    LABKEY.requiresScript("FileUploadField.js");
    LABKEY.requiresScript("ActionsAdmin.js");
</script>

<%
    ViewContext context = HttpView.currentContext();
    FilesWebPart.FilesForm bean = (FilesWebPart.FilesForm)HttpView.currentModel();
    FilesWebPart me = (FilesWebPart) HttpView.currentView();

    AttachmentDirectory root = bean.getRoot();
    Container c = context.getContainer();

    // prefix is where we what the tree rooted
    // TODO: applet and fileBrowser could use more consistent configuration parameters
    //String rootName = c.getName();
    //String webdavPrefix = context.getContextPath() + "/" + WebdavService.getServletPath();

    //String rootPath = webdavPrefix + c.getEncodedPath();

    //if (bean.getDavLabel() != null)
    //    rootPath = webdavPrefix + c.getEncodedPath() + bean.getDavLabel();
//    String rootPath = webdavPrefix + c.getEncodedPath() + "%40myfiles/";
    //if (!rootPath.endsWith("/"))
    //    rootPath += "/";

    String startDir = "/";
//    if (me.getFileSet() != null)
//        startDir += "/@files/" + me.getFileSet();
    //String baseUrl = request.getScheme() + "://" + request.getServerName() + ":" + request.getServerPort() + rootPath;
%>


<div class="extContainer">
    <table>
        <tr><td><div id="toolbar"></div></td></tr>
        <tr><td><div id="files"></div></td></tr>
    </table>
</div>

<script type="text/javascript">
Ext.BLANK_IMAGE_URL = LABKEY.contextPath + "/_.gif";
Ext.QuickTips.init();

var autoResize = <%=bean.isAutoResize()%>;
var fileBrowser = null;
var fileSystem = null;
var actionsURL = <%=PageFlowUtil.jsString(PageFlowUtil.urlProvider(PipelineUrls.class).urlActions(context.getContainer()).getLocalURIString() + "path=")%>;
var buttonActions = [];

<%
    for (FilesWebPart.FilesForm.actions action  : bean.getButtonConfig())
    {
%>
        buttonActions.push('<%=action.name()%>');
<%
    }
%>
function renderBrowser(rootPath, dir)
{
    var configureAction = new Ext.Action({text: 'Configure', handler: function()
    {
        window.location = <%=PageFlowUtil.jsString(PageFlowUtil.urlProvider(FileUrls.class).urlShowAdmin(c).getLocalURIString())%>;
    }});

    var dropAction = new Ext.Action({text: 'Upload multiple files', scope:this, disabled:false, handler: function()
    {
        var dropUrl = <%=PageFlowUtil.jsString((new ActionURL("ftp","drop",c)).getEncodedLocalURIString() + (null == me.getFileSet() ? "" : "fileSetName=" + PageFlowUtil.encode(root.getLabel())))%>;
        window.open(dropUrl, '_blank', 'height=600,width=1000,resizable=yes');
    }});

    // TODO even better just refresh/rerender the browser not the whole page
    var combo = new Ext.form.ComboBox({
        name: 'filesetComboBox',
        store: fileSets,
        typeAhead: true,
        mode: 'local',
        triggerAction: 'all',
        selectOnFocus:true,
        width:135,
        value:selectedValue
    });
    combo.on("select",function(){
        var value = combo.getValue();
        if (value.indexOf("showAdmin.view") != -1)
            window.location=value;
        else
            fileBrowser.changeDirectory(value);
    });

    /**
     * A version of a tab panel that doesn't render the tab strip, used to swap
     * in panels programmatically
     * @param w
     * @param h
     */
    TinyTabPanel = Ext.extend(Ext.TabPanel, {

        adjustBodyWidth : function(w){
            if(this.header){
                this.header.setWidth(w);
                this.header.setHeight(1);
            }
            if(this.footer){
                this.footer.setWidth(w);
                this.header.setHeight(1);
            }
            return w;
        }
    });

    // subclass the filebrowser panel
    FilesWebPartPanel = Ext.extend(LABKEY.FileBrowser, {

        // collapsible tab panel used to display dialog-like content
        collapsibleTabPanel : undefined,

        // import data tab
        importDataTab : undefined,

        actionsConnection : new Ext.data.Connection({autoAbort:true}),

        // pipeline actions
        pipelineActions : undefined,

        // file upload form field
        fileInputField : undefined,

        // toolbar buttons
        toolbarButtons : [],
        toolbar : undefined,

        constructor : function(config)
        {
            FilesWebPartPanel.superclass.constructor.call(this, config);
        },

        initComponent : function()
        {
            FilesWebPartPanel.superclass.initComponent.call(this);
            this.createPanels();

            this.on(BROWSER_EVENTS.directorychange,function(record){this.onDirectoryChange(record);}, this);
            this.grid.getSelectionModel().on(BROWSER_EVENTS.selectionchange,function(record){this.onSelectionChange(record);}, this);
        },

        getTbarConfig : function()
        {
            // no toolbar on the filebrowser grid, we'll display our own so we can insert a ribbon panel
            return [];
        },

        uploadFile : function(fb, v)
        {
            if (this.currentDirectory)
            {
                var form = this.collapsibleTabPanel.getActiveTab().getForm();
                var path = this.fileInputField.getValue();
                var i = Math.max(path.lastIndexOf('/'), path.lastIndexOf('\\'));
                var name = path.substring(i+1);
                var target = this.fileSystem.concatPaths(this.currentDirectory.data.path,name);
                var file = this.fileSystem.recordFromCache(target);
                if (file)
                {
                    alert('file already exists on server: ' + name);
                }
                else
                {
                    var options = {method:'POST', url:this.currentDirectory.data.uri, record:this.currentDirectory, name:this.fileInputField.getValue()};
                    // set errorReader, so that handleResponse() doesn't try to eval() the XML response
                    // assume that we've got a WebdavFileSystem
                    form.errorReader = this.fileSystem.transferReader;
                    form.doAction(new Ext.form.Action.Submit(form, options));
                    Ext.getBody().dom.style.cursor = "wait";
                }
            }
        },

        uploadSuccess : function(f, action)
        {
            this.fileInputField.reset();
            Ext.getBody().dom.style.cursor = "pointer";
            console.log("upload actioncomplete");
            console.log(action);
            var options = action.options;
            // UNDONE: update data store directly
            this.toggleTabPanel();
            this.refreshDirectory();
            this.selectFile(this.fileSystem.concatPaths(options.record.data.path, options.name));
        },

        uploadFailed : function(f, action)
        {
            this.fileInputField.reset();
            Ext.getBody().dom.style.cursor = "pointer";
            console.log("upload actionfailed");
            console.log(action);
            this.refreshDirectory();
        },

        /**
         * Initialize additional components
         */
        createPanels : function()
        {
            this.actions.upload = new Ext.Action({
                text: 'Upload',
                iconCls: 'iconUpload',
                tooltip: 'Upload files or folders from your local machine to the server',
                listeners: {click:function(button, event) {this.toggleTabPanel('uploadFileTab');}, scope:this}
            });

            this.actions.importData = new Ext.Action({
                text: 'Import Data',
                iconCls: 'iconDBCommit',
                tooltip: 'Import data from files into the database, or analyze data files',
                listeners: {click:function(button, event) {this.toggleTabPanel('importDataTab');}, scope:this}
            });

            this.actions.customize = new Ext.Action({
                text: 'Admin',
                iconCls: 'iconConfigure',
                tooltip: 'Configure the buttons shown on the toolbar',
                listeners: {click:function(button, event) {this.onAdmin(button);}, scope:this}
            });

            this.toolbar = new Ext.Panel({
                id: 'toolbarPanel',
                renderTo: 'toolbar'
            });
        },

        /**
         * Override base class to add components to the file browser
         * @override
         */
        getItems : function()
        {
            var items = FilesWebPartPanel.superclass.getItems.call(this);

            this.importDataTab = new Ext.Panel({
                id: 'importDataTab'
            });

            this.fileInputField = new Ext.form.FileUploadField(
            {
                id: this.id ? this.id + 'Upload' : 'fileUpload',
                buttonText: "Browse...",
                fieldLabel: 'Choose a file'
            });

            var uploadPanel = new Ext.FormPanel({
                id: 'uploadFileTab',
                formId : this.id ? this.id + 'Upload-form' : 'fileUpload-form',
                method : 'POST',
                fileUpload: true,
                enctype:'multipart/form-data',
                border:false,
                bodyStyle : 'background-color:#f0f0f0; padding:10px;',
                items: [
                    this.fileInputField,
                    {xtype: 'textfield', fieldLabel: 'Description', width: 350}
                ],
                buttons:[
                    new Ext.Button(this.actions.uploadTool),
                    {text: 'Submit', handler:this.uploadFile, scope:this},
                    {text: 'Cancel', listeners:{click:function(button, event) {this.toggleTabPanel('uploadFileTab');}, scope:this}}
                ],
                listeners: {
                    "actioncomplete" : {fn: this.uploadSuccess, scope: this},
                    "actionfailed" : {fn: this.uploadFailed, scope: this}
                }
            });
           // uploadPanel.on('render', function(c){c.doLayout();}, this);
            //this.on(BROWSER_EVENTS.directorychange,function(record){this.onDirectoryChange(record);}, this);

            this.collapsibleTabPanel = new TinyTabPanel({
                region: 'north',
                collapseMode: 'mini',
                height: 90,
                header: false,
                margins:'1 1 1 1',
                bodyStyle: 'background-color:#f0f0f0;',
                cmargins:'1 1 1 1',
                collapsible: true,
                collapsed: true,
                hideCollapseTool: true,
                activeTab: 'uploadFileTab',
                deferredRender: false,
                items: [
                    uploadPanel,
                    this.importDataTab,
                ]});

            items.push(this.collapsibleTabPanel);
            return items;
        },

        toggleTabPanel : function(tabId)
        {
            if (!tabId)
                this.collapsibleTabPanel.collapse();
            
            if (this.collapsibleTabPanel.isVisible())
            {
                var activeTab = this.collapsibleTabPanel.getActiveTab();

                if (activeTab && activeTab.getId() == tabId)
                    this.collapsibleTabPanel.collapse();
                else
                    this.collapsibleTabPanel.setActiveTab(tabId);
            }
            else
            {
                this.collapsibleTabPanel.setActiveTab(tabId);
                this.collapsibleTabPanel.expand();
            }
        },

        createGrid : function()
        {
            // mild convolution to pass fileSystem to the _attachPreview function
            var iconRenderer = renderIcon.createDelegate(null,_attachPreview.createDelegate(this.fileSystem,[],true),true);
            var sm = new Ext.grid.CheckboxSelectionModel();

            var grid = new Ext.grid.GridPanel(
            {
                store: this.store,
                border:false,
                selModel : sm,
                loadMask:{msg:"Loading, please wait..."},
                columns: [
                    sm,
                    {header: "", width:20, dataIndex: 'iconHref', sortable: false, hidden:false, renderer:iconRenderer},
                    {header: "Name", width: 250, dataIndex: 'name', sortable: true, hidden:false, renderer:Ext.util.Format.htmlEncode},
                    {header: "Modified", width: 150, dataIndex: 'modified', sortable: true, hidden:false, renderer:renderDateTime},
                    {header: "Size", width: 80, dataIndex: 'size', sortable: true, hidden:false, align:'right', renderer:renderFileSize},
                    {header: "Usages", width: 150, dataIndex: 'actionHref', sortable: true, hidden:false, renderer:renderUsage}
                ]
            });
            // hack to get the file input field to size correctly
            grid.on('render', function(c){this.fileInputField.setSize(350);}, this);
            return grid;
        },

        onDirectoryChange : function(record)
        {
            var path = record.data.path;
            if (startsWith(path,"/"))
                path = path.substring(1);
            var requestid = this.actionsConnection.request({
                autoAbort:true,
                url:actionsURL + encodeURIComponent(path),
                method:'GET',
                disableCaching:false,
                success : this.updatePipelineActions,
                scope: this
            });
        },

        updatePipelineActions : function(response)
        {
            var o = eval('var $=' + response.responseText + ';$;');
            var actions = o.success ? o.actions : [];

            var toolbarActions = [];
            var importActions = [];

            if (actions && actions.length)
            {
                for (var i=0; i < actions.length; i++)
                {
                    var action = actions[i];
                    if (action.links.items != undefined)
                    {
                        for (var j=0; j < action.links.items.length; j++)
                        {
                            var item = action.links.items[j];
                            if (item.text && item.href && item.display != 'disabled')
                            {
                                if (item.display == 'toolbar')
                                    this.addActionItem(toolbarActions, action, item);
                                else
                                    this.addActionItem(importActions, action, item);
                            }
                        }
                    }
                    else if (action.links.text && action.links.href && action.links.display != 'disabled')
                    {
                        if (action.links.display == 'toolbar')
                            this.addActionItem(toolbarActions, action);
                        else
                            this.addActionItem(importActions, action);
                    }
                }
            }

            this.displayPipelineActions(toolbarActions, importActions)
        },

        /**
         * Helper to add pipeline action items to an object array
         */
        addActionItem : function(list, action, item)
        {
            var name = action.links.text;

            // multiple items per type (menu dropdown)
            if (item)
            {
                var actionObject = list[action.links.text];
                if (!actionObject)
                {
                    actionObject = {text: name, multiSelect: action.multiSelect, files: action.files, menu: {cls: 'extContainer', items: []}};
                    list[name] = actionObject;
                }
                actionObject.menu.items.push({
                    text: item.text,
                    files: action.files,
                    multiSelect: item.multiSelect,
                    itemHref: item.href,
                    display: item.display,
                    listeners: {click: this.executePipelineAction, scope: this}});
            }
            else
            {
                list[name] = {text:name, multiSelect: action.multiSelect, files: action.files, itemHref: action.links.href, listeners: {click: this.executePipelineAction, scope: this}};
            }
        },

        displayPipelineActions : function(toolbarActions, importActions)
        {
            // delete the actions container
            if (this.importDataTab && this.importDataTab.items)
                this.importDataTab.remove('importDataPanel');

            if (this.toolbar && this.toolbar.items)
                this.toolbar.remove('toolbarPanelToolbar');

            var tbarButtons = [];
            var importDataButtons = [];

            // first add the standard buttons
            if (this.buttonCfg && this.buttonCfg.length)
            {
                for (var i=0; i < this.buttonCfg.length; i++)
                {
                    var item = this.buttonCfg[i];
                    if (typeof item == "string" && typeof this.actions[item] == "object")
                        tbarButtons.push(new Ext.Button(this.actions[item]));
                    else
                        tbarButtons.push(item);
                }
            }

            // now add the configurable pipleline actions
            this.pipelineActions = [];

            for (action in toolbarActions)
            {
                var a = toolbarActions[action];
                if (a.text)
                {
                    var tbarAction = new Ext.Action(a);
                    tbarButtons.push(new Ext.Button(tbarAction));
                    this.pipelineActions.push(tbarAction);
                }
            }

            for (action in importActions)
            {
                var a = importActions[action];
                if (a.text)
                {
                    var importAction = new Ext.Action(a);
                    importDataButtons.push(importAction);
                    this.pipelineActions.push(importAction);
                }
            }

            // add the appropriate import actions to the import data tabpanel
            var importData = new Ext.Panel({
                id: 'importDataPanel',
                bodyStyle : 'background-color:#f0f0f0; padding:10px;',
                items: new Ext.Toolbar({items:importDataButtons}),
                buttons:[
                    {text: 'Cancel', listeners:{click:function(button, event) {this.toggleTabPanel('importDataTab');}, scope:this}}
                ],
                buttonAlign: 'center'
            });
            this.importDataTab.add(importData);
            this.importDataTab.doLayout();

            var toolbar = new Ext.Toolbar({
                id: 'toolbarPanelToolbar',
                //renderTo: 'toolbar',
                border: false,
                items: tbarButtons
            });
            //this.toolbar.render('toolbar');
            this.toolbar.add(toolbar);
            this.toolbar.doLayout();
        },

        // selection change handler
        onSelectionChange : function(record)
        {
            if (this.pipelineActions)
            {
                var selections = this.grid.selModel.getSelections();
                if (!selections.length && this.grid.store.data)
                {
                    selections = this.grid.store.data.items;
                }

                if (selections.length)
                {
                    var selectionMap = {};

                    for (var i=0; i < selections.length; i++)
                        selectionMap[selections[i].data.name] = true;

                    for (var i=0; i <this.pipelineActions.length; i++)
                    {
                        var action = this.pipelineActions[i];
                        if (action.initialConfig.files && action.initialConfig.files.length)
                        {
                            var selectionCount = 0;
                            for (var j=0; j <action.initialConfig.files.length; j++)
                            {
                                if (action.initialConfig.files[j] in selectionMap)
                                {
                                    selectionCount++;
                                }
                            }
                            if (action.initialConfig.multiSelect)
                            {
                                selectionCount > 0 ? action.enable() : action.disable();
                            }
                            else
                            {
                                selectionCount == 1 ? action.enable() : action.disable();
                            }
                        }
                    }
                }
            }
        },

        executePipelineAction : function(item, e)
        {
            var selections = this.grid.selModel.getSelections();

            // if there are no selections, treat as if all are selected
            if (selections.length == 0)
            {
                var selections = [];
                var store = this.grid.getStore();

                for (var i=0; i <store.getCount(); i++)
                {
                    var record = store.getAt(i);
                    if (record.data.file)
                        selections.push(record);
                }
            }

            if (item && item.itemHref)
            {
                if (selections.length == 0)
                {
                    Ext.Msg.alert("Rename Views", "There are no views selected");
                    return false;
                }

                var form = document.createElement("form");
                form.setAttribute("method", "post");
                form.setAttribute("action", item.itemHref);

                for (var i=0; i < selections.length; i++)
                {
                    for (var j = 0; j < item.files.length; j++)
                    {
                        if (item.files[j] == selections[i].data.name)
                        {
                            var fileField = document.createElement("input");
                            fileField.setAttribute("name", "file");
                            fileField.setAttribute("value", selections[i].data.name);
                            form.appendChild(fileField);
                            break;
                        }
                    }
                }

                document.body.appendChild(form);    // Not entirely sure if this is necessary
                form.submit();
            }
        },

        onAdmin : function(btn)
        {
            var configDlg = new LABKEY.ActionsAdminPanel({path: this.currentDirectory.data.path});

            configDlg.on('success', function(c){this.onDirectoryChange(this.currentDirectory);}, this);
            configDlg.on('failure', function(){Ext.Msg.alert("Update Action Config", "Update Failed")});

            configDlg.show();
        }
    });

    if (!fileSystem)
        fileSystem = new LABKEY.WebdavFileSystem({
            baseUrl:rootPath,
            rootName:'fileset'
        });

    fileBrowser = new FilesWebPartPanel({
        fileSystem: fileSystem,
        helpEl:null,
        showAddressBar: <%=bean.isShowAddressBar()%>,
        showFolderTree: <%=bean.isShowFolderTree()%>,
        showProperties: false,
        showFileUpload: false,
        showDetails: <%=bean.isShowDetails()%>,
        allowChangeDirectory: <%=bean.isAllowChangeDirectory()%>,
        actions: {drop:dropAction, configure:configureAction},
        buttonCfg: buttonActions
/*
        buttonCfg:['download','deletePath','refresh'
        <%=c.hasPermission(context.getUser(), InsertPermission.class)?",'uploadTool'":""%>
        ,'->'
        , new Ext.form.Label({html:'File Set:&nbsp;'}), combo
        <%=c.hasPermission(context.getUser(), AdminPermission.class)?",'configure'":""%>
        ]
*/
    });

    fileBrowser.height = 300;
/*
    fileBrowser.on("doubleclick", function(record){
        var contentType = record.data.contentType || "attachment";
        var location = "<%=PageFlowUtil.encodePath(request.getContextPath())%>/files<%=c.getEncodedPath()%>" + encodeURI(record.data.name) + "?renderAs=DEFAULT<%=me.getFileSet()==null ? "" : "&fileSet=" + PageFlowUtil.encode(me.getFileSet())%>";
        if (0 == contentType.indexOf("image/") || 0 == contentType.indexOf("text/"))
            window.open(location,"_blank");
        else
            window.location = location;
        });
*/

//    var resizer = new Ext.Resizable('files', {width:800, height:600, minWidth:640, minHeight:400});
//    resizer.on("resize", function(o,width,height){ this.setWidth(width); this.setHeight(height); }.createDelegate(fileBrowser));

    fileBrowser.render('files');

    var _resize = function(w,h)
    {
        if (!fileBrowser.rendered)
            return;
        var padding = [20,20];
        var xy = fileBrowser.el.getXY();
        var size = {
            width : Math.max(100,w-xy[0]-padding[0]),
            height : Math.max(100,h-xy[1]-padding[1])};
        fileBrowser.setSize(size);
        fileBrowser.doLayout();
    };

    if (autoResize)
    {
        Ext.EventManager.onWindowResize(_resize);
        Ext.EventManager.fireWindowResize();
    }

    fileBrowser.start(dir);
}
    var fileSets = [
<%
        boolean navigate = false;
        String selectedValue = null;
        ActionURL url = PageFlowUtil.urlProvider(FileUrls.class).urlBegin(c);
        FileContentService svc = ServiceRegistry.get().getService(FileContentService.class);
        AttachmentDirectory main = svc.getMappedAttachmentDirectory(c, false);
        if (null != main && null != main.getFileSystemDirectory())
        {
            String value = navigate ? url.getLocalURIString() : "/";
            out.write("[" + q(value) + ",'Default']");
            if (StringUtils.isEmpty(me.getFileSet()) || StringUtils.equals(me.getFileSet(),"Default"))
                selectedValue = value;
        }
        for (AttachmentDirectory attDir : svc.getRegisteredDirectories(c))
        {
            String name = attDir.getLabel();
            url.replaceParameter("fileSetName",name);
            String value = navigate ? url.getLocalURIString() : "/@files/" + name;
            out.write(",[" + q(value) + "," + q(name) + "]");
            if (StringUtils.equals(me.getFileSet(),name))
                selectedValue = value;
        }
        if (c.hasPermission(context.getUser(), AdminPermission.class))
        {
    //        out.write(",[" + q(new ActionURL(FileContentController.ShowAdminAction.class,c).getLocalURIString()) + ",'[configure]']");
        }
%>
    ];

    var selectedValue = <%=q(selectedValue)%>;

    Ext.onReady(function(){renderBrowser(<%=q(bean.getRootPath())%>, <%=q(startDir)%>);});
</script>