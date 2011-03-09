/*
 * Copyright (c) 2009-2010 LabKey Corporation
 *
 * Licensed under the Apache License, Version 2.0: http://www.apache.org/licenses/LICENSE-2.0
 */

Ext.QuickTips.init();

Ext.grid.RowExpander = function(config){
    Ext.apply(this, config);

    this.addEvents({
        beforeexpand : true,
        expand: true,
        beforecollapse: true,
        collapse: true
    });

    Ext.grid.RowExpander.superclass.constructor.call(this);

    if(this.tpl){
        if(typeof this.tpl == 'string'){
            this.tpl = new Ext.Template(this.tpl);
        }
        this.tpl.compile();
    }

    this.state = {};
    this.bodyContent = {};
};

Ext.extend(Ext.grid.RowExpander, Ext.util.Observable, {
    header: "",
    width: 20,
    sortable: false,
    fixed:true,
    menuDisabled:true,
    dataIndex: '',
    id: 'expander',
    lazyRender : true,
    enableCaching: true,

    getRowClass : function(record, rowIndex, p, ds){
        p.cols = p.cols-1;
        var content = this.bodyContent[record.id];
        if(!content && !this.lazyRender){
            content = this.getBodyContent(record, rowIndex);
        }
        if(content){
            p.body = content;
        }
        return this.state[record.id] ? 'x-grid3-row-expanded' : 'x-grid3-row-collapsed';
    },

    init : function(grid){
        this.grid = grid;

        var view = grid.getView();
        view.getRowClass = this.getRowClass.createDelegate(this);

        view.enableRowBody = true;

        grid.on('render', function(){
            view.mainBody.on('mousedown', this.onMouseDown, this);
        }, this);
    },

    getBodyContent : function(record, index){
        if(!this.enableCaching){
            return this.tpl.apply(record.data);
        }
        var content = this.bodyContent[record.id];
        if(!content){
            content = this.tpl.apply(record.data);
            this.bodyContent[record.id] = content;
        }
        return content;
    },

    onMouseDown : function(e, t){
        if(t.className == 'x-grid3-row-expander'){
            e.stopEvent();
            var row = e.getTarget('.x-grid3-row');
            this.toggleRow(row);
        }
    },

    renderer : function(v, p, record){
        p.cellAttr = 'rowspan="2"';
        return '<div class="x-grid3-row-expander">&#160;</div>';
    },

    beforeExpand : function(record, body, rowIndex){
        if(this.fireEvent('beforeexpand', this, record, body, rowIndex) !== false){
            if(this.tpl && this.lazyRender){
                body.innerHTML = this.getBodyContent(record, rowIndex);
            }
            return true;
        }else{
            return false;
        }
    },

    toggleRow : function(row){
        if(typeof row == 'number'){
            row = this.grid.view.getRow(row);
        }
        this[Ext.fly(row).hasClass('x-grid3-row-collapsed') ? 'expandRow' : 'collapseRow'](row);
    },

    expandRow : function(row){
        if(typeof row == 'number'){
            row = this.grid.view.getRow(row);
        }
        var record = this.grid.store.getAt(row.rowIndex);
        var body = Ext.DomQuery.selectNode('tr:nth(2) div.x-grid3-row-body', row);
        if(this.beforeExpand(record, body, row.rowIndex)){
            this.state[record.id] = true;
            body.style.display = '';
            Ext.fly(row).replaceClass('x-grid3-row-collapsed', 'x-grid3-row-expanded');
            this.fireEvent('expand', this, record, body, row.rowIndex);
        }
    },

    collapseRow : function(row){
        if(typeof row == 'number'){
            row = this.grid.view.getRow(row);
        }
        var record = this.grid.store.getAt(row.rowIndex);
        var body = Ext.fly(row).child('tr:nth(2) div.x-grid3-row-body', true);
        if(this.fireEvent('beforecollapse', this, record, body, row.rowIndex) !== false){
            this.state[record.id] = false;
            //Ext.fly(row).replaceClass('x-grid3-row-expanded', 'x-grid3-row-collapsed');
            // hack for ie
            Ext.fly(row).removeClass('x-grid3-row-expanded');
            body.style.display='none';
            Ext.fly(row).addClass('x-grid3-row-collapsed');

            this.fireEvent('collapse', this, record, body, row.rowIndex);
        }
    }
});

LABKEY.ViewsPanel = function(config) {
    config = config || {};

    Ext.apply(this, config);

    if (!this.container)
    {
        Ext.Msg.alert("Configuration Error", "config.container is a required parameter.");
        return;
    }

    if (!this.renderTo)
    {
        Ext.Msg.alert("Configuration Error", "config.renderTo is a required parameter.");
        return;
    }
};

LABKEY.ViewsPanel.prototype = {
    // the id of the div to render this panel to
    renderTo : undefined,

    // the container path for creating the connection object
    container : undefined,

    // the grid panel
    grid : undefined,

    // the grid selection model
    selModel : new Ext.grid.CheckboxSelectionModel(),

    // an array of menu items to insert into the create dropdown button
    createMenu : undefined,

    /**
     * the query this view is filtered to, if undefined will result in all queries being
     * used to gather views from
     */
    baseQuery : undefined,

    // the id of the div to render any view filter information
    filterDiv : undefined,

    dataConnection : new Ext.data.Connection({
        url: LABKEY.ActionURL.buildURL("reports", "manageViewsSummary", this.container),
        method: 'GET',
        timeout: 300000
    }),

    /**
     * The row expander object, display when the row is expanded
     */
    expander : new Ext.grid.RowExpander({
        tpl : new Ext.XTemplate(
                '<table>',
                    '<tpl if="description != undefined"><tr><td><b>description</b></td><td>{description}</td></tr></tpl>',
                    '<tr><td><b>folder</b></td><td>{container}</td></tr>',
                    '<tr><td><b>query name</b></td><td>{query}</td></tr>',
                    '<tpl if="schema != undefined"><tr><td><b>schema name</b></td><td>{schema}</td></tr></tpl>',
                    '<tr><td><b>permissions</b></td><td>{permissions}</td>',
                    '<tpl if="runUrl != undefined || editUrl != undefined">',
                        '<tr><td></td><td>',
                            '<tpl if="runUrl != undefined">&nbsp;<a href="{runUrl}" class="labkey-text-link">view</a></tpl>',
                            '<tpl if="editUrl != undefined">&nbsp;<a href="{editUrl}" class="labkey-text-link">source</a></tpl></td></tr>',
                    '</tpl>',
                '</table>')
        }),

    /**
     * Create the data store used to parse view record information returned by the
     * connection proxy
     */
    getStore : function() {
        var store = new Ext.data.GroupingStore({
            reader: new Ext.data.JsonReader({root:'views',id:'reportId'},
                    [
                        {name:'query'},
                        {name:'schema'},
                        {name:'name'},
                        {name:'createdBy'},
                        {name:'created'},
                        {name:'modifiedBy'},
                        {name:'modified'},
                        {name:'permissions'},
                        {name:'description', defaultValue:undefined},
                        {name:'editable', type:'bool'},
                        {name:'inherited', type:'bool'},
                        {name:'icon', defaultValue:undefined},
                        {name:'runUrl', defaultValue:undefined},
                        {name:'editUrl', defaultValue:undefined},
                        {name:'reportId', defaultValue:undefined},
                        {name:'queryView', type:'boolean', defaultValue:false},
                        {name:'container'},
                        {name:'type'}]),
            proxy: new Ext.data.HttpProxy(this.dataConnection),
            autoLoad: true,
            sortInfo: {field:'query', direction:"ASC"},
/*
            listeners: {
                load: function(store, records) {
                    if (records.length == 0)
                        Ext.Msg.alert("Manage Views", "You have no views in this container.");
                }
            },
*/
            groupField:'query'});

        return store;
    },

    /**
     * Create the config object for the grid panel
     */
    getGridConfig : function() {
        var gridConfig = {
            el: this.renderTo,
            autoScroll:false,
            autoHeight:true,
            width:800,
            plugins: this.expander,
            loadMask:{msg:"Loading, please wait..."},
            store: this.getStore(),
            selModel: this.selModel,
            listeners: {
                rowclick: function(g, rowIndex, event) {
                    event.stopEvent();
                    this.expander.toggleRow(rowIndex);
                },
                rowcontextmenu : function(g, rowIndex, event) {
                    event.stopEvent();
                    var coords = event.getXY();
                    this.getContextMenu(g, g.store.getAt(rowIndex).data).showAt([coords[0], coords[1]]);
                },
                scope:this
            },
            view: new Ext.grid.GroupingView({
                startCollapsed:false,
                hideGroupedColumn:true,
                forceFit:true,
                groupTextTpl: '{values.group}'
            }),
            tbar: this.getButtons(),
            //buttons: this.getButtons(),
            buttonAlign:'center',
            columns: this.getColumns()
        };
        return gridConfig;
    },

    /**
     * Create the button at the bottom of the panel
     */
    getButtons : function() {
        this.editBtn = new Ext.Button({
            text:'Edit',
            id: 'btn_editView',
            tooltip: {text:'Edit an existing view (you can also double click on the view to edit)', title:'Edit View'},
            listeners:{click:function(button, event) {this.editSelected(button);}, scope:this}
        });

        var buttons = [
            {text:'Expand All', tooltip: {text:'Expands all groups', title:'Expand All'}, listeners:{click:function(button, event) {this.grid.view.expandAllGroups();}, scope:this}},
            {text:'Collapse All', tooltip: {text:'Collapses all groups', title:'Collapse All'}, listeners:{click:function(button, event) {this.grid.view.collapseAllGroups();}, scope:this}},
            {text:'Delete Selected', id: 'btn_deleteView', tooltip: {text:'Delete selected view', title:'Delete Views'}, listeners:{click:function(button, event) {deleteSelections(this.grid);}, scope:this}},
            {text:'Rename', id: 'btn_editView', tooltip: {text:'Rename or edit the description of an existing view', title:'Rename View'}, listeners:{click:function(button, event) {this.editSelected(button);}, scope:this}}
        ];

        if (this.createMenu != undefined)
        {
            var item = new Ext.Button({
                text:'Create',
                id: 'btn_createView',
                menu: {
                    id: 'mainMenu',
                    cls:'extContainer',
                    items: this.createMenu }
            });

/*
            item.menu.addMenuItem({
                id: 'config_views',
                listeners:{click:function(button, event) {this.configViewTypes();}, scope:this},
                text:'Configure available View types...'});

*/
            buttons.splice(0,0,item);
        }

        // options button
        if (this.baseQuery != undefined)
        {
            buttons.push('-');
            buttons.push({
                text:'Options...',
                id: 'config_views',
                tooltip: {text:'Configure View Options', title:'Options'},
                listeners:{click:function(button, event) {this.configViewTypes();}, scope:this}
            });
        }

        // selection button
        if (this.baseQuery != undefined)
        {
            var queryBtn = new Ext.Button({
                text:'Filter',
                id: 'btn_selectQuery',
                tooltip: {text: 'Filter the views that are displayed', title: 'Filter'},
                menu: {
                    cls:'extContainer',
                    items: [
                        {text:'Show all views in the current container', listeners:{click:function(button, event) {
                            this.renderFilterMsg(true);
                            this.dataConnection.extraParams = undefined;
                            this.grid.store.load();}, scope:this}},
                        {text:'Show views only from the ' + this.baseQuery.queryName + ' query', listeners:{click:function(button, event) {
                            this.renderFilterMsg(false);
                            this.dataConnection.extraParams = this.baseQuery;
                            this.grid.store.load();}, scope:this}}
                    ]}
            });
            buttons.splice(0,0,queryBtn,'-');
        }

        return buttons;
    },

    /**
     * Create the grid columns
     */
    getColumns : function() {
        return [
            //this.expander,
            //this.selModel,
            {header:'Title', dataIndex:'name', width:200, renderer:Ext.util.Format.htmlEncode},
            {header:'Type', dataIndex:'type', renderer:typeRenderer},
            {header:'Created By', dataIndex:'createdBy'},
            {header:'Created', dataIndex:'created', hidden:true},
            {header:'Modified By', dataIndex:'modifiedBy', hidden:true},
            {header:'Modified', dataIndex:'modified', hidden:true},
            {header:'Permissions', dataIndex:'permissions'},
            {header:'Query', dataIndex:'query'},
            {header:'Description', dataIndex:'description', hidden:true},
            {header:'Schema', dataIndex:'schema', hidden:true}
        ];
    },

    /**
     * Create and render this view panel
     */
    show : function() {

        this.renderFilterMsg(false);
        this.dataConnection.extraParams = this.baseQuery;
        this.grid = new Ext.grid.GridPanel(this.getGridConfig());
        this.grid.render();
    },

    renderFilterMsg : function(allViews) {

        if (this.baseQuery && this.filterDiv)
        {
            if (allViews)
                Ext.get(this.filterDiv).dom.innerHTML = 'Showing all views in this container';
            else
                Ext.get(this.filterDiv).dom.innerHTML = 'Showing only the views from the query: ' + this.baseQuery.queryName;
        }
    },

    /**
     * Edit the selected view
     * @param button
     * @param grid
     */
    editSelected : function(button) {
        var selections = this.grid.selModel.getSelections();

        if (selections.length == 0)
        {
            Ext.Msg.alert("Rename Views", "There are no views selected");
            return false;
        }

        if (selections.length > 1)
        {
            Ext.Msg.alert("Rename Views", "Only one view can be edited at a time");
            return false;
        }

        if (selections[0].data.inherited)
        {
            Ext.Msg.alert("Rename Views", "This view is shared from another container. A shared view can be edited only in the container that it was created in.");
            return;
        }

        if (!selections[0].data.editable)
        {
            Ext.Msg.alert("Rename Views", "This view is not editable.");
            return;
        }
        doEditRecord(button, this.grid, selections[0].data);
    },
    
    /**
     * Creates the grid row context menu
     */
    getContextMenu : function(grid, data) {
        if (data != undefined)
        {
            return new Ext.menu.Menu({
                id: 'rowContextMenu',
                cls: 'extContainer',
                items: [
                    {text: 'View', disabled : data.runUrl == undefined, handler: function(){window.location = data.runUrl;}},
                    {text: 'Source', disabled : data.editUrl == undefined, handler: function(){window.location = data.editUrl;}},
                        '-',
                    {text: 'Rename', disabled : (!data.editable || data.inherited), handler: function(){doEditRecord(null, grid, data);}},
                    {text: 'Delete', disabled : (!data.editable || data.inherited), handler: function(){deleteView(grid, data);}}
                ]
            });
        }
    },

    /**
     * Display the view configurations dialog box
     */
    configViewTypes : function() {

        Ext.Ajax.request({
            url: LABKEY.ActionURL.buildURL("reports", "viewOptions", null, this.baseQuery),
            method: "GET",
            scope: this,
            success: function(response, options){doConfigViewOptions(Ext.util.JSON.decode(response.responseText), options, this.baseQuery);},
            failure: function(){Ext.Msg.alert("Configure View types", "Unable to get view type information");}});
    }
};

/**
 * Column render templates
 */
var typeTemplate = new Ext.XTemplate('<tpl if="icon == undefined">{type}</tpl><tpl if="icon != undefined"><img src="{icon}" alt="{type}"></tpl>').compile();

function typeRenderer(value, p, record)
{
    return typeTemplate.apply(record.data);
}

function renderRow(value, p, record)
{
    var txt = 'ext:qtip="';

    txt = txt.concat('<b>title:</b> ' + record.data.name + '<br>');
    if (record.data.description != undefined)
        txt = txt.concat('<b>description:</b> ' + record.data.description + '<br>');
    if (record.data.query != undefined)
        txt = txt.concat('<b>query:</b> ' + record.data.query + '<br>');
    if (record.data.schema != undefined)
        txt = txt.concat('<b>schema:</b> ' + record.data.schema + '<br>');
    txt = txt.concat('"');
    p.attr = txt;

    return value;
}

/**
 * Delete the selected views
 */
function deleteSelections(grid)
{
    var selections = grid.selModel.getSelections();

    if (selections.length == 0)
    {
        Ext.Msg.alert("Delete Views", "There are no views selected");
        return;
    }
    else
    {
        var msg = "Delete Selected Views:<br/>";
        var params = [];

        for (var i=0; i < selections.length; i++)
        {
            if (selections[i].data.inherited)
            {
                Ext.Msg.alert("Delete Views", "You are trying to delete a view that is shared from another container. A shared view can be deleted only in the container that it was created in.");
                return;
            }
            msg = msg.concat(selections[i].data.name);
            msg = msg.concat('<br/>');

            if (selections[i].data.queryView)
                params.push("viewId=" + selections[i].id);
            else
                params.push("reportId=" + selections[i].id);

        }
        doDeleteViews(msg, params, grid);
    }
}

/**
 * Delete the selected views
 */
function deleteView(grid, record)
{
    if (record != undefined)
    {
        var msg = "Delete View: " + record.name + "<br>";
        var params = [];

        if (record.queryView)
            params.push("viewId=" + record.reportId);
        else
            params.push("reportId=" + record.reportId);
        
        doDeleteViews(msg, params, grid);
    }
}

/**
 * handles the server request to delete views
 */
function doDeleteViews(msg, params, grid)
{
    Ext.Msg.show({
            title : 'Delete Views',
            msg : msg,
            buttons: Ext.Msg.YESNO,
            icon: Ext.Msg.QUESTION,
            fn: function(btn, text) {
                if (btn == 'yes')
                {
                    Ext.Ajax.request({

                        url: LABKEY.ActionURL.buildURL("reports", "manageViewsDeleteReports") + '?' + params.join('&'),
                        method: "POST",
                        scope: this,
                        success: function(){grid.store.load();},
                        failure: function(){Ext.Msg.alert("Delete Views", "Deletion Failed");}
                    });
                }},
            id: 'delete_views'
    });
}

/*
function editRecord(button, grid, record, o)
{
    if (record.inherited)
    {
        Ext.Msg.alert("Rename Views", "This view is shared from another container. A shared view can be edited only in the container that it was created in.");
        return;
    }

    if (record.queryView)
    {
        Ext.Msg.alert("Rename Views", "Only views can be renamed. To convert a custom query to a view, expand the row (by selecting it) and click on the [convert to view] link");
        return;
    }
    doEditRecord(button, grid, record);
}
*/

function doEditRecord(button, grid, record)
{
    var items = [{
        fieldLabel: 'View Name',
        name: 'viewName',
        allowBlank:false,
        width: 250,
        value: record.name
    }];

    if (!record.queryView)
    {
        items[items.length] = {
            fieldLabel: 'Description',
            name: 'description',
            xtype: 'textarea',
            width: 250,
            value: record.description
        }
    }

    var formPanel = new Ext.FormPanel({
        bodyStyle:'padding:5px',
        defaultType: 'textfield',
        items: items
    });

    var params = [];
    if (record.queryView)
        params.push("viewId=" + record.reportId);
    else
        params.push("reportId=" + record.reportId);

    var win = new Ext.Window({
        title: 'Edit View',
        layout:'form',
        border: false,
        width: 450,
        height: 185,
        closeAction:'close',
        modal: false,
        items: formPanel,
        buttons: [{
            text: 'Submit',
            id: 'btn_submit',
            handler: function(){submitForm(win, formPanel, params, grid);}
        },{
            text: 'Cancel',
            id: 'btn_cancel',
            handler: function(){win.close();}
        }]
    });

    win.show(button);
}

function doAdvancedEdit(config)
{
    Ext.Msg.confirm('Edit Source', "Do you want to navigate away from your current view to the advanced editor?", function(btn, text) {
        if (btn == 'yes')
        {
            window.location = config.dest;
        }
    });
}

function submitForm(win, panel, params, grid)
{
    var items = panel.items;

    // client side validation
    var form = panel.getForm();
    if (form && !form.isValid())
    {
        Ext.Msg.alert('Edit Views', 'Not all fields have been properly completed');
        return;
    }

    form.submit({
        url: LABKEY.ActionURL.buildURL("reports", "manageViewsEditReports") + '?' + params.join('&'),
        waitMsg:'Submiting Form...',
        method: 'POST',
        success: function(){
            win.close();
            grid.store.load();
        },
        failure: function(form, action){Ext.Msg.alert("Save Error", "An error occurred while saving the view");}
    });
}

function setFormFieldTooltip(component)
{
    var label = Ext.get('x-form-el-' + component.id).prev('label');
    Ext.QuickTips.register({
        target: label,
        text: component.tooltip.text,
        title: ''
    });
}

function doConfigViewOptions(response, options, baseQuery)
{
    // should be the parsed json object
    var options = response.viewOptions;
    var formItems = new Array();

    for (var i=0; i < options.length; i++)
    {
        formItems.push({
            xtype: 'checkbox',
            boxLabel: options[i].reportLabel,
            name: 'viewItemTypes',
            inputValue: options[i].reportType,
            checked: options[i].enabled == 'true'
        });
    }
    // query and schema name
    formItems.push({name: 'schemaName', xtype: 'hidden', value: baseQuery.schemaName});
    formItems.push({name: 'queryName', xtype: 'hidden', value: baseQuery.queryName});
    formItems.push({name: 'baseFilterItems', xtype: 'hidden', value: baseQuery.baseFilterItems});

    var formPanel = new Ext.FormPanel({
        bodyStyle:'padding:5px',
        autoHeight: true,
        items: [{
            xtype: 'checkboxgroup',
            fieldLabel: 'Available view types',
            columns: 1,
            items: formItems
        }]
    });

    var win = new Ext.Window({
        title: 'Configure View Options',
        layout:'form',
        border: false,
        autoHeight: true,
        width: 450,
        closeAction:'close',
        modal: false,
        items: formPanel,
        buttons: [{
            text: 'Submit',
            id: 'btn_submit',
            handler: function(){updateViewOptions(win, formPanel);}
        },{
            text: 'Cancel',
            id: 'btn_cancel',
            handler: function(){win.close();}
        },{
            text: 'Reset to Default',
            id: 'btn_reset',
            disabled: true,
            handler: function(){win.close();}
        }]
    });

    win.show();
}

function updateViewOptions(win, panel)
{
    var items = panel.items;

    // client side validation
    var form = panel.getForm();
    if (form && !form.isValid())
    {
        Ext.Msg.alert('Edit Views', 'Not all fields have been properly completed');
        return;
    }

    form.submit({
        url: LABKEY.ActionURL.buildURL("reports", "manageViewsUpdateViewOptions"),
        waitMsg:'Submiting Form...',
        method: 'POST',
        success: function(){
            win.close();
        },
        failure: function(form, action){Ext.Msg.alert("Save Error", "An error occurred while saving the view");}
    });
}

