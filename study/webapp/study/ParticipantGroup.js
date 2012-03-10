/*
 * Copyright (c) 2011 LabKey Corporation
 *
 * Licensed under the Apache License, Version 2.0: http://www.apache.org/licenses/LICENSE-2.0
 */

Ext.namespace("LABKEY.study");

Ext.QuickTips.init();
Ext.GuidedTips.init();

LABKEY.study.ParticipantGroupDialog = Ext.extend(Ext.Window, {

    constructor : function(config){
        this.panelConfig = config;
        this.addEvents('aftersave');
        var h = config.hideDataRegion ? 500 : Ext.getBody().getViewSize().height * .75;

        if(h < 500)
            h = 500;

        LABKEY.study.ParticipantGroupDialog.superclass.constructor.call(this, {
            cls: 'extContainer',
            title: 'Define ' + Ext.util.Format.htmlEncode(config.subject.nounSingular) + ' Group',
            layout:'fit',
            width: Ext.getBody().getViewSize().width < 850 ? Ext.getBody().getViewSize().width * .9 : 800,
            height: h,
            modal: true,
            closeAction:'close'
        });
    },

    initComponent : function() {
        var groupPanel = new LABKEY.study.ParticipantGroupPanel(this.panelConfig);

        groupPanel.on('closeWindow', this.close, this);
        groupPanel.on('aftersave', function(){this.fireEvent('aftersave'); this.close();}, this);
        this.items = [groupPanel];
        
        LABKEY.study.ParticipantGroupDialog.superclass.initComponent.call(this);
    }
});

/**
 * Panel to take user input for the label and list of participant ids for a classfication to be created or edited
 * @param categoryRowId = the rowId of the category to be edited (null if create new)
 * @param categoryLabel = the current label of the category to be edited (null if create new)
 * @param categoryParticipantIds = the string representation of the ptid ids array of the category to be edited (null if create new)
 */
LABKEY.study.ParticipantGroupPanel = Ext.extend(Ext.Panel, {
    constructor : function(config){
        Ext.apply(config, {
            layout: 'form',
            bodyStyle:'padding:20px;',
            border: false,
            autoScroll: true
        });

        this.addEvents('closeWindow');
        this.addEvents('aftersave');

        this.isAdmin = config.isAdmin || false;
        this.subject = config.subject;
        this.hasButtons = config.hasButtons || true;
        this.canShare = config.canShare || true;
        this.dataRegionName = config.dataRegionName || 'demoDataRegion';

        LABKEY.study.ParticipantGroupPanel.superclass.constructor.call(this, config);
    },

    initComponent : function() {
        var buttons = [];

        if (this.hasButtons)
        {
            buttons.push({text:'Save', handler: this.saveCategory, disabled : !this.canEdit, scope: this});
            buttons.push({text:'Cancel', handler: function(){this.fireEvent('closeWindow');}, scope: this});
        }

        this.categoryPanel = new Ext.form.FormPanel({
            border: false,
            defaults : {disabled : !this.canEdit},
            labelAlign: 'top',
            items: [{
                id: 'categoryLabel',
                xtype: 'textfield',
                value: this.categoryLabel,
                fieldLabel: this.subject.nounSingular + ' Group Label',
                emptyText: this.subject.nounSingular + ' Group Label',
                allowBlank: false,
                selectOnFocus: true,
                preventMark: true,
                anchor: '100%',
                listeners: {
                    scope:this,
                    specialkey: function(f, e){
                        if(e.getKey() == e.ENTER){
                            this.saveCategory();
                        }
                    }
                }
            },{
                id: 'categoryIdentifiers',
                xtype: 'textarea',
                value: this.categoryParticipantIds,
                fieldLabel: this.subject.nounSingular + ' Identifiers',
                emptyText: 'Enter ' + this.subject.nounSingular + ' Identifiers Separated by Commas',
                allowBlank: false,
                preventMark: true,
                height: 100,
                anchor: '100%'
            }],
            buttons: buttons
        });

        if (!this.hideDataRegion)
        {
            var demoStore = new LABKEY.ext.Store({
                schemaName: 'study',
                queryName: 'DataSets',
                filterArray: [LABKEY.Filter.create('DemographicData', true)],
                columns: 'Label',
                sort: 'Label',
                listeners: {
                    scope: this,
                    'load': function(store, records, options)
                    {
                        // on load, select the first item in the combobox
                        if (records.length > 0)
                        {
                            this.demoCombobox.setValue(records[0].get("Label"));
                            this.demoCombobox.fireEvent('select', this.demoCombobox, records[0], 0);
                        }
                    }
                },
                autoLoad: true
            });

            this.demoCombobox = new Ext.form.ComboBox({
                triggerAction: 'all',
                mode: 'local',
                store: demoStore,
                valueField: 'Label',
                displayField: 'Label',
                fieldLabel: 'Select ' + Ext.util.Format.htmlEncode(this.subject.nounPlural) + ' from',
                labelStyle: 'width: 150px;',
                labelSeparator : '',
                minListWidth : 300,
                disabled : !this.canEdit,
                listeners: {
                    scope: this,
                    'select': function(cmp, record, index){
                        this.getDemoQueryWebPart(record.get("Label"));
                    }
                }
            });
        }

        var sharedTip = '' +
            '<div>' +
                '<div class=\'g-tip-subheader\'>' +
                    'Share this ' + Ext.util.Format.htmlEncode(this.subject.nounSingular) + ' group with all users' +
                '</div>' +
            '</div>';

        this.sharedfield = new Ext.form.Checkbox({
            fieldLabel     : 'Shared',
            name           : 'Shared',
            labelSeparator : '',
            hidden         : !this.canShare,
            disabled       : !this.isAdmin || !this.canEdit,
            gtip           : sharedTip
        });

        Ext.QuickTips.register({
            target : this.sharedfield,
            text   : 'Share this ' + Ext.util.Format.htmlEncode(this.subject.nounSingular) + ' group with all users'
        });

        if (!this.categoryShared || this.categoryShared == "false")
            this.sharedfield.setValue(false);
        else
            this.sharedfield.setValue(true);

        var categoryItems = [this.sharedfield];
        if (this.demoCombobox)
            categoryItems.push(this.demoCombobox);

        this.items = [
            this.categoryPanel,
            {
                border : false, frame: false,
                style  : this.hasButtons ? 'margin-top: -22px;' : '',
                width  : 450,
                items  : [{
                    layout : 'column',
                    border : false, frame : false,
                    defeaults : { border: false, frame: false },
                    items  : [{
                        layout      : 'form',
                        columnWidth : 1,
                        border : false, frame : false,
                        items : categoryItems
                    }]
                }]
            }
        ];

        if (!this.hideDataRegion)
            this.items.push({xtype: 'panel', id: 'demoQueryWebPartPanel', border: false});

        LABKEY.study.ParticipantGroupPanel.superclass.initComponent.call(this);
    },

    validate: function() {

        // get the label and ids from the form
        var fieldValues = this.categoryPanel.getForm().getFieldValues();
        var label = fieldValues["categoryLabel"];
        var idStr = fieldValues["categoryIdentifiers"];

        // make sure the label and idStr are not null
        if (!label)
        {
            Ext.Msg.alert("Error", this.subject.nounSingular + " Category Label required.");
            return false;
        }
        if (!idStr)
        {
            Ext.Msg.alert("Error", "One or more " + this.subject.nounSingular + " Identifiers required.");
            return false;
        }
        return true;
    },

    saveCategory: function()
    {
         if (!this.validate())
            return;
        var categoryData = this.getCategoryData();

        if (this.categoryRowId)
        {
            categoryData.rowId = this.categoryRowId;
        }

        // save the participant category ("create" if no prior rowId, "update" if rowId exists)
        Ext.Ajax.request(
        {
            url : (this.categoryRowId
                    ? LABKEY.ActionURL.buildURL("participant-group", "updateParticipantCategory")
                    : LABKEY.ActionURL.buildURL("participant-group", "createParticipantCategory")
                  ),
            method : 'POST',
            success: function(){
                this.getEl().unmask();
                this.fireEvent('aftersave');
                _grid.getStore().reload();
            },
            failure: function(response, options){
                this.getEl().unmask();
                LABKEY.Utils.displayAjaxErrorResponse(response, options, false, 'An error occurred:<br>');
            },
            jsonData : categoryData,
            headers : {'Content-Type' : 'application/json'},
            scope: this
        });
    },

    getCategoryData: function(){
         // get the label and ids from the form
        var fieldValues = this.categoryPanel.getForm().getFieldValues();
        var label = fieldValues["categoryLabel"];
        var idStr = fieldValues["categoryIdentifiers"];

        // mask the panel
        this.getEl().mask("Saving category...", "x-mask-loading");

        // split the ptid list into an array of strings
        var ids = idStr.split(",");
        for (var i = 0; i < ids.length; i++)
        {
            ids[i] = ids[i].trim();
        }

        // setup the data to be stored for the category
        var categoryData = {
            label: label,
            type: 'list',
            participantIds: ids,
            shared : this.sharedfield.getValue()
        };
        
        return categoryData;
    },

    getDemoQueryWebPart: function(queryName)
    {
        var ptidCategoryPanel = this;
        var initialLoad = true;

        var demoQueryWebPart =  new LABKEY.QueryWebPart({
            renderTo: 'demoQueryWebPartPanel',
            dataRegionName: this.dataRegionName,
            schemaName: 'study',
            queryName: queryName,
            frame: 'none',
            border: false,
            showRecordSelectors: true,
            showUpdateColumn: false,
            maskEl: ptidCategoryPanel.getEl(),
            buttonBar: {
                position: (this.canEdit ? 'top' : 'none'),
                includeStandardButtons: false,
                items:[{
                    text: 'Add Selected',
                    requiresSelection: true,
                    handler: function(){
                        ptidCategoryPanel.getSelectedDemoParticipants(queryName, "selected");
                    }
                },{
                    text: 'Add All',
                    handler: function(){
                        // todo: fix this to only add the visible records (i.e. if filter applied to dataregion)
                        ptidCategoryPanel.getSelectedDemoParticipants(queryName, "all");
                    }
                }]
            },
            success: function(){
                // clear any cached selections from the last time this dataRegion was used
                if (initialLoad)
                {
                    Ext.ComponentMgr.get(this.dataRegionName).clearSelected();
                    initialLoad = false;
                }
            }
        });
    },

    getSelectedDemoParticipants: function(queryName, showStr) {
        var ptidCategoryPanel = this;

        // convert user filters from data region to expected filterArray
        var filters = [];
        Ext.each(Ext.ComponentMgr.get(this.dataRegionName).getUserFilter(), function(usrFilter){
            var filterType = this.getFilterTypeByURLSuffix(usrFilter.op);
            filters.push(LABKEY.Filter.create(usrFilter.fieldKey,  usrFilter.value, filterType));
        }, this);

        // get the selected rows from the QWP data region
        LABKEY.Query.selectRows({
            schemaName: 'study',
            queryName: queryName,
            selectionKey: Ext.ComponentMgr.get(this.dataRegionName).selectionKey,
            showRows: showStr,
            filterArray: filters,
            columns: this.subject.columnName,
            scope: this,
            success: function(data){
                // get the current list of participant ids from the form
                var classPanelValues = ptidCategoryPanel.categoryPanel.getForm().getFieldValues();
                var tempIds = classPanelValues["categoryIdentifiers"];

                // also store the ids as an array to check if the ids to add already exist
                var tempIdsArray = tempIds.split(",");
                for (var i = 0; i < tempIdsArray.length; i++)
                {
                    tempIdsArray[i] = tempIdsArray[i].trim();
                }

                // append the selected ids to the current list
                if (data.rows.length > 0)
                {
                   for (var i = 0; i < data.rows.length; i++)
                   {
                       if (tempIdsArray.indexOf(data.rows[i][this.subject.nounColumnName]) == -1)
                       {
                           tempIds += (tempIds.length > 0 ? ", " : "") + data.rows[i][this.subject.nounColumnName];
                           tempIdsArray.push(data.rows[i][this.subject.nounColumnName]);
                       }
                   }
                }

                // put the new list of ids into the form
                ptidCategoryPanel.categoryPanel.getForm().setValues({
                   categoryIdentifiers: tempIds
                });
            }
        });
    },

    getFilterTypeByURLSuffix: function(op)
    {
        // loop through the labkey filter types to match the URL suffix
        for (var type in LABKEY.Filter.Types)
        {
            if (LABKEY.Filter.Types[type].getURLSuffix() == op)
            {
                return LABKEY.Filter.Types[type];
            }
        }
        return null;
    }
});
