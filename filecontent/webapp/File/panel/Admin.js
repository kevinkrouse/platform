/*
 * Copyright (c) 2013 LabKey Corporation
 *
 * Licensed under the Apache License, Version 2.0: http://www.apache.org/licenses/LICENSE-2.0
 */
Ext4.define('File.panel.Admin', {

    extend : 'Ext.tab.Panel',

    constructor : function(config) {

        Ext4.apply(config, {
            defaults: {
                xtype: 'panel',
                border: false,
                margin: '5 0 0 0'
            }
        });

        Ext4.applyIf(config, {

        });

        this.callParent([config]);

//        this.addEvents();
    },

    initComponent : function() {
        this.items = this.getItems();

        var submitButton = {
            xtype: 'button',
            text: 'submit',
            handler: this.onSubmit,
            scope: this
        };

        var cancelButton = {
            xtype: 'button',
            text: 'cancel',
            handler: this.onCancel,
            scope: this
        };

        this.resetDefaultsButton = Ext4.create('Ext.button.Button', {
            text: 'Reset To Default',
            handler: this.onResetDefaults,
            scope: this
        });


        this.buttons = [submitButton, cancelButton, this.resetDefaultsButton];
        this.callParent();
    },

    getItems: function(){
        return [
//            this.getActionsPanel(), TODO: Create the actions panel. Skipping for this sprint (13.1 Sprint 2)
            this.getFilePropertiesPanel(),
            this.getToolBarPanel(),
            this.getGeneralSettingsPanel()
        ];
    },

    getActionsPanel: function(){
//        this.actionsPanel = Ext4.create('', {
//            title: 'Actions'
//        });

//        this.actionsPanel.on('activate', function(){
//            this.resetDefaultsButton.show();
//        }, this);

//        return this.actionsPanel;
    },

    getFilePropertiesPanel: function(){
        this.filePropertiesPanel = Ext4.create('File.panel.FileProperties', {
            border: false,
            padding: 10,
            fileConfig: this.pipelineFileProperties.fileConfig,
            additionalPropertiesType: this.additionalPropertiesType
        });

        this.filePropertiesPanel.on('editfileproperties', this.onEditFileProperties, this);

        this.filePropertiesPanel.on('activate', function(){
            this.resetDefaultsButton.hide();
        }, this);

        return this.filePropertiesPanel;
    },

    getToolBarPanel: function(){
        this.toolBarPanel = Ext4.create('File.panel.ToolbarPanel', {
            title : 'Toolbar and Grid Settings',
            tbarActions : this.pipelineFileProperties.tbarActions,
            gridConfigs : this.pipelineFileProperties.gridConfig
        });

        this.toolBarPanel.on('activate', function(){
            this.resetDefaultsButton.show();
        }, this);
        return this.toolBarPanel;
    },

    getGeneralSettingsPanel: function(){
        if(!this.generalSettingsPanel){
            var descriptionText = {
                html: '<span class="labkey-strong">Configure General Settings</span>' +
                        '<br />' +
                        'Set the default File UI preferences for this folder.',
                border: false,
                height: 55,
                autoScroll:true
            };

            this.showUploadCheckBox = Ext4.create('Ext.form.field.Checkbox', {
                boxLabel: 'Show the file upload panel by default.',
                width: '100%',
                margin: '0 0 0 10',
                checked: this.pipelineFileProperties.expandFileUpload,
                name: 'showUpload'
            });

            this.generalSettingsPanel = Ext4.create('Ext.panel.Panel', {
                title: 'General Settings',
                border: false,
                padding: 10,
                items: [descriptionText, this.showUploadCheckBox]
            });
        }

        this.generalSettingsPanel.on('activate', function(){
            this.resetDefaultsButton.hide();
        }, this);

        return this.generalSettingsPanel;
    },

    onCancel: function(){
        this.fireEvent('close');
    },

    onSubmit: function(button, event, handler){
        var updateURL = LABKEY.ActionURL.buildURL('pipeline', 'updatePipelineActionConfig', this.containerPath);
        var postData = {
            expandFileUpload: this.showUploadCheckBox.getValue(),
            fileConfig: this.filePropertiesPanel.getFileConfig(),
            gridConfig: this.toolBarPanel.getGridConfigs(),
            tbarActions: this.toolBarPanel.getTbarActions()
            //actions: this.actionsPanel.getActionConfigs()
        };

        if(!handler){
            handler = function(){
                this.fireEvent('success');
                this.fireEvent('close');
            }
        }

        Ext4.Ajax.request({
            url: updateURL,
            method: 'POST',
            scope: this,
            success: handler,
            failure: function(){
                console.log('Failure saving files webpart settings.');
                this.fireEvent('failure');
            },
            jsonData: postData
        });
    },

    onEditFileProperties: function(){
        // TODO: Save new settings and navigate to ecit properties page.
        var handler = function(){
            window.location = LABKEY.ActionURL.buildURL('fileContent', 'designer', this.containerPath, {'returnURL':window.location});
        };
        
        this.onSubmit(null, null, handler);
    },

    onResetDefaults: function(){
        var tab = this.getActiveTab(),
            type,
            msg;
        if(tab.title === "Toolbar and Grid Settings"){
            type = 'tbar';
            msg = 'All grid and toolbar button customizations on this page will be deleted, continue?';
        } else if(tab.title === "Actions"){
            type = 'actions';
            msg = 'All action customizations on this page will be deleted, continue?';
        }

        var requestConfig = {
            url: LABKEY.ActionURL.buildURL('filecontent', 'resetFileOptions', null, {type:type}),
            method: 'POST',
            success: function(response){
                this.onCancel();
            },
            failure: function(response){
                var json = Ext4.JSON.decode(response.responseText);
                console.log(json);
            },
            scope: this
        };

        Ext4.Msg.show({
            title: 'Confirm Reset',
            msg: msg,
            buttons: Ext4.Msg.YESNO,
            icon: Ext4.Msg.QUESTION,
            fn: function(choice){
                if(choice === 'yes'){
                    Ext4.Ajax.request(requestConfig);
                }
            }
        });
    }
});
