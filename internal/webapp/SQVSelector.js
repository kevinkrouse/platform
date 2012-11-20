/*
 * Copyright (c) 2012 LabKey Corporation
 *
 * Licensed under the Apache License, Version 2.0: http://www.apache.org/licenses/LICENSE-2.0
 */
/**
 * Created with IntelliJ IDEA.
 * User: Rylan
 * Date: 10/31/12
 * Time: 10:51 AM
 * To change this template use File | Settings | File Templates.
 */

LABKEY.requiresExt4ClientAPI(true);

Ext4.define('LABKEY.SQVModel', {
    extend : 'Ext.Component',

    constructor: function(config){
        this.schemaCombo = config.schemaCombo;
        this.queryCombo = config.queryCombo;
        this.viewCombo = config.viewCombo;

         //Store and model for the schemaCombo
        Ext4.define('schemaModel', {
            extend : 'Ext.data.Model',
            fields : [{
                name : 'schema'
            }]
        });

        //Store and model for the queryCombo
        Ext4.define('queryModel', {
            extend : 'Ext.data.Model',
            fields : [
                {name : 'isUserDefined', type : 'boolean'},
                {name : 'name',          type : 'string'},
                {name : 'viewDataURL',   type : 'string'},
                {name : 'listId',        type : 'string'}
            ]
        })

        this.queryStore = Ext4.create('Ext.data.Store', {
            model : 'queryModel'
        });

        //Store and model for the viewCombo
        Ext4.define('viewModel', {
            extend : 'Ext.data.Model',
            fields : [
                {name : 'default',      type : 'boolean'},
                {name : 'name',         type : 'string'},
                {name : 'viewDataUrl',  type : 'string'}
            ]
        });

        this.viewStore = Ext4.create('Ext.data.Store', {
            model : 'viewModel'
        });


        this.callParent([config]);
    },

    getSchemaStore : function() {
        if (this.schemaStore) {
            return this.schemaStore;
        }

        this.schemaStore = Ext4.create('Ext.data.Store', {
            model : 'schemaModel'
        });

        var me = this;

        //This is called here rather than in a function because it never requires changing.
        LABKEY.Query.getSchemas({
            success : function(schemasInfo){
                var schemaData = schemasInfo,
                    arrayedData = [];
                for(var i = 0; i < schemaData.schemas.length; i++){
                    schemaData.schema[i].name = Ext4.htmlEncode(schemaData.schema[i].name);
                }
                for(var i = 0; i < schemaData.schemas.length; i++){
                    arrayedData.push([schemaData.schemas[i]]);
                }
                schemaData = arrayedData;
                me.schemaStore.loadData(arrayedData);
            }
        });

        return this.schemaStore;
    },

        //Makes the configuration for a schemaCombo.  NOTE:  Does not set its own value of SchemaCombo to this one,
        //so you still need to add it after at present.
        makeSchemaComboConfig : function(config) {
            return {
                xtype : 'combo',
                name : config.name || 'schemaCombo',
                queryMode : 'local',
                store : this.getSchemaStore(),
                fieldLabel : config.fieldLabel || 'Schema',
                valueField : 'schema',
                displayField : 'schema',
                editable : false,
                listeners : {
                    afterrender : function(cb) {
                        this.schemaCombo = cb;
                    },
                    select :  function(cb){
                        if(this.queryCombo){
                            this.changeQueryStore(cb.getRawValue());
                        }
                    },
                    scope : this
                },
                scope : this
            }
        },

        makeQueryComboConfig : function(config){
             return {
                 xtype : 'combo',
                 name : config.name || 'queryCombo',
                 defaultSchema : config.defaultSchema,
                 queryMode : 'local',
                 fieldLabel : config.fieldLabel || config.defaultSchema || 'Query',
                 valueField : config.valueField || 'name',
                 displayField : 'name',
                 initialValue : config.initialValue,
                 store : this.queryStore,
                 editable : false,
                 disabled : true,
                 listeners : {
                     scope : this,
                     afterrender : function(cb) {
                         this.queryCombo = cb;
                         if(cb.defaultSchema){
                             this.changeQueryStore(cb.defaultSchema);
                             cb.fieldLabel = cb.defaultSchema;
                         }
                     },
                     select :  function(cb){
                         var schema = "";
                         if(cb.defaultSchema){
                            schema = cb.defaultSchema;
                         }
                         else if(this.schemaCombo){
                             schema = this.schemaCombo.getRawValue();
                         }

                         if(schema != "" && cb.getRawValue() != "") {
                            this.changeViewStore(schema, cb.getRawValue());
                         }
                     },
                     dataloaded : function(cb){
                         if(!this.initallyLoaded){
                           this.initiallyLoaded = true;
                           if(cb.initialValue){
                               cb.select(cb.findRecord(cb.valueField, cb.initialValue).data.name);
                               cb.setValue(cb.initialValue);
                               cb.fireEvent('select', cb);
                           }
                         }
                     }
                 },
                 scope : this
             }
        },

        makeViewComboConfig : function(config){
            return {
                xtype : 'combo',
                name : config.name || 'viewCombo',
                initialValue : config.initialValue,
                queryMode : 'local',
                fieldLabel : config.fieldLabel || 'View',
                valueField : 'name',
                displayField : 'name',
                disabled : true,
                editable : false,
                store : this.viewStore,
                listeners : {
                    afterrender : function(cb) {
                        this.viewCombo = cb;
                    },
                    dataloaded : function(cb){
                        xx = cb;
                        if(!cb.initiallyLoaded){
                            cb.initiallyLoaded = true;
                            if(cb.initialValue && cb.initialValue != ''){
                                cb.select(cb.findRecord(cb.displayField, cb.initialValue));
                            }
                        }

                    },
                    scope : this
                },
                scope : this
            }
        },

        changeQueryStore : function(selectedSchema){
            this.queryCombo.setDisabled(false);
            this.queryCombo.clearValue();
            if(this.viewCombo){
                this.viewCombo.setDisabled(true);
                this.viewCombo.clearValue();
            }

            var me = this;
            LABKEY.Query.getQueries({
                schemaName : selectedSchema,
                success : function(details) {
                    for(var i = 0; i < details.queries.length; i++){
                        details.queries[i].name = Ext4.htmlEncode(details.queries[i].name);
                    }
                    var newQueries = details.queries;
                    for (var q=0; q < newQueries.length; q++) {
                        var params = LABKEY.ActionURL.getParameters(newQueries[q].viewDataUrl);
                        if (params[me.queryCombo.valueField]) {
                            newQueries[q][me.queryCombo.valueField] = params.listId;
                        }
                    }
                    this.queryStore.loadData(newQueries);
                    console.log("Fire.");
                    this.queryCombo.fireEvent('dataloaded', this.queryCombo);
                },
                scope : this
            });
        },

        changeViewStore : function(selectedSchema, selectedQuery){
            this.viewCombo.setDisabled(false);
            this.viewCombo.clearValue();
            LABKEY.Query.getQueryViews({
                scope : this,
                schemaName : selectedSchema,
                queryName : selectedQuery,
                successCallback : function(details){
                    for(var i = 0; i < details.views.length; i++){
                        details.views[i].name = Ext4.htmlEncode(details.views[i].name);
                    }
                    for(var i = 0; i < details.views.length; i++){
                        if(details.views[i].name == ""){
                            details.views[i].name = "[default view]";
                        }
                        if(details.views[i].default == true && details.views[i].name != "[default view]"){
                            details.views[i].name += " [default]";
                        }
                    }
                    this.viewStore.loadData(details.views);
                    this.viewCombo.fireEvent('dataloaded', this.viewCombo);
                }
            });
        }

});

Ext4.define('LABKEY.SQVPicker', {
    extend : 'Ext.Panel',

    constructor : function(config){
        this.border = false;
        this.callParent([config]);
    },

    initComponent : function(){

        var sqvModel = Ext4.create('LABKEY.SQVModel', {});

        var schemaCombo = Ext4.create('Ext.form.field.ComboBox', sqvModel.makeSchemaComboConfig({}));
        var queryCombo = Ext4.create('Ext.form.field.ComboBox', sqvModel.makeQueryComboConfig({}));
        var viewCombo = Ext4.create('Ext.form.field.ComboBox', sqvModel.makeViewComboConfig({}));

        this.items = [schemaCombo, queryCombo, viewCombo];

        this.callParent();
    }
});
