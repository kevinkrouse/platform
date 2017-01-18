
LABKEY.ColumnSummaryStatistics = new function ()
{
    /**
     * Used via SummaryStatisticsAnalyticsProvider to show a dialog of the applicable summary statistics for a column in the view.
     * @param dataRegionName
     * @param colFieldKey
     */
    var showDialogFromDataRegion = function(dataRegionName, colFieldKey)
    {
        var region = LABKEY.DataRegions[dataRegionName];
        if (region)
        {
            var regionViewName = region.viewName || "",
                column = region.getColumn(colFieldKey);

            if (column)
            {
                region.getColumnAnalyticsProviders(regionViewName, colFieldKey, function(colSummaryStats)
                {
                    Ext4.create('LABKEY.ext4.ColumnSummaryStatisticsDialog', {
                        queryConfig: region.getQueryConfig(),
                        filterArray: LABKEY.Filter.getFiltersFromUrl(region.selectAllURL, 'query'), //Issue 26594
                        containerPath: region.containerPath,
                        column: column,
                        initSelection: colSummaryStats,
                        listeners: {
                            applySelection: function(win, colSummaryStatsNames)
                            {
                                win.getEl().mask("Applying selection...");
                                region.setColumnSummaryStatistics(regionViewName, colFieldKey, colSummaryStatsNames);
                                win.close();
                            }
                        }
                    }).show();
                });
            }
        }
    };

    return {
        showDialogFromDataRegion: showDialogFromDataRegion
    };
};

Ext4.define('LABKEY.ext4.ColumnSummaryStatisticsDialog', {
    extend: 'Ext.window.Window',

    title: 'Summary Statistics',
    cls: 'summary-stats-dialog',
    bodyStyle: 'padding: 10px;',
    border: false,
    modal: true,
    minWidth: 300,
    minHeight: 200,

    queryConfig: null,
    filterArray: null,
    containerPath: null,
    column: null,
    initSelection: null,
    rowCount: 0,

    constructor : function(config)
    {
        this.callParent([config]);
        this.addEvents('applySelection');
    },

    initComponent : function()
    {
        Ext4.tip.QuickTipManager.init();
        Ext4.apply(Ext4.tip.QuickTipManager.getQuickTip(), {
            minWidth: 150,
            maxWidth: 300,
            showDelay: 100
        });

        if (this.column == null)
            this.column = {};

        if (this.initSelection == null)
            this.initSelection = [];

        // we expect more summary stats for numeric types, so change minHeight accordingly
        var colType = this.column.displayFieldJsonType || this.column.jsonType;
        if (!this.column.isKeyField && (colType.toLowerCase() == 'int' || colType.toLowerCase() == 'float'))
            this.minHeight = this.minHeight + 150;

        this.items = [this.getDialogDescription()];

        this.dockedItems = Ext4.create('Ext.toolbar.Toolbar', {
            xtype: 'toolbar',
            dock: 'bottom',
            ui: 'footer',
            padding: 10,
            items: [
                '->',
                this.getApplyButton(),
                this.getCancelButton()
            ]
        });

        this.callParent();

        this.on('show', this.querySummaryStatResults, this, {single: true});
    },

    getDialogDescription : function()
    {
        if (!this.dialogDescription)
        {
            var queryConfig = this.queryConfig || {},
                viewName = queryConfig.viewName || 'default';

            this.dialogDescription = Ext4.create('Ext.Component', {
                width: 315,
                padding: '0 0 10px 0',
                html: 'Select the summary statistics which you would like to show for the '
                    + '<b>' + Ext4.String.htmlEncode(this.column.caption) + '</b> column in the '
                    + '<b>' + Ext4.String.htmlEncode(viewName) + '</b> view.'
            });
        }

        return this.dialogDescription;
    },

    getParamsFromQueryConfig : function()
    {
        var queryConfig = this.queryConfig || {};

        var params = LABKEY.Query.buildQueryParams(
            queryConfig.schemaName,
            queryConfig.queryName,
            (this.filterArray != null ? this.filterArray : queryConfig.filters),
            null,
            queryConfig.dataRegionName
        );

        if (queryConfig.viewName)
            params[queryConfig.dataRegionName + '.viewName'] = queryConfig.viewName;

        if (queryConfig.containerFilter)
            params.containerFilter = queryConfig.containerFilter;

        if (LABKEY.ActionURL.getParameter(queryConfig.dataRegionName + '.ignoreFilter'))
            params[queryConfig.dataRegionName + '.ignoreFilter'] = true;

        Ext4.Object.each(queryConfig.parameters, function(key, value) {
            params[queryConfig.dataRegionName + '.param.' + key] = value;
        });

        params[queryConfig.dataRegionName + '.columns'] = this.column.fieldKey;
        params[queryConfig.dataRegionName + '.maxRows'] = -1; // ALL

        return params;
    },

    querySummaryStatResults : function()
    {
        this.getEl().mask('Loading...');

        var config = {
            success: this.onSuccess,
            failure: this.onFailure
        };

        LABKEY.Ajax.request({
            url: LABKEY.ActionURL.buildURL('query', 'getColumnSummaryStats.api', this.containerPath),
            method: "POST",
            params: this.getParamsFromQueryConfig(),
            scope: this,
            success: LABKEY.Utils.getCallbackWrapper(LABKEY.Utils.getOnSuccess(config), this),
            failure: LABKEY.Utils.getCallbackWrapper(LABKEY.Utils.getOnFailure(config), this, true)
        });
    },

    onSuccess : function(response)
    {
        if (!response.success)
        {
            this.onFailure(response);
            return;
        }

        this.add(this.getDisplayView(response));
        this.getEl().unmask();
    },

    getDisplayStore : function(response)
    {
        if (!this.displayStore)
        {
            var statRowData = [];
            this.rowCount = 0;

            Ext4.Object.each(response['analyticsProviders'], function(key, val)
            {
                this.rowCount++;

                if (Ext4.isArray(val.aggregates))
                {
                    if (val.aggregates.length == 1)
                    {
                        var result = response['aggregateResults'][val.aggregates[0]];
                        statRowData.push({
                            name: key,
                            label: result.label,
                            description: result.description,
                            value: result.value,
                            checked: this.initSelection.indexOf(key) > -1,
                            altRow: this.rowCount % 2 == 0
                        });
                    }
                    else
                    {
                        var rowData = {
                            name: key,
                            label: val.label,
                            checked: this.initSelection.indexOf(key) > -1,
                            altRow: this.rowCount % 2 == 0
                        };

                        rowData.children = [];
                        Ext4.each(val.aggregates, function(aggName)
                        {
                            var result = response['aggregateResults'][aggName];
                            rowData.children.push({
                                label: result.label,
                                description: result.description,
                                value: result.value
                            });
                        }, this);

                        statRowData.push(rowData);
                    }
                }
            }, this);

            this.displayStore = Ext4.create('Ext.data.Store', {
                model: 'LABKEY.ext4.ColumnSummaryStatisticsModel',
                data: statRowData
            });
        }

        return this.displayStore;
    },

    getDisplayView : function(response)
    {
        if (!this.displayView)
        {
            var store = this.getDisplayStore(response);

            this.displayView = Ext4.create('Ext.view.View', {
                store: store,
                disableSelection: true,
                tpl: new Ext4.XTemplate(
                    '<table class="stat-table">',
                        '<tpl for=".">',
                            '<tr class="row {[this.getAltRowCls(values.altRow)]}">',
                                '<td class="check">',
                                    '<input type="checkbox" name="stat-cb" value="{name}" {[this.getCheckboxState(values.checked)]}/>',
                                '</td>',
                                '<td class="label">{label}',
                                    '{[this.getDescriptionHtml(values)]}',
                                    '{[this.getChildrenLabels(values.children)]}',
                                '</td>',
                                '<td class="value">',
                                    '{[this.getValueHtml(values.value)]}',
                                    '{[this.getChildrenValues(values.children)]}',
                                '</td>',
                            '</tr>',
                        '</tpl>',
                    '</table>',
                    {
                        getAltRowCls: function(altRow)
                        {
                            return altRow ? 'alt-row' : '';
                        },
                        getCheckboxState: function(checked)
                        {
                            return checked ? 'checked' : '';
                        },
                        getDescriptionHtml: function(values)
                        {
                            if (values.description != null && values.description != '')
                                return '<i class="fa fa-question description" data-qtitle="' + values.label + '" data-qtip="' + values.description + '"></i>';

                            return '';
                        },
                        getValueHtml: function(value)
                        {
                            return value != null && value != '' ? Ext4.String.htmlEncode(value) : '&nbsp;';
                        },
                        getChildrenLabels: function(children)
                        {
                            if (Ext4.isArray(children))
                            {
                                var html = '';
                                Ext4.each(children, function(child)
                                {
                                    var descHtml = '';
                                    if (child.description != null && child.description != '')
                                        descHtml = '<i class="fa fa-question description" data-qtitle="' + child.label + '" data-qtip="' + child.description + '"></i>';

                                    html += '<div class="indent">' + Ext4.String.htmlEncode(child.label) + descHtml + '</div>';
                                });
                                return html;
                            }

                            return '';
                        },
                        getChildrenValues: function(children)
                        {
                            if (Ext4.isArray(children))
                            {
                                var html = '';
                                Ext4.each(children, function(child)
                                {
                                    html += '<div>' + Ext4.String.htmlEncode(child.value) + '</div>';
                                });
                                return html;
                            }

                            return '';
                        }
                    }
                )
            });

            this.displayView.on('refresh', this.attachCheckboxClickListeners, this, {single: true});
        }

        return this.displayView;
    },

    attachCheckboxClickListeners : function(view)
    {
        Ext4.each(this.getCheckboxInputs(), function(cb)
        {
            Ext4.get(cb).on('click', this.toggleApplyButtonState, this);
        }, this);
    },

    toggleApplyButtonState : function()
    {
        var dirty = !Ext4.Array.equals(this.initSelection, this.getSelectedStats());
        this.getApplyButton().setDisabled(!dirty);
    },

    getSelectedStats : function()
    {
        var selected = [];
        Ext4.each(this.getCheckboxInputs(), function(cb)
        {
            if (cb.checked)
                selected.push(cb.value);
        }, this);
        return selected;
    },

    getCheckboxInputs : function()
    {
        return Ext4.DomQuery.select('input[name=stat-cb]', this.getDisplayView().getEl().dom);
    },

    onFailure : function(response)
    {
        this.add({
            xtype: 'box',
            cls: 'labkey-error',
            border: false,
            width: 315,
            html: response.exception || response.message
        });

        this.getEl().unmask();
    },

    getApplyButton : function()
    {
        if (!this.applyButton)
        {
            this.applyButton = Ext4.create('Ext.button.Button', {
                text: 'Apply',
                width: 63,
                scope: this,
                disabled: true,
                handler: function()
                {
                    this.fireEvent('applySelection', this, this.getSelectedStats());
                }
            });
        }

        return this.applyButton;
    },

    getCancelButton : function()
    {
        if (!this.cancelButton)
        {
            this.cancelButton = Ext4.create('Ext.button.Button', {
                text: 'Cancel',
                width: 63,
                scope: this,
                handler: function()
                {
                    this.close();
                }
            });
        }

        return this.cancelButton;
    }
});

Ext4.define('LABKEY.ext4.ColumnSummaryStatisticsModel', {
    extend: 'Ext.data.Model',
    fields: [
        {name: 'name'},
        {name: 'label'},
        {name: 'description'},
        {name: 'value'},
        {name: 'altRow'},
        {name: 'checked'},
        {name: 'children'}
    ]
});