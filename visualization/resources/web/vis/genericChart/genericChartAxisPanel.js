/*
 * Copyright (c) 2012-2016 LabKey Corporation
 *
 * Licensed under the Apache License, Version 2.0: http://www.apache.org/licenses/LICENSE-2.0
 */
Ext4.define('LABKEY.vis.GenericChartAxisPanel', {

    extend : 'LABKEY.vis.GenericOptionsPanel',

    border: false,

    axisName: null,
    multipleCharts: false,
    isSavedReport: false,

    initComponent : function()
    {
        this.userEditedLabel = this.isSavedReport;

        this.axisLabelField =  Ext4.create('Ext.form.field.Text', {
            name: 'label',
            fieldLabel: 'Label',
            enableKeyEvents: true,
            width: 360
        });

        this.axisLabelField.addListener('keyup', function(){
            this.userEditedLabel = this.axisLabelField.getValue() != '';
        }, this, {buffer: 500});

        this.scaleTypeRadioGroup = Ext4.create('Ext.form.RadioGroup', {
            fieldLabel: 'Scale Type',
            columns: 2,
            width: 250,
            layoutOptions: ['point', 'time'],
            items: [
                Ext4.create('Ext.form.field.Radio', {
                    boxLabel: 'Linear',
                    inputValue: 'linear',
                    name: 'scaleType',
                    checked: 'true'
                }),
                Ext4.create('Ext.form.field.Radio', {
                    boxLabel: 'Log',
                    inputValue: 'log',
                    name: 'scaleType'
                })
            ]
        });

        this.scaleRangeMinField = Ext4.create('Ext.form.field.Number', {
            name: 'rangeMin',
            emptyText: 'Min',
            style: 'margin-right: 10px',
            width: 85,
            disabled: true
        });

        this.scaleRangeMaxField = Ext4.create('Ext.form.field.Number', {
            name: 'rangeMax',
            emptyText: 'Max',
            width: 85,
            disabled: true
        });

        this.scaleRangeRadioGroup = Ext4.create('Ext.form.RadioGroup', {
            fieldLabel: 'Range',
            columns: 1,
            vertical: true,
            submitEmptyText: false,
            padding: '0 0 10px 0',
            items: [{
                    boxLabel: 'Automatic' + (this.multipleCharts ? ' Across Charts' : ''),
                    name: 'scale',
                    inputValue: 'automatic',
                    checked: true
                },{
                    boxLabel: 'Automatic Within Chart',
                    name: 'scale',
                    inputValue: 'automatic_per_chart',
                    hidden: !this.multipleCharts
                },
                {
                    xtype: 'container',
                    layout: 'hbox',
                    items: [
                        {
                            xtype: 'radio',
                            boxLabel: 'Manual',
                            name: 'scale',
                            inputValue: 'manual',
                            style: 'margin-right: 10px'
                        },
                        this.scaleRangeMinField,
                        this.scaleRangeMaxField
                    ]
                }
            ],
            listeners: {
                scope: this,
                change: function(rg, newValue)
                {
                    var isAutomatic = newValue.scale != 'manual';
                    this.scaleRangeMinField.setDisabled(isAutomatic);
                    this.scaleRangeMaxField.setDisabled(isAutomatic);
                    if (isAutomatic)
                    {
                        this.scaleRangeMinField.setValue(null);
                        this.scaleRangeMaxField.setValue(null);
                    }
                }
            }
        });

        this.timeAxisIntervalCombo = Ext4.create('Ext.form.field.ComboBox', {
            //name: 'interval',
            //getInputValue: this.getTimeAxisInterval,
            fieldLabel: 'Time Interval',
            store: Ext4.create('Ext.data.ArrayStore', {
                fields: ['value'],
                data: [['Days'], ['Weeks'], ['Months'], ['Years']]
            }),
            width: 200,
            padding: '0 0 10px 0',
            layoutOptions: 'time',
            queryMode: 'local',
            editable: false,
            forceSelection: true,
            displayField: 'value',
            valueField: 'value',
            value: 'Days'
        });

        this.items = this.getInputFields();
        
        this.callParent();
    },

    getInputFields : function()
    {
        return [
            this.axisLabelField,
            this.scaleTypeRadioGroup,
            this.scaleRangeRadioGroup
        ];
    },

    getDefaultLabel: function(){
        var label;
        if(this.measure) {
            label = this.measure.label;
        } else {
            label = this.queryName;
        }
        return label;
    },

    getPanelOptionValues: function()
    {
        return {
            label: this.getAxisLabel(),
            scaleTrans: this.getScaleType(),
            scaleRangeType: this.getScaleRangeType(),
            scaleRange: this.getScaleRange()
        };
    },

    setPanelOptionValues: function(config)
    {
        if (!Ext4.isDefined(config))
            return;

        if (config.label)
            this.setAxisLabel(config.label);

        if (config.trans)
            this.setScaleTrans(config.trans);
        else if (config.scaleTrans)
            this.setScaleTrans(config.scaleTrans);

        if (config.interval)
            this.setTimeAxisInterval(config.interval);

        this.setScaleRange(config);
    },

    getAxisLabel: function(){
        return this.axisLabelField.getValue();
    },

    setAxisLabel: function(value){
        this.axisLabelField.setValue(value);
    },

    getScaleType: function(){
        return this.scaleTypeRadioGroup.getValue().scaleType;
    },

    getScaleRangeType: function() {
        return this.scaleRangeRadioGroup.getValue().scale;
    },

    setScaleRangeType: function(value) {
        this.scaleRangeRadioGroup.setValue(value);
        var radioComp = this.getScaleRangeTypeRadioByValue(value);
        if (radioComp)
            radioComp.setValue(true);
    },

    getScaleRangeTypeRadioByValue: function(value) {
        return this.scaleRangeRadioGroup.down('radio[inputValue="' + value + '"]');
    },

    getScaleRange: function () {
        var range = {};
        range.min = this.scaleRangeMinField.getValue();
        range.max = this.scaleRangeMaxField.getValue();
        return range;
    },

    setScaleRange: function(config)
    {
        var range = config;
        if (Ext4.isObject(config.range))
            range = config.range;
        else if (Ext4.isObject(config.scaleRange))
            range = config.scaleRange;

        var hasMin = range.min != null,
            hasMax = range.max != null;

        if (hasMin)
            this.scaleRangeMinField.setValue(range.min);
        if (hasMax)
            this.scaleRangeMaxField.setValue(range.max);

        if (Ext4.isString(range.type))
            this.setScaleRangeType(range.type);
        else if (Ext4.isString(range.scaleRangeType))
            this.setScaleRangeType(range.scaleRangeType);
        else
            this.setScaleRangeType(hasMin || hasMax ? 'manual' : 'automatic');
    },

    setScaleTrans: function(value){
        this.scaleTypeRadioGroup.setValue(value);
        var radioComp = this.scaleTypeRadioGroup.down('radio[inputValue="' + value + '"]');
        if (radioComp)
            radioComp.setValue(true);
    },

    getTimeAxisInterval: function(){
        return this.timeAxisIntervalCombo.getValue();
    },

    setTimeAxisInterval: function(value){
        this.timeAxisIntervalCombo.setValue(value);
    },

    validateManualScaleRange: function() {
        var range = this.getScaleRange();

        if (range.min != null || range.max != null)
            if (range.min != null && range.max != null && range.min >= range.max) {
                this.scaleRangeMinField.markInvalid("Value must be a number less than the Max");
                this.scaleRangeMaxField.markInvalid("Value must be a number greater than the Min");
                return false;
            } else {
                return true;
            }
        else {
            this.scaleRangeMinField.markInvalid("Value must be a number less than the Max");
            this.scaleRangeMaxField.markInvalid("Value must be a number greater than the Min");
        }
    },

    adjustScaleOptions: function(isNumeric)
    {
        //disable for non-numeric types
        this.scaleRangeRadioGroup.hideForDatatype = !isNumeric;
        this.scaleTypeRadioGroup.hideForDatatype = !isNumeric;
    },

    validateChanges : function ()
    {
        if (this.getScaleRangeType() == 'manual') {
            return this.validateManualScaleRange();
        }
        return true; //else automatic scale, which is valid
    },

    onMeasureChange : function(measures, renderType)
    {
        if (renderType == 'time_chart')
            this.onMeasureChangeTimeChart(measures);
        else
            this.onMeasureChangesGenericChart(measures, renderType);
    },

    onMeasureChangeTimeChart : function(measures)
    {
        // special case for x-xis: no label change and always hide log/linear
        if (this.axisName == 'x')
        {
            var isVisitBased = measures.time == 'visit';
            this.adjustScaleOptions(false);
            this.scaleRangeRadioGroup.hideForDatatype = isVisitBased;
        }
        else
        {
            this.adjustScaleOptions(true);

            var side = this.axisName == 'y' ? 'left' : 'right';
            if (!this.userEditedLabel)
                this.setAxisLabel(LABKEY.vis.TimeChartHelper.getMeasuresLabelBySide(measures.y, side));
        }
    },

    onMeasureChangesGenericChart : function(measures, renderType)
    {
        var properties = measures[this.axisName],
            type = LABKEY.vis.GenericChartHelper.getMeasureType(properties),
            isNumeric = LABKEY.vis.GenericChartHelper.isNumericType(type);

        this.adjustScaleOptions(isNumeric);

        if (!this.userEditedLabel)
        {
            if (Ext4.isDefined(properties))
                this.setAxisLabel(LABKEY.vis.GenericChartHelper.getSelectedMeasureLabel(renderType, this.axisName, properties));
            else
                this.setAxisLabel('');
        }
    },

    onChartLayoutChange : function(multipleCharts)
    {
        var automaticRadio = this.getScaleRangeTypeRadioByValue('automatic'),
                automaticPerChartRadio = this.getScaleRangeTypeRadioByValue('automatic_per_chart');

        automaticRadio.setBoxLabel(multipleCharts ? 'Automatic Across Charts' : 'Automatic');
        automaticPerChartRadio.setVisible(multipleCharts);
        if (automaticPerChartRadio.checked && automaticPerChartRadio.isHidden())
            this.setScaleRangeType('automatic');
    }
});
