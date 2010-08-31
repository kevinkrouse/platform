function getSuccessCallbackWrapper(createMeasureFn, fn, scope)
{
    return function(response, options)
    {
        //ensure response is JSON before trying to decode
        var json = null;
        var measures = null;
        if (response && response.getResponseHeader && response.getResponseHeader('Content-Type')
                && response.getResponseHeader('Content-Type').indexOf('application/json') >= 0)
        {
            json = Ext.util.JSON.decode(response.responseText);
            measures = createMeasureFn(json);
        }

        if(fn)
            fn.call(scope || this, measures, response);
    };
}

LABKEY.Visualization = new function() {

    function formatParams(config)
    {
        var params = {};

        if (config.filters && config.filters.length)
        {
            params['filters'] = config.filters;
        }
        return params;
    }

    /*-- public methods --*/
    /** @scope LABKEY.Visualization */
    return {

        Types : {
            TABULAR : 'tabular',
            EXCEL : 'excel',
            SCATTER : 'scatter',
            TIMEPLOT : 'timeplot'},

        getTypes : function(config) {

            return [LABKEY.Visualization.Types.TABULAR, LABKEY.Visualization.Types.EXCEL, LABKEY.Visualization.Types.SCATTER, LABKEY.Visualization.Types.TIMEPLOT];
        },

        getMeasures : function(config) {

            function createMeasures(json)
            {
                var measures = [];
                if (json.measures && json.measures.length)
                {
                    for (var i=0; i < json.measures.length; i++)
                        measures.push(new LABKEY.Visualization.Measure(json.measures[i]));
                }
                return measures;
            }

            var params = formatParams(config);

            Ext.Ajax.request(
            {
                url : LABKEY.ActionURL.buildURL("reports", "getMeasures"),
                method : 'GET',
                success: getSuccessCallbackWrapper(createMeasures, config.successCallback, config.scope),
                failure: LABKEY.Utils.getCallbackWrapper(config.failureCallback, config.scope, true),
                params : params
            });
        }
    };
};

LABKEY.Visualization.Measure = Ext.extend(Object, {

    constructor : function(config)
    {
        LABKEY.Visualization.Measure.superclass.constructor.call(this, config);
        Ext.apply(this, config);
    },

    getQueryName : function() {
        return this.queryName;
    },

    getSchemaName : function() {
        return this.schemaName;
    },

    isUserDefined : function() {
        return this.isUserDefined;
    },

    getName : function() {
        return this.name;
    },

    getLabel : function() {
        return this.label;
    },

    getType : function() {
        return this.type;
    },

    getDescription : function() {
        return this.description;
    },

    getDimensions : function(config) {

        var params = {query: this.queryName, schema: this.schemaName};

        if (config.includeDemographics)
            params['includeDemographics'] = config.includeDemographics;

        function createDimensions(json)
        {
            var dimensions = [];
            if (json.dimensions && json.dimensions.length)
            {
                for (var i=0; i < json.dimensions.length; i++)
                    dimensions.push(new LABKEY.Visualization.Dimension(json.dimensions[i]));
            }
            return dimensions;
        }

        Ext.Ajax.request(
        {
            url : LABKEY.ActionURL.buildURL("reports", "getDimensions"),
            method : 'GET',
            params : params,
            success: getSuccessCallbackWrapper(createDimensions, config.successCallback, config.scope),
            failure: LABKEY.Utils.getCallbackWrapper(config.failureCallback, config.scope, true)
        });
    }
});

LABKEY.Visualization.Dimension = Ext.extend(Object, {

    constructor : function(config)
    {
        LABKEY.Visualization.Dimension.superclass.constructor.call(this, config);
        Ext.apply(this, config);
    },

    getQueryName : function() {
        return this.query;
    },

    getSchemaName : function() {
        return this.schema;
    },

    isUserDefined : function() {
        return this.isUserDefined;
    },

    getName : function() {
        return this.name;
    },

    getLabel : function() {
        return this.label;
    },

    getType : function() {
        return this.type;
    },

    getDescription : function() {
        return this.description;
    },

    getValues : function(config) {

        var params = {query: this.queryName, schema: this.schemaName, name: this.name};
        function createValues(json)
        {
            if (json.success && json.values)
                return json.values;
            return [];
        }

        Ext.Ajax.request(
        {
            url : LABKEY.ActionURL.buildURL("reports", "getDimensionValues"),
            method : 'GET',
            params : params,
            success: getSuccessCallbackWrapper(createValues, config.successCallback, config.scope),
            failure: LABKEY.Utils.getCallbackWrapper(config.failureCallback, config.scope, true)
        });
    }
});

LABKEY.Visualization.Filter = new function()
{
    function getURLParameterValue(config)
    {
        var params = [config.schema];

        if (config.query)
            params.push(config.query);
        else
            params.push('~');
        
        if (config.queryType)
            params.push(config.queryType);

        return params.join('|');
    }

    return {
        QueryType : {
            BUILT_IN : 'builtIn',
            CUSTOM : 'custom',
            ALL : 'all'
        },

        create : function(config)
        {
            if (!config.schema)
                Ext.Msg.alert("Coding Error!", "You must supply a value for schema in your configuration object!");
            else
                return getURLParameterValue(config);
        }
    };
};