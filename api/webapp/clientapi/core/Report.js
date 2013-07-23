/**
 * @fileOverview
 * @author <a href="https://www.labkey.org">LabKey Software</a> (<a href="mailto:info@labkey.com">info@labkey.com</a>)
 * @license Copyright (c) 2012-2013 LabKey Corporation
 * <p/>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p/>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p/>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * <p/>
 */

/**
 * @namespace Report static class that allows programmatic manipulation of reports and their underlying engines.
 */
LABKEY.Report = new function(){
    /**
     * Private function to decode json output parameters into objects
     * @param config
     * @return {Mixed}
     */
    function getExecuteSuccessCallbackWrapper(callbackFn, scope)
    {
        return LABKEY.Utils.getCallbackWrapper(function(data, response, options){
            if (data && data.outputParams) {
                for (var idx = 0; idx < data.outputParams.length; idx++) {
                    var param = data.outputParams[idx];
                    if (param.type == 'json') {
                        param.value = LABKEY.ExtAdapter.decode(param.value);
                    }
                }
            }
            if (callbackFn)
                callbackFn.call(scope || this, data, options, response);
        }, this);
    }

    //public interface
    /** @scope LABKEY.Report */
    return {
        /**
         * Creates a new report session which can be used across multiple report requests.  For example,
         * this allows an R script to setup an R environment and then use this environment in
         * subsequent R scripts.
         * @param {Object} config A configuration object with the following properties.
         * @param {Object} config.clientContext Client supplied identifier returned in a call to getSessions()
         * @param {Function} config.success The function to call with the resulting information.
         * This function will be passed a single parameter of type object, which will have the following
         * properties:
         * <ul>
         *  <li>reportSessionId: A unique identifier that represents the new underlying report session, a String</li>
         * </ul>
         * @param {Function} [config.failure] A function to call if an error occurs. This function
         * will receive one parameter of type object with the following properites:
         * <ul>
         *  <li>exception: The exception message.</li>
         * </ul>
         * @param {String} [config.containerPath] The container in which to make the request (defaults to current container)
         * @param {Object} [config.scope] The scope to use when calling the callbacks (defaults to this).
         */
        createSession : function(config) {
            var containerPath = config && config.containerPath;
            var createParams = {};
            createParams["clientContext"] = config.clientContext;

            LABKEY.Ajax.request({
                url: LABKEY.ActionURL.buildURL("reports", "createSession", containerPath ),
                method: 'POST',
                success: LABKEY.Utils.getCallbackWrapper(LABKEY.Utils.getOnSuccess(config), config.scope),
                failure: LABKEY.Utils.getCallbackWrapper(LABKEY.Utils.getOnFailure(config), config.scope, true),
                jsonData : createParams
            });
        },

        /**
         * Deletes an underlying report session
         *
         * @param {Object} config A configuration object with the following properties.
         * @param {String} config.reportSessionId Identifier for the report session to delete.
         * @param {Function} config.success The function to call if the operation is successful.
         * @param {Function} [config.failure] A function to call if an error occurs. This function
         * will receive one parameter of type object with the following properites:
         * <ul>
         *  <li>exception: The exception message.</li>
         * </ul>
         * @param {String} [config.containerPath] The container in which to make the request (defaults to current container)
         * @param {Object} [config.scope] The scope to use when calling the callbacks (defaults to this).
         */
        deleteSession : function(config) {
            var params = { reportSessionId : config.reportSessionId };
            LABKEY.Ajax.request({
                url: LABKEY.ActionURL.buildURL("reports", "deleteSession", config.containerPath),
                method: 'POST',
                params: params,
                success: LABKEY.Utils.getCallbackWrapper(LABKEY.Utils.getOnSuccess(config), config.scope),
                failure: LABKEY.Utils.getCallbackWrapper(LABKEY.Utils.getOnFailure(config), config.scope, true)
            });
        },

        /**
         * Returns a list of report sessions created via createSession
         *
         * @param {Object} config A configuration object with the following properties.
         * @param {Function} config.success The function to call if the operation is successful.  This function will
         * receive an object with the following properties
         * <ul>
         *     <li>reportSessions:  a reportSession[] of any sessions that have been created by the client
         * </ul>
         *
         * @param {Function} [config.failure] A function to call if an error occurs. This function
         * will receive one parameter of type object with the following properites:
         * <ul>
         *  <li>exception: The exception message.</li>
         * </ul>
         * @param {String} [config.containerPath] The container in which to make the request (defaults to current container)
         * @param {Object} [config.scope] The scope to use when calling the callbacks (defaults to this).
         */
        getSessions : function(config) {
            LABKEY.Ajax.request({
                url: LABKEY.ActionURL.buildURL("reports", "getSessions", config.containerPath),
                method: 'POST',
                success: LABKEY.Utils.getCallbackWrapper(LABKEY.Utils.getOnSuccess(config), config.scope),
                failure: LABKEY.Utils.getCallbackWrapper(LABKEY.Utils.getOnFailure(config), config.scope, true)
            });
        },

        /**
         * Executes a report script
         *
         * @param {Object} config A configuration object with the following properties.
         * @param {String} [config.containerPath] The container in which to make the request (defaults to current container)
         * @param {Object} [config.scope] The scope to use when calling the callbacks (defaults to this).
         * @param {String} config.reportId Identifier for the report to execute
         * @param {String} [config.reportSessionId] Execute within the existsing report session.
         * @param {String} [config.inputParams] An object with properties for input parameters.
         * @param {Function} config.success The function to call if the operation is successful.  This function will
         * receive an object with the following properties
         * <ul>
         *     <li>console:  a string[] of information written by the script to the console</li>
         *     <li>error:  any exception thrown by the script that halted execution</li>
         *     <li>ouputParams:  an outputParam[] of any output parameters (imgout, jsonout, etc) returned by the script</li>
         * </ul>
         * @param {Function} [config.failure] A function to call if an error preventing script execution occurs.
         * This function will receive one parameter of type object with the following properites:
         * <ul>
         *  <li>exception: The exception message.</li>
         * </ul>
         */
        execute : function(config) {
            if (!config)
                throw "You must supply a config object to call this method.";

            if (!config.reportId)
                throw "You must supply a value for the reportId config property.";

            var execParams = {};

            // bind client input params to our parameter map
            for (var key in config.inputParams)
            {
                execParams["inputParams[" + key + "]"] = config.inputParams[key];
            }

            // must have a script id  by now, the scriptId is the reportId
            execParams["reportId"] = config.reportId;

            // optional session id
            if (config.reportSessionId)
            {
                execParams["reportSessionId"] = config.reportSessionId;
            }

            return LABKEY.Ajax.request({
                url: LABKEY.ActionURL.buildURL("reports", "execute", config.containerPath),
                method: 'POST',
                success: getExecuteSuccessCallbackWrapper(LABKEY.Utils.getOnSuccess(config), config.scope),
                failure: LABKEY.Utils.getCallbackWrapper(LABKEY.Utils.getOnFailure(config), config.scope, true),
                jsonData : execParams
            });
        }
    };
};
