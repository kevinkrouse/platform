/**
 * @fileOverview
 * @author <a href="https://www.labkey.org">LabKey Software</a> (<a href="mailto:info@labkey.com">info@labkey.com</a>)
 * @version 8.3
 * @license Copyright (c) 2008-2009 LabKey Corporation
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
 * @namespace LabKey Security Reporting and Helper class.
 * This class provides several static methods and data members for
 * calling the security-related APIs, and interpreting the results.
 */
LABKEY.Security = new function()
{
    /*-- private methods --*/
    function getCallbackWrapper(fn, scope)
    {
        return function(response, options)
        {
            //ensure response is JSON before trying to decode
            var json = null;
            if(response && response.getResponseHeader && response.getResponseHeader['Content-Type']
                    && response.getResponseHeader['Content-Type'].indexOf('application/json') >= 0)
                json = Ext.util.JSON.decode(response.responseText);

            if(fn)
                fn.call(scope || this, json, response);
        };
    }

    /*-- public methods --*/
    /** @scope LABKEY.Security.prototype */
    return {

        /**
         * A map of the various permission bits supported in the LabKey Server.
         * You can use these values with the hasPermission() method to test if
         * a user or group has a particular permission. The values in this map
         * are as follows:
         * <ul>
         * <li>read</li>
         * <li>insert</li>
         * <li>update</li>
         * <li>del</li>
         * <li>readOwn</li>
         * <li>updateOwn</li>
         * <li>deleteOwn</li>
         * <li>all</li>
         * </ul>
         * For example, to refer to the update permission, the syntax would be:<br/>
         * <pre><code>LABKEY.Security.permissions.update</code></pre>
         */
        permissions : {
            read: 1,
            insert: 2,
            update: 4,
            del: 8,
            readOwn: 16,
            updateOwn: 64,
            deleteOwn: 128,
            admin: 32768,
            all: 65535
        },

        /**
         * A map of the various permission roles exposed in the user interface.
         * The members are as follows:
         * <ul>
         * <li>admin</li>
         * <li>editor</li>
         * <li>author</li>
         * <li>reader</li>
         * <li>restrictedReader</li>
         * <li>noPerms</li>
         * </ul>
         * For example, to refer to the author role, the syntax would be:<br/>
         * <pre><code>LABKEY.Security.roles.author</code></pre>
         */
        roles : {
            admin: 65535,
            editor: 15,
            author: 195,
            reader: 1,
            restrictedReader: 16,
            submitter: 2,
            noPerms: 0
        },

        /**
         * A map of the special system group ids. These ids are assigned by the system
         * at initial startup and are constant across installations. The values in
         * this map are as follows:
         * <ul>
         * <li>administrators</li>
         * <li>users</li>
         * <li>guests</li>
         * <li>developers</li>
         * </ul>
         * For example, to refer to the administrators group, the syntax would be:<br/>
         * <pre><code>LABKEY.Security.systemGroups.administrators</code></pre>
         */
        systemGroups : {
            administrators: -1,
            users: -2,
            guests: -3,
            developers: -4
        },

        /**
         * Get the effective permissions for all groups within the container, optionally
         * recursing down the container hierarchy. This may be called only by
         * users who have administrator permissions in the given container.
         * @param config A configuration object with the following properties:
         * @param {function} config.successCallback A reference to a function to call with the API results. This
         * function will be passed the following parameters:
         * <ul>
         * <li><b>groupPermsInfo:</b> an object containing properties about the container and group permissions.
         * This object will have the following shape:
         *  <ul>
         *  <li>container
         *      <ul>
         *          <li>id: the container id</li>
         *          <li>name: the container name</li>
         *          <li>path: the container path</li>
         *          <li>isInheritingPerms: true if the container is inheriting permissions from its parent</li>
         *          <li>groups: an array of group objects, each of which will have the following properties:
         *              <ul>
         *                  <li>id: the group id</li>
         *                  <li>name: the group's name</li>
         *                  <li>type: the group's type ('g' for group, 'r' for role, 'm' for module-specific)</li>
         *                  <li>roleLabel: a description of the group's permission role. This will correspond
         *                      to the visible labels shown on the permissions page (e.g., 'Admin (all permissions)'.</li>
         *                  <li>role: the group's role value (e.g., 'ADMIN'). Use this property for programmatic checks.</li>
         *                  <li>permissions: The group's effective permissions as a bit mask.
         *                          Use this with the hasPermission() method to test for specific permissions.</li>
         *              </ul>
         *          </li>
         *          <li>children: if includeSubfolders was true, this will contain an array of objects, each of
         *              which will have the same shape as the parent container object.</li>
         *      </ul>
         *  </li>
         * </ul>
         * </li>
         * <li><b>response:</b> The XMLHttpResponse object</li>
         * </ul>
         * @param {function} [config.errorCallback] A reference to a function to call when an error occurs. This
         * function will be passed the following parameters:
         * <ul>
         * <li><b>errorInfo:</b> an object containing detailed error information (may be null)</li>
         * <li><b>response:</b> The XMLHttpResponse object</li>
         * </ul>
         * @param {boolean} [config.includeSubfolders] Set to true to recurse down the subfolders (defaults to false)
         * @param {string} [config.containerPath] An alternate container path to get permissions from. If not specified,
         * the current container path will be used.
         * @param {object} [config.scope] An optional scoping object for the success and error callback functions (default to this).
         */
        getGroupPermissions : function(config)
        {
            if(!config.successCallback)
                Ext.Msg.alert("Programming Error", "You must specify a value for the config.successCallback when calling LABKEY.Security.getGroupPermissions()!");

            var params = {};
            if(config.includeSubfolders != undefined)
                params.includeSubfolders = config.includeSubfolders;

            Ext.Ajax.request({
                url: LABKEY.ActionURL.buildURL("security", "getGroupPerms", config.containerPath),
                method : 'GET',
                params: params,
                success: getCallbackWrapper(config.successCallback, config.scope),
                failure: getCallbackWrapper(config.errorCallback, config.scope)
            });
        },

        /**
         * Returns true if the permission passed in 'perm' is on in the permissions
         * set passed as 'perms'. This is a local function and does not make a call to the server.
         * @param {integer} perms The permission set, typically retrieved for a given user or group.
         * @param {integer} perm A specific permission bit to check for.
         */
        hasPermission : function(perms, perm)
        {
            return perms & perm;
        },

        /**
         * Returns the name of the security role represented by the permissions passed as 'perms'.
         * The return value will be the name of a property in the LABKEY.Security.roles map.
         * This is a local function, and does not make a call to the server.
         * @param perms The permissions set
         */
        getRole : function(perms)
        {
            for(var role in LABKEY.Security.roles)
            {
                if(perms == LABKEY.Security.roles[role])
                    return role;
            }
        },

        /**
         * Returns information about a specific user's permissions within a container. This may be called only by
         * users who have administrator permissions in the given container. To get the current user's permissions
         * in a given container, use the getContainers() method instead.
         * @param config A configuration object containing the following properties
         * @param {integer} config.userId The id of the user.
         * @param {string} config.userEmail The email address (user name) of the user (specify only userId or userEmail, not both)
         * @param {function} config.successCallback A reference to a function to call with the API results. This
         * function will be passed the following parameters:
         * <ul>
         * <li><b>userPermsInfo:</b> an object containing properties about the user's permissions.
         * This object will have the following shape:
         *  <ul>
         *  <li>container: information about the container and the groups the user belongs to in that container
         *      <ul>
         *          <li>id: the container id</li>
         *          <li>name: the container name</li>
         *          <li>path: the container path</li>
         *          <li>roleLabel: a description of the user's permission role in this container. This will correspond
         *               to the visible labels shown on the permissions page (e.g., 'Admin (all permissions)'.</li>
         *          <li>role: the user's role value (e.g., 'ADMIN'). Use this property for programmatic checks.</li>
         *          <li>permissions: The user's effective permissions in this container as a bit mask.
         *               Use this with the hasPermission() method to test for specific permissions.</li>
         *          <li>groups: an array of group objects to which the user belongs, each of which will have the following properties:
         *              <ul>
         *                  <li>id: the group id</li>
         *                  <li>name: the group's name</li>
         *                  <li>roleLabel: a description of the group's permission role. This will correspond
         *                      to the visible labels shown on the permissions page (e.g., 'Admin (all permissions)'.</li>
         *                  <li>role: the group's role value (e.g., 'ADMIN'). Use this property for programmatic checks.</li>
         *                  <li>permissions: The group's effective permissions as a bit mask.
         *                          Use this with the hasPermission() method to test for specific permissions.</li>
         *              </ul>
         *          </li>
         *          <li>children: if includeSubfolders was true, this will contain an array of objects, each of
         *              which will have the same shape as the parent container object.</li>
         *      </ul>
         *  </li>
         *  <li>user: information about the requested user
         *      <ul>
         *          <li>userId: the user's id</li>
         *          <li>displayName: the user's display name</li>
         *      </ul>
         *  </li>
         * </ul>
         * </li>
         * <li><b>response:</b> The XMLHttpResponse object</li>
         * </ul>
         * @param {function} [config.errorCallback] A reference to a function to call when an error occurs. This
         * function will be passed the following parameters:
         * <ul>
         * <li><b>errorInfo:</b> an object containing detailed error information (may be null)</li>
         * <li><b>response:</b> The XMLHttpResponse object</li>
         * </ul>
         * @param {boolean} [config.includeSubfolders] Set to true to recurse down the subfolders (defaults to false)
         * @param {string} [config.containerPath] An alternate container path to get permissions from. If not specified,
         * the current container path will be used.
         * @param {object} [config.scope] An optional scoping object for the success and error callback functions (default to this).
         */
        getUserPermissions : function(config)
        {
            if(!config.successCallback)
                Ext.Msg.alert("Programming Error", "You must specify a value for the config.successCallback when calling LABKEY.Security.getUserPermissions()!");

            var params = {};

            if(config.userId != undefined)
                params.userId = config.userId;
            else if(config.userEmail != undefined)
                params.userEmail = config.userEmail;

            if(config.includeSubfolders != undefined)
                params.includeSubfolders = config.includeSubfolders;

            Ext.Ajax.request({
                url: LABKEY.ActionURL.buildURL("security", "getUserPerms", config.containerPath),
                method : 'GET',
                params: params,
                success: getCallbackWrapper(config.successCallback, config.scope),
                failure: getCallbackWrapper(config.errorCallback, config.scope)
            });
        },

        /**
         * Returns a list of users given selection criteria. This may be called by any logged-in user.
         * @param config A configuration object containing the following properties
         * @param {integer} [config.groupId] The id of a project group for which you want the members.
         * @param {string} [config.group] The name of a project group for which you want the members (specify groupId or group, not both).
         * @param {string} [config.name] The first part of the user name, useful for user name completion. If specified,
         * only users whose email address or display name starts with the value supplied will be returned.
         * @param {function} config.successCallback A reference to a function to call with the API results. This
         * function will be passed the following parameters:
         * <ul>
         * <li><b>usersInfo:</b> an object with the following shape:
         *  <ul>
         *      <li>users: an array of user objects in the following form:
         *          <ul>
         *              <li>userId: the user's id</li>
         *              <li>displayName: the user's display name</li>
         *          </ul>
         *      </li>
         *      <li>container: the path of the requested container</li>
         *  </ul>
         * </li>
         * <li><b>response:</b> The XMLHttpResponse object</li>
         * </ul>
         * @param {function} [config.errorCallback] A reference to a function to call when an error occurs. This
         * function will be passed the following parameters:
         * <ul>
         * <li><b>errorInfo:</b> an object containing detailed error information (may be null)</li>
         * <li><b>response:</b> The XMLHttpResponse object</li>
         * </ul>
         * @param {string} [config.containerPath] An alternate container path to get permissions from. If not specified,
         * the current container path will be used.
         * @param {object} [config.scope] An optional scoping object for the success and error callback functions (default to this).
         */
        getUsers : function(config)
        {
            if(!config.successCallback)
                Ext.Msg.alert("Programming Error", "You must specify a value for the config.successCallback when calling LABKEY.Security.getUsers()!");

            var params = {};
            if(undefined != config.groupId)
                params.groupId = config.groupId;
            else if(undefined != config.group)
                params.group = config.group;

            if(undefined != config.name)
                params.name = config.name;

            Ext.Ajax.request({
                url: LABKEY.ActionURL.buildURL("user", "getUsers", config.containerPath),
                method : 'GET',
                params: params,
                success: getCallbackWrapper(config.successCallback, config.scope),
                failure: getCallbackWrapper(config.errorCallback, config.scope)
            });
        },

        /**
         * Returns information about the specified container, including the user's current permissions within
         * that container. If the includeSubfolders config option is set to true, it will also return information
         * about all descendants the user is allowed to see.
         * @param config A configuration object with the following properties
         * @param {boolean} [config.includeSubfolders] If set to true, the entire branch of containers will be returned.
         * If false, only the immediate children of the starting container will be returned (defaults to false).
         * @param {function} config.successCallback A reference to a function to call with the API results. This
         * function will be passed the following parameters:
         * <ul>
         * <li><b>containersInfo:</b> an object with the following properties:
         *  <ul>
         *      <li>id: the id of the requested container</li>
         *      <li>name: the name of the requested container</li>
         *      <li>path: the path of the requested container</li>
         *      <li>sortOrder: the relative sort order of the requested container</li>
         *      <li>userPermissions: the permissions the current user has in the requested container.
         *          Use this value with the hasPermission() method to test for specific permissions.</li>
         *      <li>children: if the includeSubfolders parameter was true, this will contain
         *          an array of child container objects with the same shape as the parent object.</li>
         *  </ul>
         * </li>
         * <li><b>response:</b> The XMLHttpResponse object</li>
         * </ul>
         * @param {function} [config.errorCallback] A reference to a function to call when an error occurs. This
         * function will be passed the following parameters:
         * <ul>
         * <li><b>errorInfo:</b> an object containing detailed error information (may be null)</li>
         * <li><b>response:</b> The XMLHttpResponse object</li>
         * </ul>
         * @param {string} [config.containerPath] An alternate container path to get permissions from. If not specified,
         * the current container path will be used.
         * @param {object} [config.scope] An optional scoping object for the success and error callback functions (default to this).
         */
        getContainers : function(config)
        {
            if(!config.successCallback)
                Ext.Msg.alert("Programming Error", "You must specify a value for the config.successCallback when calling LABKEY.Security.getContainers()!");

            var params = {};
            if(undefined != config.includeSubfolders)
                params.includeSubfolders = config.includeSubfolders;

            Ext.Ajax.request({
                url: LABKEY.ActionURL.buildURL("project", "getContainers", config.containerPath),
                method : 'GET',
                params: params,
                success: getCallbackWrapper(config.successCallback, config.scope),
                failure: getCallbackWrapper(config.errorCallback, config.scope)
            });
        },

        /**
         * Exposes limited information about the current user. This property returns a JavaScript object
         * with the following properties:
         * <ul>
         * <li>id: the user's unique id number</li>
         * <li>displayName: the user's display name</li>
         * <li>email: the user's email address</li>
         * <li>canInsert: set to true if this user can insert data in the current folder</li>
         * <li>canUpdate: set to true if this user can update data in the current folder</li>
         * <li>canUpdateOwn: set to true if this user can update data this user created in the current folder</li>
         * <li>canDelete: set to true if this user can delete data in the current folder</li>
         * <li>canDeleteOwn: set to true if this user can delete data this user created in the current folder</li>
         * <li>isAdmin: set to true if this user is a system administrator</li>
         * </ul>
         */
        currentUser : LABKEY.user

    };
};