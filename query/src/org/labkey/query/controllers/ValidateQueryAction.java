/*
 * Copyright (c) 2009-2012 LabKey Corporation
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

package org.labkey.query.controllers;

import org.apache.commons.lang3.StringUtils;
import org.labkey.api.action.ApiAction;
import org.labkey.api.action.ApiResponse;
import org.labkey.api.action.ApiSimpleResponse;
import org.labkey.api.action.SpringActionController;
import org.labkey.api.data.TableInfo;
import org.labkey.api.query.QueryForm;
import org.labkey.api.query.UserSchema;
import org.labkey.api.security.RequiresPermissionClass;
import org.labkey.api.security.permissions.ReadPermission;
import org.labkey.query.persist.QueryManager;
import org.springframework.validation.BindException;
import org.springframework.validation.Errors;

/**
 * Created by IntelliJ IDEA.
 * User: dave
 * Date: Aug 4, 2009
 * Time: 5:17:26 PM
 */

@RequiresPermissionClass(ReadPermission.class)
public class ValidateQueryAction extends ApiAction<ValidateQueryAction.ValidateQueryForm>
{
    UserSchema schema;
    TableInfo table;

    @Override
    public void validateForm(ValidateQueryForm form, Errors errors)
    {
        if (null == StringUtils.trimToNull(form.getSchemaName()))
            errors.rejectValue("schemaName", SpringActionController.ERROR_REQUIRED, "schemaName parameter is required");

        if (null == StringUtils.trimToNull(form.getQueryName()))
            errors.rejectValue("queryName", SpringActionController.ERROR_REQUIRED, "queryName parameter is required");

        if (errors.hasErrors())
            return;

        schema = form.getSchema();
        if (null == schema)
        {
            errors.reject(SpringActionController.ERROR_MSG, "Schema not found: " + form.getSchemaName());
            return;
        }

        table = schema.getTable(form.getQueryName());
        if (null == table)
        {
            errors.reject(SpringActionController.ERROR_MSG, "Query not found: " + form.getQueryName());
            return;
        }
    }


    public ApiResponse execute(ValidateQueryForm form, BindException errors) throws Exception
    {
        QueryManager.get().validateQuery(table, form.isIncludeAllColumns());

        //if we got here, the query is OK
        return new ApiSimpleResponse("valid", true);
    }


    public static class ValidateQueryForm extends QueryForm
    {
        private boolean _includeAllColumns = true;

        public boolean isIncludeAllColumns()
        {
            return _includeAllColumns;
        }

        public void setIncludeAllColumns(boolean includeAllColumns)
        {
            _includeAllColumns = includeAllColumns;
        }
    }
}
