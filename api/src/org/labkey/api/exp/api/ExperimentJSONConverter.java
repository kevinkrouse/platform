/*
 * Copyright (c) 2009 LabKey Corporation
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
package org.labkey.api.exp.api;

import org.json.JSONObject;
import org.json.JSONArray;
import org.labkey.api.exp.property.DomainProperty;
import org.labkey.api.exp.property.Domain;

import java.sql.SQLException;

/**
 * User: jeckels
 * Date: Jan 21, 2009
 */
public class ExperimentJSONConverter
{
    // General experiment object properties
    public static final String ID = "id";
    public static final String CREATED = "created";
    public static final String CREATED_BY = "createdBy";
    public static final String MODIFIED = "modified";
    public static final String MODIFIED_BY = "modifiedBy";
    public static final String NAME = "name";
    public static final String LSID = "lsid";
    public static final String PROPERTIES = "properties";
    public static final String COMMENT = "comment";
    public static final String DATA_FILE_URL = "dataFileURL";

    // Run properties
    public static final String DATA_INPUTS = "dataInputs";

    public static JSONObject serializeRunGroup(ExpExperiment runGroup, Domain domain) throws SQLException
    {
        JSONObject jsonObject = serializeStandardProperties(runGroup, domain);
        jsonObject.put(COMMENT, runGroup.getComments());
        return jsonObject;
    }

    public static JSONObject serializeRun(ExpRun run, Domain domain) throws SQLException
    {
        JSONObject jsonObject = serializeStandardProperties(run, domain);
        jsonObject.put(COMMENT, run.getComments());

        JSONArray inputDataArray = new JSONArray();
        for (ExpData data : run.getDataInputs().keySet())
        {
            inputDataArray.put(ExperimentJSONConverter.serializeData(data));
        }
        jsonObject.put(DATA_INPUTS, inputDataArray);
        return jsonObject;
    }


    public static JSONObject serializeStandardProperties(ExpObject object, Domain domain)
    {
        JSONObject jsonObject = new JSONObject();

        // Standard properties on all experiment objects
        jsonObject.put(NAME, object.getName());
        jsonObject.put(LSID, object.getLSID());
        jsonObject.put(ID, object.getRowId());
        if (object.getCreatedBy() != null)
        {
            jsonObject.put(CREATED_BY, object.getCreatedBy().getEmail());
        }
        jsonObject.put(CREATED, object.getCreated());
        if (object.getModifiedBy() != null)
        {
            jsonObject.put(MODIFIED_BY, object.getModifiedBy().getEmail());
        }
        jsonObject.put(MODIFIED, object.getModified());
        String comment = object.getComment();
        if (comment != null)
            jsonObject.put(COMMENT, object.getComment());

        // Add the custom properties
        if (domain != null)
        {
            JSONObject propertiesObject = new JSONObject();
            for (DomainProperty dp : domain.getProperties())
            {
                propertiesObject.put(dp.getName(), object.getProperty(dp));
            }
            jsonObject.put(PROPERTIES, propertiesObject);
        }

        return jsonObject;
    }


    public static JSONObject serializeData(ExpData data)
    {
        JSONObject jsonObject = serializeStandardProperties(data, null);
        jsonObject.put(DATA_FILE_URL, data.getDataFileUrl());
        return jsonObject;
    }
}