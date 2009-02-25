/*
 * Copyright (c) 2007-2009 LabKey Corporation
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

package org.labkey.api.study.assay;

import org.labkey.api.exp.OntologyManager;
import org.labkey.api.exp.ObjectProperty;

import java.util.Map;
import java.sql.SQLException;

/**
 * User: jeckels
 * Date: Jul 23, 2007
 */
public class SimpleAssayDataImportHelper implements OntologyManager.ImportHelper
{
    private int _id = 0;
    private String _dataLSID;
    public SimpleAssayDataImportHelper(String dataLSID)
    {
        _dataLSID = dataLSID;
    }

    public String beforeImportObject(Map<String, Object> map) throws SQLException
    {
        return _dataLSID + ".DataRow-" + _id++;
    }

    public void afterImportObject(String lsid, ObjectProperty[] props) throws SQLException
    {

    }
}
