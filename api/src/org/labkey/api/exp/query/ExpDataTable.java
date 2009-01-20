/*
 * Copyright (c) 2006-2009 LabKey Corporation
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

package org.labkey.api.exp.query;

import org.labkey.api.data.ColumnInfo;
import org.labkey.api.exp.api.*;

public interface ExpDataTable extends ExpTable<ExpDataTable.Column>
{
    static final public String COLUMN_ROWID = "exp.data.rowid";
    enum Column
    {
        RowId,
        LSID,
        Name,
        Protocol,
        DataFileUrl,
        Run,
        Created,
        Folder,
        Flag,
        DownloadLink,
        ContentLink,
        ViewFileLink,
        Thumbnail,
    }

    void setExperiment(ExpExperiment experiment);
    ExpExperiment getExperiment();
    void setRun(ExpRun run);
    ExpRun getRun();
    
    void setDataType(DataType type);
    DataType getDataType();

    ColumnInfo addMaterialInputColumn(String alias, SamplesSchema schema, String inputRole, ExpSampleSet sampleSet);
    ColumnInfo addDataInputColumn(String alias, String role);
    ColumnInfo addInputRunCountColumn(String alias);
}
