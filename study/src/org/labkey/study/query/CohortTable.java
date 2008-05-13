package org.labkey.study.query;

import org.labkey.api.query.FilteredTable;
import org.labkey.study.StudySchema;

/**
 * Copyright (c) 2008 LabKey Corporation
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
 * User: brittp
 * Created: Jan 18, 2008 12:53:27 PM
 */
public class CohortTable extends StudyTable
{
    public CohortTable(StudyQuerySchema schema)
    {
        super(schema, StudySchema.getInstance().getTableInfoCohort());
        addWrapColumn(_rootTable.getColumn("Label"));
        addWrapColumn(_rootTable.getColumn("RowId")).setIsHidden(true);
    }
}
