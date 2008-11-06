/*
 * Copyright (c) 2006-2008 LabKey Corporation
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

package org.labkey.experiment.api;

import org.labkey.api.exp.api.ExpProtocolTable;
import org.labkey.api.exp.api.ExpSchema;
import org.labkey.api.data.ColumnInfo;
import org.labkey.api.query.RowIdForeignKey;
import org.labkey.api.query.DetailsURL;
import org.labkey.api.query.QuerySchema;
import org.labkey.api.view.ActionURL;

import java.util.Collections;

public class ExpProtocolTableImpl extends ExpTableImpl<ExpProtocolTable.Column> implements ExpProtocolTable
{
    public ExpProtocolTableImpl(String alias, QuerySchema schema)
    {
        super(alias, ExperimentServiceImpl.get().getTinfoProtocol(), schema);
        setTitleColumn("Name");
    }
    public ColumnInfo createColumn(String alias, Column column)
    {
        switch (column)
        {
            case RowId:
                return wrapColumn(alias, _rootTable.getColumn("RowId"));
            case Name:
                return wrapColumn(alias, _rootTable.getColumn("Name"));
            case LSID:
                return wrapColumn(alias, _rootTable.getColumn("LSID"));
            case Container:
                return wrapColumn(alias, _rootTable.getColumn("Container"));
        }
        throw new IllegalArgumentException("Unknown column " + column);
    }

    public void populate(ExpSchema schema)
    {
        ColumnInfo colRowId = addColumn(Column.RowId);
        colRowId.setIsHidden(true);
        colRowId.setFk(new RowIdForeignKey(colRowId));
        colRowId.setKeyField(true);
        ColumnInfo colName = addColumn(Column.Name);
        setTitleColumn(colName.getName());
        ColumnInfo colLSID = addColumn(Column.LSID);
        colLSID.setIsHidden(true);
        addContainerColumn(Column.Container);
        ActionURL urlDetails = new ActionURL("Experiment", "protocolDetails", schema.getContainer().getPath());
        setDetailsURL(new DetailsURL(urlDetails, Collections.singletonMap("rowId", "RowId")));
        addDetailsURL(new DetailsURL(urlDetails, Collections.singletonMap("LSID", "LSID")));
    }
}
