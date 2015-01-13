/*
 * Copyright (c) 2014 LabKey Corporation
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

import org.labkey.api.data.DbSchema;
import org.labkey.api.data.DbSchemaType;
import org.labkey.api.data.DbScope;

import java.util.Collection;

/**
 * Created by klum on 2/23/14.
 */
public class ProvisionedDbSchema extends DbSchema
{
    public ProvisionedDbSchema(String name, DbScope scope)
    {
        super(name, DbSchemaType.Provisioned, scope, null);
    }

    @Override
    protected String getMetaDataName(String tableName)
    {
        return tableName;
    }

    @Override
    public Collection<String> getTableNames()
    {
        throw new IllegalStateException("Should not be requesting table names from provisioned schema \"" + getName() + "\"");
    }
}
