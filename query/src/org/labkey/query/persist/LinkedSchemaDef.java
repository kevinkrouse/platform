/*
 * Copyright (c) 2012 LabKey Corporation
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
package org.labkey.query.persist;

import org.jetbrains.annotations.Nullable;
import org.labkey.api.data.Container;
import org.labkey.api.data.ContainerManager;

public class LinkedSchemaDef extends AbstractExternalSchemaDef
{
    static public class Key extends AbstractExternalSchemaDef.Key<LinkedSchemaDef>
    {
        public Key(@Nullable Container container)
        {
            super(LinkedSchemaDef.class, container);
        }

        @Override
        public SchemaType getSchemaType()
        {
            return SchemaType.linked;
        }
    }

    @Override
    public boolean isEditable()
    {
        return false;
    }

    @Override
    public boolean isIndexable()
    {
        return false;
    }

    // Source container id is an alias for data source.
    public String getSourceContainerId()
    {
        return getDataSource();
    }

    public Container lookupSourceContainer()
    {
        String containerId = getSourceContainerId();
        if (containerId != null)
            return ContainerManager.getForId(containerId);

        return null;
    }

    @Override
    public boolean equals(Object o)
    {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;

        LinkedSchemaDef that = (LinkedSchemaDef) o;

        return true;
    }

    @Override
    public int hashCode()
    {
        int result = super.hashCode();
        return result;
    }
}
