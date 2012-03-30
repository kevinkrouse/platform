/*
 * Copyright (c) 2006-2011 LabKey Corporation
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

package org.labkey.api.query;

import org.jetbrains.annotations.Nullable;
import org.labkey.api.data.Container;
import org.labkey.api.data.DbSchema;
import org.labkey.api.data.TableInfo;
import org.labkey.api.security.User;
import org.labkey.api.view.NavTree;

import java.util.Set;

public interface QuerySchema
{
    public User getUser();

    public Container getContainer();

    public DbSchema getDbSchema();

    public TableInfo getTable(String name);

    // Could be null if, for example, provider hides schema when module is inactive.
    public @Nullable QuerySchema getSchema(String name);

    public Set<String> getSchemaNames();

    public String getName();

    public @Nullable String getDescription();

    public NavTree getSchemaBrowserLinks(User user);
}
