/*
 * Copyright (c) 2013-2015 LabKey Corporation
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
package org.labkey.study.query.studydesign;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.labkey.api.data.BaseColumnInfo;
import org.labkey.api.data.ContainerFilter;
import org.labkey.api.data.TableInfo;
import org.labkey.api.exp.api.StorageProvisioner;
import org.labkey.api.exp.property.Domain;
import org.labkey.api.query.FieldKey;
import org.labkey.api.query.LookupForeignKey;
import org.labkey.api.query.QueryService;
import org.labkey.api.query.UserSchema;
import org.labkey.api.security.UserPrincipal;
import org.labkey.api.security.permissions.Permission;
import org.labkey.study.query.StudyQuerySchema;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by klum on 12/13/13.
 */
public class StudyProductAntigenTable extends DefaultStudyDesignTable
{
    static final List<FieldKey> defaultVisibleColumns = new ArrayList<>();

    static {

        defaultVisibleColumns.add(FieldKey.fromParts("Container"));
        defaultVisibleColumns.add(FieldKey.fromParts("ProductId"));
        defaultVisibleColumns.add(FieldKey.fromParts("Gene"));
        defaultVisibleColumns.add(FieldKey.fromParts("SubType"));
        defaultVisibleColumns.add(FieldKey.fromParts("GenBankId"));
        defaultVisibleColumns.add(FieldKey.fromParts("Sequence"));
    }


    public static StudyProductAntigenTable create(Domain domain, UserSchema schema, @Nullable ContainerFilter filter)
    {
        TableInfo storageTableInfo = StorageProvisioner.createTableInfo(domain);
        if (null == storageTableInfo)
        {
            throw new IllegalStateException("Could not create provisioned table for domain: " + domain.getTypeURI());
        }
        return new StudyProductAntigenTable(domain, storageTableInfo, schema, filter);
    }


    private StudyProductAntigenTable(Domain domain, TableInfo storageTableInfo, UserSchema schema, @Nullable ContainerFilter containerFilter)
    {
        super(domain, storageTableInfo, schema, containerFilter);

        setName(StudyQuerySchema.PRODUCT_ANTIGEN_TABLE_NAME);
        setDescription("Contains one row per study product antigen");
    }


    @Override
    protected void initColumn(BaseColumnInfo col)
    {
        if ("ProductId".equalsIgnoreCase(col.getName()))
        {
            col.setFk(new LookupForeignKey("RowId")
            {
                @Override
                public TableInfo getLookupTableInfo()
                {
                    return QueryService.get().getUserSchema(_userSchema.getUser(), _userSchema.getContainer(), StudyQuerySchema.SCHEMA_NAME).getTable(StudyQuerySchema.PRODUCT_TABLE_NAME);
                }
            });
        }
        else if ("Gene".equalsIgnoreCase(col.getName()))
        {
            col.setFk(new LookupForeignKey("Name")
            {
                public TableInfo getLookupTableInfo()
                {
                    return QueryService.get().getUserSchema(_userSchema.getUser(), _userSchema.getContainer(), StudyQuerySchema.SCHEMA_NAME).getTable(StudyQuerySchema.STUDY_DESIGN_GENES_TABLE_NAME);
                }
            });
        }
        else if ("SubType".equalsIgnoreCase(col.getName()))
        {
            col.setFk(new LookupForeignKey("Name")
            {
                public TableInfo getLookupTableInfo()
                {
                    return QueryService.get().getUserSchema(_userSchema.getUser(), _userSchema.getContainer(), StudyQuerySchema.SCHEMA_NAME).getTable(StudyQuerySchema.STUDY_DESIGN_SUB_TYPES_TABLE_NAME);
                }
            });
        }
    }

    @Override
    public List<FieldKey> getDefaultVisibleColumns()
    {
        return defaultVisibleColumns;
    }

    @Override
    public boolean hasPermission(@NotNull UserPrincipal user, @NotNull Class<? extends Permission> perm)
    {
        // This is editable in Dataspace, but not in a folder within a Dataspace
        if (getContainer().getProject().isDataspace() && !getContainer().isDataspace())
            return false;
        return hasPermissionOverridable(user, perm);
    }
}
