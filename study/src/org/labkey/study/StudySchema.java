/*
 * Copyright (c) 2006-2013 LabKey Corporation
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

package org.labkey.study;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.labkey.api.data.Container;
import org.labkey.api.data.DbSchema;
import org.labkey.api.data.DbScope;
import org.labkey.api.data.TableInfo;
import org.labkey.api.data.dialect.SqlDialect;
import org.labkey.api.security.User;
import org.labkey.api.study.SpecimenTablesTemplate;
import org.labkey.study.model.DataSetDefinition;
import org.labkey.study.model.DefaultSpecimenTablesTemplate;
import org.labkey.study.model.StudyImpl;
import org.labkey.study.model.StudyManager;
import org.labkey.study.query.SpecimenTablesProvider;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * User: brittp
 * Date: Jan 6, 2006
 * Time: 10:36:43 AM
 */
public class StudySchema
{
    private static final StudySchema instance = new StudySchema();
    private static final String SCHEMA_NAME = "study";

    private static SpecimenTablesTemplate specimenTablesTemplate = new DefaultSpecimenTablesTemplate();

    public static StudySchema getInstance()
    {
        return instance;
    }

    private StudySchema()
    {
    }

    public String getSchemaName()
    {
        return SCHEMA_NAME;
    }

    public DbSchema getSchema()
    {
        return DbSchema.get(SCHEMA_NAME);
    }

    public DbScope getScope()
    {
        return getSchema().getScope();
    }

    public String getDatasetSchemaName()
    {
        return "studydataset";
    }


    public SqlDialect getSqlDialect()
    {
        return getSchema().getSqlDialect();
    }

    public TableInfo getTableInfoStudy()
    {
        return getSchema().getTable("Study");
    }

    public TableInfo getTableInfoVisit()
    {
        return getSchema().getTable("Visit");
    }

    public TableInfo getTableInfoVisitAliases()
    {
        return getSchema().getTable("VisitAliases");
    }

    public TableInfo getTableInfoDataSet()
    {
        return getSchema().getTable("DataSet");
    }

    public TableInfo getTableInfoSite()
    {
        return getSchema().getTable("Site");
    }

    public TableInfo getTableInfoVisitMap()
    {
        return getSchema().getTable("VisitMap");
    }

    public TableInfo getTableInfoStudyData(StudyImpl study, @Nullable User user)
    {
        return new StudyUnionTableInfo(study, StudyManager.getInstance().getDataSetDefinitions(study), user);
    }

    public TableInfo getTableInfoStudyDataFiltered(StudyImpl study, Collection<DataSetDefinition> defs, User user)
    {
        return new StudyUnionTableInfo(study, defs, user);
    }

    public TableInfo getTableInfoStudyDataVisible(StudyImpl study, @Nullable User user)
    {
        List<DataSetDefinition> defsAll = study.getDataSets();
        List<DataSetDefinition> defsVisible = new ArrayList<>(defsAll.size());
        for (DataSetDefinition def : defsAll)
        {
            if (!def.isShowByDefault())
                continue;
            if (null != user && !def.canRead(user))
                continue;
            defsVisible.add(def);
        }
        return new StudyUnionTableInfo(study, defsVisible, user);
    }

    public TableInfo getTableInfoParticipant()
    {
        return getSchema().getTable("Participant");
    }

    public TableInfo getTableInfoParticipantVisit()
    {
        return getSchema().getTable("ParticipantVisit");
    }

    public TableInfo getTableInfoSampleRequest()
    {
        return getSchema().getTable("SampleRequest");
    }

    public TableInfo getTableInfoSampleRequestEvent()
    {
        return getSchema().getTable("SampleRequestEvent");
    }

    public TableInfo getTableInfoSampleRequestRequirement()
    {
        return getSchema().getTable("SampleRequestRequirement");
    }

    public TableInfo getTableInfoSampleRequestActor()
    {
        return getSchema().getTable("SampleRequestActor");
    }

    public TableInfo getTableInfoSampleRequestStatus()
    {
        return getSchema().getTable("SampleRequestStatus");
    }

    public TableInfo getTableInfoSampleRequestSpecimen()
    {
        return getSchema().getTable("SampleRequestSpecimen");
    }

    /*
     *  Provisioned tables: Specimen, Vial, SpecimenEvent
     */
    @NotNull
    public TableInfo getTableInfoVial(Container container)
    {
        return getTableInfoVial(container, null);
    }

    @NotNull
    public TableInfo getTableInfoVial(Container container, User user)
    {
        SpecimenTablesProvider specimenTablesProvider = new SpecimenTablesProvider(container, user, specimenTablesTemplate);
        return specimenTablesProvider.createTableInfo(SpecimenTablesProvider.VIAL_TABLENAME);
    }

    @Nullable
    public TableInfo getTableInfoVialIfExists(Container container)
    {
        SpecimenTablesProvider specimenTablesProvider = new SpecimenTablesProvider(container, null, null);
        return specimenTablesProvider.getTableInfoIfExists(SpecimenTablesProvider.VIAL_TABLENAME);
    }

    @NotNull
    public TableInfo getTableInfoSpecimen(Container container)
    {
        return getTableInfoSpecimen(container, null);
    }

    @NotNull
    public TableInfo getTableInfoSpecimen(Container container, User user)
    {
        SpecimenTablesProvider specimenTablesProvider = new SpecimenTablesProvider(container, user, specimenTablesTemplate);
        return specimenTablesProvider.createTableInfo(SpecimenTablesProvider.SPECIMEN_TABLENAME);
    }

    @Nullable
    public TableInfo getTableInfoSpecimenIfExists(Container container)
    {
        SpecimenTablesProvider specimenTablesProvider = new SpecimenTablesProvider(container, null, null);
        return specimenTablesProvider.getTableInfoIfExists(SpecimenTablesProvider.SPECIMEN_TABLENAME);
    }

    @NotNull
    public TableInfo getTableInfoSpecimenEvent(Container container)
    {
        return getTableInfoSpecimenEvent(container, null);
    }

    @NotNull
    public TableInfo getTableInfoSpecimenEvent(Container container, User user)
    {
        SpecimenTablesProvider specimenTablesProvider = new SpecimenTablesProvider(container, user, specimenTablesTemplate);
        return specimenTablesProvider.createTableInfo(SpecimenTablesProvider.SPECIMENEVENT_TABLENAME);
    }

    @Nullable
    public TableInfo getTableInfoSpecimenEventIfExists(Container container)
    {
        SpecimenTablesProvider specimenTablesProvider = new SpecimenTablesProvider(container, null, null);
        return specimenTablesProvider.getTableInfoIfExists(SpecimenTablesProvider.SPECIMENEVENT_TABLENAME);
    }

    public TableInfo getTableInfoSpecimenDetail(Container container)
    {
        return getSchema().getTable("SpecimenDetail");
    }

    public TableInfo getTableInfoSpecimenSummary()
    {
        return getSchema().getTable("SpecimenSummary");
    }

    public TableInfo getTableInfoSpecimenPrimaryType()
    {
        return getSchema().getTable("SpecimenPrimaryType");
    }
    public TableInfo getTableInfoSpecimenAdditive()
    {
        return getSchema().getTable("SpecimenAdditive");
    }
    public TableInfo getTableInfoSpecimenDerivative()
    {
        return getSchema().getTable("SpecimenDerivative");
    }

    public TableInfo getTableInfoUploadLog()
    {
        return getSchema().getTable("UploadLog");
    }

    public TableInfo getTableInfoPlate()
    {
        return getSchema().getTable("Plate");
    }

    public TableInfo getTableInfoWellGroup()
    {
        return getSchema().getTable("WellGroup");
    }

    public TableInfo getTableInfoWell()
    {
        return getSchema().getTable("Well");
    }

    public TableInfo getTableInfoCohort()
    {
        return getSchema().getTable("Cohort");
    }

    public TableInfo getTableInfoQCState()
    {
        return getSchema().getTable("QCState");
    }

    public TableInfo getTableInfoParticipantView()
    {
        return getSchema().getTable("ParticipantView");
    }

    public TableInfo getTableInfoSpecimenComment()
    {
        return getSchema().getTable("SpecimenComment");
    }

    public TableInfo getTableInfoPrimaryType()
    {
        return getSchema().getTable("SpecimenPrimaryType");
    }

    public TableInfo getTableInfoDerivativeType()
    {
        return getSchema().getTable("SpecimenDerivative");
    }

    public TableInfo getTableInfoAdditiveType()
    {
        return getSchema().getTable("SpecimenAdditive");
    }

    public TableInfo getTableInfoSpecimenVialCount()
    {
        return getSchema().getTable("VialCounts");
    }

    public TableInfo getTableInfoSampleAvailabilityRule()
    {
        return getSchema().getTable("SampleAvailabilityRule");
    }

    public TableInfo getTableInfoParticipantCategory()
    {
        return getSchema().getTable("ParticipantCategory");
    }

    public TableInfo getTableInfoParticipantGroup()
    {
        return getSchema().getTable("ParticipantGroup");
    }

    public TableInfo getTableInfoParticipantGroupMap()
    {
        return getSchema().getTable("ParticipantGroupMap");
    }

    public TableInfo getTableInfoStudySnapshot()
    {
        return getSchema().getTable("StudySnapshot");
    }

    public TableInfo getTableInfoStudyDesignImmunogenTypes()
    {
        return getSchema().getTable("StudyDesignImmunogenTypes");
    }

    public TableInfo getTableInfoStudyDesignGenes()
    {
        return getSchema().getTable("StudyDesignGenes");
    }

    public TableInfo getTableInfoStudyDesignRoutes()
    {
        return getSchema().getTable("StudyDesignRoutes");
    }

    public TableInfo getTableInfoStudyDesignSubTypes()
    {
        return getSchema().getTable("StudyDesignSubTypes");
    }

    public TableInfo getTableInfoStudyDesignSampleTypes()
    {
        return getSchema().getTable("StudyDesignSampleTypes");
    }

    public TableInfo getTableInfoStudyDesignUnits()
    {
        return getSchema().getTable("StudyDesignUnits");
    }

    public TableInfo getTableInfoStudyDesignAssays()
    {
        return getSchema().getTable("StudyDesignAssays");
    }

    public TableInfo getTableInfoStudyDesignLabs()
    {
        return getSchema().getTable("StudyDesignLabs");
    }
}
