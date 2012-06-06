/*
 * Copyright (c) 2007-2012 LabKey Corporation
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

package org.labkey.study.query;

import org.labkey.study.StudySchema;

/**
 * User: brittp
 * Date: Jan 26, 2007
 * Time: 9:49:46 AM
 */
public class SpecimenEventTable extends BaseStudyTable
{
    public SpecimenEventTable(StudyQuerySchema schema)
    {
        super(schema, StudySchema.getInstance().getTableInfoSpecimenEvent(), true);

        addWrapColumn(_rootTable.getColumn("VialId"));
        addWrapColumn(_rootTable.getColumn("SpecimenNumber"));
        addWrapLocationColumn("LabId", "LabId").setLabel("Location");
        addWrapColumn(_rootTable.getColumn("Stored"));
        addWrapColumn(_rootTable.getColumn("StorageFlag"));
        addWrapColumn(_rootTable.getColumn("StorageDate"));
        addWrapColumn(_rootTable.getColumn("ShipFlag"));
        addWrapColumn(_rootTable.getColumn("ShipBatchNumber"));
        addWrapColumn(_rootTable.getColumn("ShipDate"));
        addWrapColumn(_rootTable.getColumn("LabReceiptDate"));
        addWrapColumn(_rootTable.getColumn("SpecimenCondition"));
        addWrapColumn(_rootTable.getColumn("Comments"));
        addWrapColumn(_rootTable.getColumn("fr_container"));
        addWrapColumn(_rootTable.getColumn("fr_level1"));
        addWrapColumn(_rootTable.getColumn("fr_level2"));
        addWrapColumn(_rootTable.getColumn("fr_position"));
        addWrapColumn(_rootTable.getColumn("freezer"));
        addWrapParticipantColumn("PTID").setKeyField(true);
        addWrapColumn(_rootTable.getColumn("DrawTimestamp"));
        addWrapColumn(_rootTable.getColumn("SalReceiptDate"));
        addWrapTypeColumn("PrimaryType", "PrimaryTypeId");
        addWrapTypeColumn("DerivativeType", "DerivativeTypeId");
        addWrapTypeColumn("AdditiveType", "AdditiveTypeId");
        addWrapTypeColumn("DerivativeType2", "DerivativeTypeId2");
        addWrapColumn(_rootTable.getColumn("VisitValue"));
        addWrapColumn(_rootTable.getColumn("VisitDescription"));
        addWrapColumn(_rootTable.getColumn("ClassId"));
        addWrapColumn(_rootTable.getColumn("ProtocolNumber"));
        addWrapColumn(_rootTable.getColumn("Volume"));
        addWrapColumn(_rootTable.getColumn("VolumeUnits"));
        addWrapColumn(_rootTable.getColumn("SubAdditiveDerivative"));
        addWrapLocationColumn("Clinic", "OriginatingLocationId");
        addWrapColumn(_rootTable.getColumn("FrozenTime"));
        addWrapColumn(_rootTable.getColumn("ProcessingTime"));
        addWrapColumn(_rootTable.getColumn("PrimaryVolume"));
        addWrapColumn(_rootTable.getColumn("PrimaryVolumeUnits"));
        addWrapColumn(_rootTable.getColumn("ProcessingDate"));
        addWrapColumn(_rootTable.getColumn("ProcessedByInitials"));
        addWrapColumn(_rootTable.getColumn("ShippedFromLab"));
        addWrapColumn(_rootTable.getColumn("ShippedToLab"));
        addWrapColumn(_rootTable.getColumn("ExpectedTimeValue"));
        addWrapColumn(_rootTable.getColumn("ExpectedTimeUnit"));
        addWrapColumn(_rootTable.getColumn("UpdateTimestamp"));
        addWrapColumn(_rootTable.getColumn("TotalCellCount"));
        addWrapColumn(_rootTable.getColumn("TubeType"));
        addContainerColumn();
    }

    @Override
    protected String getParticipantColumnName()
    {
        return "PTID";
    }

}
