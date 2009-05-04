/*
 * Copyright (c) 2009 LabKey Corporation
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

/* study-8.30-8.31.sql */

ALTER TABLE study.Dataset
  ADD protocolid INT NULL;
GO

/* study-8.31-8.32.sql */

ALTER TABLE study.SpecimenEvent
	ADD SpecimenNumber NVARCHAR(50);
GO

UPDATE study.SpecimenEvent SET SpecimenNumber =
	(SELECT SpecimenNumber FROM study.Specimen WHERE study.SpecimenEvent.SpecimenId = study.Specimen.RowId);
GO

ALTER TABLE study.Specimen
	DROP COLUMN SpecimenNumber;
GO

/* study-8.32-8.33.sql */

EXEC core.fn_dropifexists 'Visit', 'study', 'INDEX', 'IX_Visit_ContainerSeqNum'
go
EXEC core.fn_dropifexists 'Visit', 'study', 'INDEX', 'IX_Visit_SequenceNumMin'
go
ALTER TABLE study.Visit ADD CONSTRAINT UQ_Visit_ContSeqNum UNIQUE (Container, SequenceNumMin)
go

/* study-8.33-8.34.sql */

UPDATE exp.protocol SET MaxInputMaterialPerInstance = NULL
    WHERE
        (
            Lsid LIKE '%:LuminexAssayProtocol.Folder-%' OR
            Lsid LIKE '%:GeneralAssayProtocol.Folder-%' OR
            Lsid LIKE '%:NabAssayProtocol.Folder-%' OR 
            Lsid LIKE '%:ElispotAssayProtocol.Folder-%' OR 
            Lsid LIKE '%:MicroarrayAssayProtocol.Folder-%'
        ) AND ApplicationType = 'ExperimentRun'
GO

/* study-8.34-8.35.sql */

-- Remove ScharpId from SpecimenPrimaryType
ALTER TABLE study.SpecimenPrimaryType DROP CONSTRAINT UQ_PrimaryTypes;
DROP INDEX study.SpecimenPrimaryType.IX_SpecimenPrimaryType_ScharpId;
ALTER TABLE study.SpecimenPrimaryType ADD ExternalId INT NOT NULL DEFAULT 0;
GO
UPDATE study.SpecimenPrimaryType SET ExternalId = ScharpId;
ALTER TABLE study.SpecimenPrimaryType DROP COLUMN ScharpId;
CREATE INDEX IX_SpecimenPrimaryType_ExternalId ON study.SpecimenPrimaryType(ExternalId);
ALTER TABLE study.SpecimenPrimaryType ADD CONSTRAINT UQ_PrimaryType UNIQUE (ExternalId, Container);
GO

-- Remove ScharpId from SpecimenDerivativeType
ALTER TABLE study.SpecimenDerivative DROP CONSTRAINT UQ_Derivatives;
DROP INDEX study.SpecimenDerivative.IX_SpecimenDerivative_ScharpId;
ALTER TABLE study.SpecimenDerivative ADD ExternalId INT NOT NULL DEFAULT 0;
GO
UPDATE study.SpecimenDerivative SET ExternalId = ScharpId;
ALTER TABLE study.SpecimenDerivative DROP COLUMN ScharpId;
CREATE INDEX IX_SpecimenDerivative_ExternalId ON study.SpecimenDerivative(ExternalId);
ALTER TABLE study.SpecimenDerivative ADD CONSTRAINT UQ_Derivative UNIQUE (ExternalId, Container);
GO

-- Remove ScharpId from SpecimenAdditive
ALTER TABLE study.SpecimenAdditive DROP CONSTRAINT UQ_Additives;
DROP INDEX study.SpecimenAdditive.IX_SpecimenAdditive_ScharpId;
ALTER TABLE study.SpecimenAdditive ADD ExternalId INT NOT NULL DEFAULT 0;
GO
UPDATE study.SpecimenAdditive SET ExternalId = ScharpId;
ALTER TABLE study.SpecimenAdditive DROP COLUMN ScharpId;
CREATE INDEX IX_SpecimenAdditive_ExternalId ON study.SpecimenAdditive(ExternalId);
ALTER TABLE study.SpecimenAdditive ADD CONSTRAINT UQ_Additive UNIQUE (ExternalId, Container);
GO

-- Remove ScharpId from Site
ALTER TABLE study.Site ADD ExternalId INT;
GO
UPDATE study.Site SET ExternalId = ScharpId;
ALTER TABLE study.Site DROP COLUMN ScharpId;
GO

-- Remove ScharpId from SpecimenEvent
ALTER TABLE study.SpecimenEvent ADD ExternalId INT;
GO
UPDATE study.SpecimenEvent SET ExternalId = ScharpId;
ALTER TABLE study.SpecimenEvent DROP COLUMN ScharpId;
GO

UPDATE study.Specimen SET
    PrimaryTypeId = (SELECT RowId FROM study.SpecimenPrimaryType WHERE
        ExternalId = study.Specimen.PrimaryTypeId AND study.SpecimenPrimaryType.Container = study.Specimen.Container),
    DerivativeTypeId = (SELECT RowId FROM study.SpecimenDerivative WHERE
        ExternalId = study.Specimen.DerivativeTypeId AND study.SpecimenDerivative.Container = study.Specimen.Container),
    AdditiveTypeId = (SELECT RowId FROM study.SpecimenAdditive WHERE
        ExternalId = study.Specimen.AdditiveTypeId AND study.SpecimenAdditive.Container = study.Specimen.Container);
GO

ALTER TABLE study.Site ADD
    Repository BIT,
    Clinic BIT,
    SAL BIT,
    Endpoint BIT;
GO

UPDATE study.Site SET Repository = IsRepository, Clinic = IsClinic, SAL = IsSAL, Endpoint = IsEndpoint;

ALTER TABLE study.Site DROP COLUMN
    IsRepository,
    IsClinic,
    IsSAL,
    IsEndpoint;
GO

EXEC core.executeJavaUpgradeCode 'upgradeMissingProtocols'
GO

/* study-8.38-8.39.sql */

/*
LDMS Name 	Export Name 			Association
dervst2 	derivative_type_id_2 	the vial
froztm 	    frozen_time 			the vial
proctm 	    processing_time  		the vial
frlab       shipped_from_lab 	 	single vial location
tolab 	    shipped_to_lab 	 		single vial location
privol      primary_volume 	 		the draw
pvlunt 	    primary_volume_units 	the draw
*/

ALTER TABLE study.Specimen ADD
  DerivativeTypeId2 INT,
  FrozenTime DATETIME,
  ProcessingTime DATETIME,
  PrimaryVolume FLOAT,
  PrimaryVolumeUnits NVARCHAR(20),
  CONSTRAINT FK_Specimens_Derivatives2 FOREIGN KEY (DerivativeTypeId2) REFERENCES study.SpecimenDerivative(RowId)

GO

ALTER TABLE study.SpecimenEvent ADD
    ShippedFromLab INT,
    ShippedToLab INT,
    CONSTRAINT FK_ShippedFromLab_Site FOREIGN KEY (ShippedFromLab) references study.Site(RowId),
    CONSTRAINT FK_ShippedToLab_Site FOREIGN KEY (ShippedToLab) references study.Site(RowId)

GO

CREATE INDEX IX_SpecimenEvent_ShippedFromLab ON study.SpecimenEvent(ShippedFromLab)
CREATE INDEX IX_SpecimenEvent_ShippedToLab ON study.SpecimenEvent(ShippedToLab)

GO

ALTER TABLE study.Site ALTER COLUMN LabUploadCode NVARCHAR(10);
GO

ALTER TABLE study.SpecimenAdditive ALTER COLUMN LdmsAdditiveCode NVARCHAR(30);
GO

ALTER TABLE study.SpecimenDerivative ALTER COLUMN LdmsDerivativeCode NVARCHAR(20);
GO

ALTER TABLE study.Specimen ALTER COLUMN GlobalUniqueId NVARCHAR(50) NOT NULL;
ALTER TABLE study.Specimen ALTER COLUMN ClassId NVARCHAR(20);
ALTER TABLE study.Specimen ALTER COLUMN ProtocolNumber NVARCHAR(20);
ALTER TABLE study.Specimen ALTER COLUMN VisitDescription NVARCHAR(10);
ALTER TABLE study.Specimen ALTER COLUMN VolumeUnits NVARCHAR(20);
ALTER TABLE study.Specimen ALTER COLUMN SubAdditiveDerivative NVARCHAR(50);
GO

ALTER TABLE study.SpecimenEvent ALTER COLUMN UniqueSpecimenId NVARCHAR(50);
ALTER TABLE study.SpecimenEvent ALTER COLUMN RecordSource NVARCHAR(20);
ALTER TABLE study.SpecimenEvent ALTER COLUMN OtherSpecimenId NVARCHAR(50);
ALTER TABLE study.SpecimenEvent ALTER COLUMN XSampleOrigin NVARCHAR(50);
ALTER TABLE study.SpecimenEvent ALTER COLUMN SpecimenCondition NVARCHAR(30);
ALTER TABLE study.SpecimenEvent ALTER COLUMN ExternalLocation NVARCHAR(50);
GO

/* study-8.39-8.40.sql */

-- Migrate batch properties from runs to separate batch objects

-- Create batch rows
INSERT INTO exp.experiment (lsid, name, created, createdby, modified, modifiedby, container, hidden, batchprotocolid)
SELECT
REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(er.lsid, ':ElispotAssayRun', ':Experiment'), ':MicroarrayAssayRun', ':Experiment'), ':GeneralAssayRun', ':Experiment'), ':NabAssayRun', ':Experiment'), ':LuminexAssayRun', ':Experiment'),
er.name + ' Batch', er.created, er.createdby, er.modified, er.modifiedby, er.container, 0, p.rowid FROM exp.experimentrun er, exp.protocol p
WHERE er.lsid LIKE 'urn:lsid:%:%AssayRun.Folder-%:%' AND er.protocollsid = p.lsid
AND er.RowId NOT IN (SELECT ExperimentRunId FROM exp.RunList rl, exp.Experiment e WHERE rl.ExperimentId = e.RowId AND e.BatchProtocolId IS NOT NULL)
GO

-- Add an entry to the object table
INSERT INTO exp.object (objecturi, container)
SELECT
REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(er.lsid, ':ElispotAssayRun', ':Experiment'), ':MicroarrayAssayRun', ':Experiment'), ':GeneralAssayRun', ':Experiment'), ':NabAssayRun', ':Experiment'), ':LuminexAssayRun', ':Experiment'),
er.container FROM exp.experimentrun er
WHERE er.lsid LIKE 'urn:lsid:%:%AssayRun.Folder-%:%'
AND er.RowId NOT IN (SELECT ExperimentRunId FROM exp.RunList rl, exp.Experiment e WHERE rl.ExperimentId = e.RowId AND e.BatchProtocolId IS NOT NULL)
GO

-- Flip the properties to hang from the batch
UPDATE exp.ObjectProperty SET ObjectId =
	(SELECT oBatch.ObjectId
		FROM exp.Object oRun, exp.Object oBatch WHERE exp.ObjectProperty.ObjectId = oRun.ObjectId AND
		REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(oRun.ObjectURI, ':ElispotAssayRun', ':Experiment'), ':MicroarrayAssayRun', ':Experiment'), ':GeneralAssayRun', ':Experiment'), ':NabAssayRun', ':Experiment'), ':LuminexAssayRun', ':Experiment') = oBatch.ObjectURI
	)
WHERE
	PropertyId IN (SELECT dp.PropertyId FROM exp.DomainDescriptor dd, exp.PropertyDomain dp WHERE dd.DomainId = dp.DomainId AND dd.DomainURI LIKE 'urn:lsid:%:AssayDomain-Batch.Folder-%:%')
	AND ObjectId IN (SELECT o.ObjectId FROM exp.Object o, exp.ExperimentRun er WHERE o.ObjectURI = er.LSID AND er.lsid LIKE 'urn:lsid:%:%AssayRun.Folder-%:%'
	AND er.RowId NOT IN (SELECT ExperimentRunId FROM exp.RunList rl, exp.Experiment e WHERE rl.ExperimentId = e.RowId AND e.BatchProtocolId IS NOT NULL))
GO

-- Point the runs at their new batches
INSERT INTO exp.RunList (ExperimentRunId, ExperimentId)
	SELECT er.RowId, e.RowId FROM exp.ExperimentRun er, exp.Experiment e
	WHERE
		e.LSID = REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(er.LSID, ':ElispotAssayRun', ':Experiment'), ':MicroarrayAssayRun', ':Experiment'), ':GeneralAssayRun', ':Experiment'), ':NabAssayRun', ':Experiment'), ':LuminexAssayRun', ':Experiment')
		AND er.RowId NOT IN (SELECT ExperimentRunId FROM exp.RunList rl, exp.Experiment e WHERE rl.ExperimentId = e.RowId AND e.BatchProtocolId IS NOT NULL)
GO

-- Clean out the duplicated batch properties on the runs
DELETE FROM exp.ObjectProperty
	WHERE
		ObjectId IN (SELECT o.ObjectId FROM exp.Object o WHERE o.ObjectURI LIKE 'urn:lsid:%:%AssayRun.Folder-%:%')
		AND PropertyId IN (SELECT dp.PropertyId FROM exp.DomainDescriptor dd, exp.PropertyDomain dp WHERE dd.DomainId = dp.DomainId AND dd.DomainURI LIKE 'urn:lsid:%:AssayDomain-Batch.Folder-%:%')
GO