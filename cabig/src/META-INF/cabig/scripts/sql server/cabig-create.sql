CREATE VIEW cabig.Containers AS
    SELECT c.RowId, c.EntityId, c.Name, p.RowId AS ParentId FROM core.Containers c
        LEFT OUTER JOIN core.Containers p ON c.Parent = p.EntityId
        WHERE NOT EXISTS(SELECT * FROM prop.PropertySets s INNER JOIN prop.Properties p ON s.[Set] = p.[Set] WHERE Category = 'SiteConfig' AND Name = 'caBIGEnabled' AND Value = 'FALSE') AND
            c.CaBIGPublished = 1
GO

CREATE VIEW cabig.propertyvalue AS
    SELECT ((4294967296 * op.propertyid) + op.objectid) AS valueid, op.objectid, op.propertyid
        , CASE WHEN op.floatvalue IS NOT NULL THEN CAST(op.floatvalue AS CHAR(255))
            WHEN op.datetimevalue IS NOT NULL THEN CAST(op.datetimevalue AS CHAR(255))
            ELSE op.stringvalue END AS strvalue
        , pd.propertyuri, pd.name, pd.rangeuri
    --	, pd.propertyid, pd.ontologyuri, pd.description, pd.concepturi
    --	, op.typetag, op.floatvalue, op.datetimevalue, op.stringvalue
    FROM exp.objectproperty op
        INNER JOIN exp.propertydescriptor pd ON (op.propertyid = pd.propertyid)
        INNER JOIN exp.object o ON (op.objectid = o.objectid)
        INNER JOIN cabig.containers c ON (o.container = c.entityid)
GO

CREATE VIEW cabig.propertydescriptor AS
    SELECT pd.propertyid, pd.propertyuri, pd.name, pd.ontologyuri, pd.description, pd.rangeuri, pd.concepturi
    FROM exp.propertydescriptor pd
	    INNER JOIN cabig.containers c ON c.entityid = pd.container
GO

CREATE VIEW cabig.domaindescriptor AS
    SELECT dd.domainid , dd.name, dd.domainuri, dd.description
    FROM exp.domaindescriptor dd
	    INNER JOIN cabig.containers c ON c.entityid = dd.container
GO

CREATE VIEW cabig.propertydomain AS
    SELECT pd.domainid , pd.propertyid
    FROM exp.propertydomain pd
GO

CREATE VIEW cabig.customproperties AS
    SELECT o.objectid, o.objecturi, o.ownerobjectid
    FROM exp.object o
	    INNER JOIN cabig.containers c ON c.entityid = o.container
GO

CREATE VIEW cabig.protocoldefinition AS
    SELECT p.rowid AS protocolid, p.lsid
        , p.name, p.protocoldescription, p.applicationtype, p.maxinputmaterialperinstance
        , p.maxinputdataperinstance, p.outputmaterialperinstance, p.outputdataperinstance, p.outputmaterialtype
        , p.outputdatatype, p.instrument, p.software, p.contactid
        , c.rowid AS containerid, o.objectid
    FROM exp.protocol p
        INNER JOIN cabig.containers c on (p.container = c.entityid)
        LEFT OUTER JOIN exp.object o on (p.lsid = o.objecturi)
GO

CREATE VIEW cabig.protocolaction AS
    SELECT pa.rowid AS actionid, pa.childprotocolid AS protocolid
    FROM exp.protocolaction pa
        INNER JOIN exp.protocol p ON pa.childprotocolid=p.rowid
        INNER JOIN cabig.containers c ON c.entityid = p.container
GO

CREATE VIEW cabig.runprotocol AS
    SELECT pa.rowid AS runactionid
    FROM exp.protocolaction pa
        INNER JOIN cabig.protocoldefinition pd ON pa.childprotocolid=pd.protocolid
    WHERE pa.parentprotocolid = pa.childprotocolid
GO

CREATE VIEW cabig.protocolstep AS
    SELECT pa.rowid AS stepactionid, pa.sequence, pap.rowid AS parentactionid
    FROM exp.protocolaction pa
        INNER JOIN exp.protocolaction pap ON (pap.childprotocolid = pa.parentprotocolid)
    WHERE pa.parentprotocolid <> pa.childprotocolid
GO

CREATE VIEW cabig.actionsuccessor AS
    SELECT pa.rowid AS successoractionid, pa.sequence
    FROM exp.protocolaction pa
        INNER JOIN exp.protocol p ON pa.childprotocolid=p.rowid
        INNER JOIN cabig.containers c ON c.entityid = p.container
    WHERE EXISTS (SELECT * FROM exp.protocolactionpredecessor pap WHERE pap.actionid = pa.rowid)
GO

CREATE VIEW cabig.successorpredecessor AS
    SELECT pap.actionid AS successoractionid, pap.predecessorid AS predecessoractionid
    FROM exp.protocolactionpredecessor pap
    WHERE pap.actionid <> pap.predecessorid
GO

CREATE VIEW cabig.data AS
    SELECT d.rowid, d.lsid, d.name, d.cpastype, d.sourceapplicationid, d.datafileurl, d.runid
        ,c.rowid AS containerid, o.objectid
    FROM exp.data d
        INNER JOIN cabig.containers c ON d.container = c.entityid
        LEFT OUTER JOIN exp.object o on d.lsid = o.objecturi
GO

CREATE VIEW cabig.datainput AS
    SELECT dataid, targetapplicationid, propertyid
    FROM exp.datainput
GO

CREATE VIEW cabig.experiment AS
    SELECT e.rowid, e.lsid, e.name, e.hypothesis, e.contactid, e.experimentdescriptionurl, e.comments
        , c.rowid AS containerid
        , o.objectid
    FROM exp.experiment e
        INNER JOIN cabig.containers c on e.container = c.entityid
        LEFT OUTER JOIN exp.object o on e.lsid = o.objecturi
GO

CREATE VIEW cabig.material AS
    SELECT m.rowid, m.lsid, m.name, m.cpastype, m.sourceapplicationid, m.runid
        ,c.rowid AS containerid, o.objectid, ms.rowid AS materialsourceid
    FROM exp.material m
        INNER JOIN cabig.containers c ON m.container = c.entityid
        LEFT OUTER JOIN exp.object o on m.lsid = o.objecturi
        LEFT OUTER JOIN exp.materialsource ms on m.cpastype = ms.lsid
GO

CREATE VIEW cabig.materialinput AS
    SELECT materialid, targetapplicationid, propertyid
    FROM exp.materialinput
GO

CREATE VIEW cabig.protocolapplication AS
    SELECT pa.rowid, pa.lsid, pa.name, pa.cpastype, pa.protocollsid, pa.activitydate, pa.comments, pa.runid, pa.actionsequence
        ,p.rowid AS protocolid
    FROM exp.protocolapplication pa
        INNER JOIN exp.protocol p ON pa.protocollsid = p.lsid
        INNER JOIN exp.ExperimentRun er ON er.rowid =pa.runid
        INNER JOIN cabig.containers c ON er.container = c.entityid
GO

CREATE VIEW cabig.protocolapplicationparameter AS
    SELECT pap.rowid, pap.protocolapplicationid, pap.name, pap.ontologyentryuri, pap.valuetype
        , CASE WHEN pap.integervalue  IS NOT NULL THEN CAST(pap.integervalue  AS CHAR)
            WHEN pap.doublevalue IS NOT NULL THEN CAST(pap.doublevalue AS CHAR)
            WHEN pap.datetimevalue IS NOT NULL THEN CAST(pap.datetimevalue AS CHAR)
            ELSE pap.stringvalue END AS paramvalue
    --	, pap.stringvalue, pap.integervalue, pap.doublevalue, pap.datetimevalue
    FROM exp.protocolapplicationparameter pap
        INNER JOIN exp.protocolapplication pa ON (pap.protocolapplicationid = pa.rowid)
        INNER JOIN exp.ExperimentRun er ON er.rowid =pa.runid
        INNER JOIN cabig.containers c ON er.container = c.entityid
GO

CREATE VIEW cabig.protocolparameter AS
    SELECT pp.rowid, pp.protocolid, pp.name, pp.ontologyentryuri, pp.valuetype
        , CASE WHEN pp.integervalue  IS NOT NULL THEN CAST(pp.integervalue  AS CHAR)
            WHEN pp.doublevalue IS NOT NULL THEN CAST(pp.doublevalue AS CHAR)
            WHEN pp.datetimevalue IS NOT NULL THEN CAST(pp.datetimevalue AS CHAR)
            ELSE pp.stringvalue END AS defaultvalue
    --	, pp.stringvalue, pp.integervalue, pp.doublevalue, pp.datetimevalue
    FROM exp.protocolparameter pp
        INNER JOIN exp.protocol p ON pp.protocolid = p.rowid
        INNER JOIN cabig.containers c ON c.entityid = p.container
GO

CREATE VIEW cabig.runlist AS
    SELECT experimentid, experimentrunid
    FROM exp.runlist
GO

CREATE VIEW cabig.dataruninputs AS
    SELECT di.dataid, di.propertyid, pa.runid
    FROM exp.data d
        INNER JOIN exp.datainput di ON (d.rowid = di.dataid)
        INNER JOIN exp.protocolapplication pa ON (di.targetapplicationid = pa.rowid)
        INNER JOIN exp.experimentrun er ON (pa.runid = er.rowid)
    WHERE pa.cpastype ='ExperimentRun'
GO

CREATE VIEW cabig.datarunoutputs AS
    SELECT di.dataid, di.propertyid, pa.runid
    FROM exp.data d
        INNER JOIN exp.datainput di ON (d.rowid = di.dataid)
        INNER JOIN exp.protocolapplication pa ON (di.targetapplicationid = pa.rowid)
        INNER JOIN exp.experimentrun er ON (pa.runid = er.rowid)
    WHERE pa.cpastype ='ExperimentRunOutput'
GO

CREATE VIEW cabig.materialruninputs AS
    SELECT mi.materialid, mi.propertyid, pa.runid
    FROM exp.material m
        INNER JOIN exp.materialinput mi ON (m.rowid = mi.materialid)
        INNER JOIN exp.protocolapplication pa ON (mi.targetapplicationid = pa.rowid)
        INNER JOIN exp.experimentrun er ON (pa.runid = er.rowid)
    WHERE pa.cpastype ='ExperimentRun'
GO

CREATE VIEW cabig.materialrunoutputs AS
    SELECT mi.materialid, mi.propertyid, pa.runid
    FROM exp.material m
        INNER JOIN exp.materialinput mi ON (m.rowid = mi.materialid)
        INNER JOIN exp.protocolapplication pa ON (mi.targetapplicationid = pa.rowid)
        INNER JOIN exp.experimentrun er ON (pa.runid = er.rowid)
    WHERE pa.cpastype ='ExperimentRunOutput'
GO

CREATE VIEW cabig.MS2RunsFilter AS
    SELECT mr.run, mr.type, mr.haspeptideprophet, mr.fastaid
        , mr.description AS rundescription
        ,c.rowid AS containerid
    FROM (ms2.runs mr
        INNER JOIN cabig.containers c ON (mr.container = c.entityid))
    WHERE mr.deleted = 0
GO

CREATE VIEW cabig.MS2Runs AS
    SELECT mr.run, mr.description, mr.path, mr.filename,
        mr.type, mr.searchengine, mr.massspectype, mr.searchenzyme,
        mr.haspeptideprophet, mr.peptidecount, mr.spectrumcount, mr.negativehitcount,
        mr.fastaid, mr.status, mr.statusid,
        c.rowid AS containerid,
        er.rowid AS experimentrunid
    FROM (ms2.runs mr
        INNER JOIN cabig.containers c ON (mr.container = c.entityid))
            LEFT JOIN exp.experimentrun er ON (er.lsid = mr.experimentrunlsid)
    WHERE mr.deleted = 0
GO

CREATE VIEW cabig.Fractions AS
    SELECT f.fraction, f.description, f.filename,
            f.run, f.pepxmldatalsid, f.mzxmlurl
    FROM ms2.Fractions f
        INNER JOIN cabig.MS2RunsFilter mr on (f.run = mr.run)
GO

CREATE VIEW cabig.SpectraData AS
    SELECT ((4294967296 * CAST(sd.fraction AS BigInt)) + sd.scan) AS spectrumid, f.run, sd.fraction, sd.scan, sd.spectrum
    FROM ms2.spectradata sd
        INNER JOIN cabig.Fractions f on (f.Fraction = sd.fraction)
GO

CREATE VIEW cabig.PeptidesView AS
    SELECT frac.run, run.rundescription, pep.fraction
        , LEFT(frac.FileName, CHARINDEX('.', frac.FileName) - 1) AS FractionName
        , pep.scan, pep.retentiontime, pep.charge
        , pep.ionpercent, pep.mass
        , pep.DeltaMass, (pep.Mass + DeltaMass) AS PrecursorMass
        , ABS(DeltaMass - ROUND(DeltaMass, 0)) AS FractionalDeltaMass
        , CASE
            WHEN pep.Mass = 0 THEN 0
            ELSE ABS(1000000 * ABS(DeltaMass - ROUND(DeltaMass, 0)) / (pep.Mass + (Charge - 1) * 1.007276))
        END AS FractionalDeltaMassPPM
        ,CASE
            WHEN pep.Mass = 0 THEN 0
            ELSE ABS(1000000 * DeltaMass / (pep.Mass + (Charge - 1) * 1.007276))
        END AS DeltaMassPPM
            ,CASE
            WHEN Charge = 0 THEN 0
            ELSE (pep.Mass + DeltaMass + (Charge - 1) * 1.007276) / Charge
        END AS MZ
        , pep.peptideprophet, pep.peptidepropheterrorrate, pep.peptide, pep.proteinhits, pep.protein, pep.prevaa, pep.trimmedpeptide
        , pep.nextaa
        , LTRIM(RTRIM(PrevAA + TrimmedPeptide + NextAA)) AS StrippedPeptide
        , pep.sequenceposition, pep.seqid, pep.rowid
        , quant.decimalratio, quant.heavy2lightratio, quant.heavyarea, quant.heavyfirstscan, quant.heavylastscan, quant.heavymass
        , quant.lightarea, quant.lightfirstscan, quant.lightlastscan, quant.lightmass, quant.ratio
        , proph.prophetfval, proph.prophetdeltamass, proph.prophetnumtrypticterm, proph.prophetnummissedcleav
       FROM ms2.peptidesdata pep
       JOIN ms2.fractions frac ON pep.fraction = frac.fraction
       JOIN cabig.MS2RunsFilter run ON frac.run = run.run
       LEFT JOIN ms2.quantitation quant ON pep.rowid = quant.peptideid
       LEFT JOIN ms2.peptideprophetdata proph ON pep.rowid = proph.peptideid
GO

CREATE VIEW cabig.XTandemScores AS
    SELECT pep.rowid AS xtandemscoreid
        , pep.score1 AS hyper, pep.score2 AS "next", pep.score3 AS b, pep.score4 AS y, pep.score5 AS expect
    FROM ms2.PeptidesData pep
        INNER JOIN ms2.Fractions f ON (pep.fraction = f.fraction)
        INNER JOIN cabig.MS2RunsFilter r ON (f.run = r.run)
    WHERE LOWER(SUBSTRING(r.type, 1, 7))='xtandem'
GO

CREATE VIEW cabig.MascotScores AS
    SELECT pep.rowid AS mascotscoreid
        , pep.score1 AS ion, pep.score2 AS mascotidentity, pep.score3 AS homology, pep.score5 AS expect
    FROM ms2.PeptidesData pep
        INNER JOIN ms2.Fractions f ON (pep.fraction = f.fraction)
        INNER JOIN cabig.MS2RunsFilter r ON (f.run = r.run)
    WHERE LOWER(SUBSTRING(r.type, 1, 6))='mascot'
GO

CREATE VIEW cabig.SequestScores AS
    SELECT pep.rowid AS sequestscoreid
        , pep.score1 AS spscore, pep.score2 AS deltacn, pep.score3 AS xcorr, pep.score4 AS sprank
    FROM ms2.PeptidesData pep
        INNER JOIN ms2.Fractions f ON (pep.fraction = f.fraction)
        INNER JOIN cabig.MS2RunsFilter r ON (f.run = r.run)
    WHERE LOWER(SUBSTRING(r.type, 1, 7))='sequest'
GO

CREATE VIEW cabig.CometScores AS
    SELECT pep.rowid AS cometscoreid
        , pep.score1 AS rawscore, pep.score2 AS diffscore, pep.score3 AS zscore
    FROM ms2.PeptidesData pep
        INNER JOIN ms2.Fractions f ON (pep.fraction = f.fraction)
        INNER JOIN cabig.MS2RunsFilter r ON (f.run = r.run)
    WHERE LOWER(SUBSTRING(r.type, 1, 5))='comet'
GO

CREATE VIEW cabig.Modifications AS
    SELECT CAST(m.run AS BigInt) * 65536 + ASCII(AminoAcid) * 256 + ASCII(Symbol) AS ModificationId,
            m.run, m.aminoacid, m.massdiff, m.variable, m.symbol
    FROM ms2.Modifications m
        INNER JOIN cabig.MS2RunsFilter r ON r.run = m.run
GO

CREATE VIEW cabig.FastaFiles AS
    SELECT ff.FastaId, ff.FileName, ff.Loaded, ff.FileChecksum
    FROM prot.FastaFiles ff
    WHERE ff.FastaId IN (SELECT FastaId FROM cabig.MS2RunsFilter)
GO

CREATE VIEW cabig.FastaSequences AS
    SELECT fs.FastaId, fs.LookupString, fs.SeqId ,
        (CAST((4294967296 * fs.FastaId) AS BigInt) + fs.seqid) AS FastaSequenceId
    FROM prot.FastaSequences fs
    WHERE (fs.FastaId IN (SELECT FastaId FROM cabig.MS2RunsFilter))
GO

CREATE VIEW cabig.QuantSummaries AS
    SELECT qs.QuantId, qs.Run, qs.AnalysisType, qs.AnalysisTime, qs.Version, qs.LabeledResidues,
        qs.MassDiff, qs.MassTol, qs.SameScanRange, qs.XpressLight
    FROM ms2.QuantSummaries qs
        INNER JOIN cabig.MS2RunsFilter r on (r.run = qs.run)
GO

CREATE VIEW cabig.ProteinProphetFiles AS
    SELECT pp.RowId, pp.FilePath, pp.Run, pp.UploadCompleted, pp.MinProbSeries, pp.SensitivitySeries, pp.ErrorSeries,
        pp.PredictedNumberCorrectSeries, pp.PredictedNumberIncorrectSeries
    FROM ms2.ProteinProphetFiles pp
        INNER JOIN cabig.MS2RunsFilter r on (r.run = pp.run)
GO

CREATE VIEW cabig.ProteinGroups AS
    SELECT pg.RowId, pg.GroupProbability, pg.ProteinProphetFileId, pp.Run,
        pg.GroupNumber, pg.IndistinguishableCollectionId,
        pg.UniquePeptidesCount, pg.TotalNumberPeptides, pg.PctSpectrumIds, pg.PercentCoverage,
        pg.ProteinProbability, pg.ErrorRate
    FROM (ms2.ProteinGroups pg
        INNER JOIN ms2.ProteinProphetFiles pp ON pg.ProteinProphetFileId = pp.RowId
        INNER JOIN cabig.MS2RunsFilter r ON r.run = pp.run )
        LEFT JOIN ms2.ProteinQuantitation pq ON pq.ProteinGroupId = pg.RowId
GO

CREATE VIEW cabig.ProteinGroupMembers AS
    SELECT pgm.SeqId, pgm.ProteinGroupId, pgm.probability, (CAST((4294967296 * pgm.ProteinGroupId) AS BIGINT) + pgm.SeqId) AS ProteinGroupMemberId
    FROM ms2.ProteinGroupMemberships pgm
    WHERE pgm.ProteinGroupId IN (
        SELECT pg.RowId FROM ms2.ProteinGroups pg
        INNER JOIN ms2.ProteinProphetFiles pp ON pg.ProteinProphetFileId = pp.RowId
        INNER JOIN cabig.MS2RunsFilter r ON r.run = pp.run )
GO

CREATE VIEW cabig.PeptideMembers AS
    SELECT pm.PeptideId, pm.ProteinGroupId, (CAST((4294967296 * pm.ProteinGroupId) AS BIGINT) + pm.PeptideId) AS PeptideMemberId,
        pm.NSPAdjustedProbability, pm.Weight, pm.NondegenerateEvidence,
        pm.EnzymaticTermini, pm.SiblingPeptides, pm.SiblingPeptidesBin, pm.Instances,
        pm.ContributingEvidence, pm.CalcNeutralPepMass
    FROM ms2.PeptideMemberships pm
    WHERE pm.ProteinGroupId IN
        ( SELECT pg.RowId FROM ms2.ProteinGroups pg
        INNER JOIN ms2.ProteinProphetFiles pp ON pg.ProteinProphetFileId = pp.RowId
        INNER JOIN cabig.MS2RunsFilter r ON r.run = pp.run )
GO

CREATE VIEW cabig.ProtSequences AS
    SELECT s.SeqId, s.ProtSequence, s.Hash, s.Description,
        src.Name AS SourceName, s.SourceVersion, src.Url AS SourceUrl, s.InsertDate, s.OrgId, s.Mass,
        s.BestName, s.BestGeneName, s.Length, o.CommonName AS OrganismName, o.Genus, o.Species, o.Comments
    FROM prot.Sequences s
        -- join in Source info if available
        LEFT JOIN prot.InfoSources src on (src.SourceId = s.SourceId AND src.Deleted = 0)
        -- join in Org info if is is available
        LEFT JOIN prot.Organisms o ON (s.OrgId = o.OrgId AND o.Deleted = 0)
    WHERE s.Deleted = 0
        AND s.SeqId IN (
        SELECT fs.SeqId
        FROM prot.FastaSequences fs
        WHERE fs.FastaId IN (SELECT FastaId FROM cabig.MS2RunsFilter))
GO

CREATE VIEW cabig.materialsource AS
    SELECT ms.rowid, ms.name, ms.lsid, ms.materiallsidprefix, ms.description
        ,c.rowid AS containerid, dd.domainid
    FROM exp.materialsource ms
        INNER JOIN cabig.containers c ON ms.container = c.entityid
        INNER JOIN exp.domaindescriptor dd on (dd.domainuri = ms.lsid)
GO

CREATE VIEW cabig.experimentrun AS
    SELECT er.rowid, er.lsid, er.name, er.protocollsid, er.comments, er.filepathroot
        , c.rowid AS containerid
        , o.objectid
        , p.rowid AS protocolid
        , pa.rowid AS actionid
    FROM (exp.experimentrun er
        INNER JOIN cabig.containers c ON (er.container = c.entityid)
        LEFT OUTER JOIN exp.object o ON (er.lsid = o.objecturi))
        INNER JOIN exp.protocol p ON (er.protocollsid = p.lsid)
        INNER JOIN exp.protocolaction pa ON (pa.parentprotocolid = p.rowid) AND (pa.parentprotocolid = pa.childprotocolid)
GO
