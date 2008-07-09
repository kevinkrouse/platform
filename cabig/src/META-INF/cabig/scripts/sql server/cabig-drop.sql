-- DROP current views.
EXEC core.fn_dropifexists 'experimentrun', 'cabig', 'VIEW', NULL
EXEC core.fn_dropifexists 'materialsource', 'cabig', 'VIEW', NULL
EXEC core.fn_dropifexists 'ProtSequences', 'cabig', 'VIEW', NULL
EXEC core.fn_dropifexists 'PeptideMembers', 'cabig', 'VIEW', NULL
EXEC core.fn_dropifexists 'ProteinGroupMembers', 'cabig', 'VIEW', NULL
EXEC core.fn_dropifexists 'ProteinGroups', 'cabig', 'VIEW', NULL
EXEC core.fn_dropifexists 'ProteinProphetFiles', 'cabig', 'VIEW', NULL
EXEC core.fn_dropifexists 'QuantSummaries', 'cabig', 'VIEW', NULL
EXEC core.fn_dropifexists 'FastaSequences', 'cabig', 'VIEW', NULL
EXEC core.fn_dropifexists 'FastaFiles', 'cabig', 'VIEW', NULL
EXEC core.fn_dropifexists 'Modifications', 'cabig', 'VIEW', NULL
EXEC core.fn_dropifexists 'CometScores', 'cabig', 'VIEW', NULL
EXEC core.fn_dropifexists 'SequestScores', 'cabig', 'VIEW', NULL
EXEC core.fn_dropifexists 'MascotScores', 'cabig', 'VIEW', NULL
EXEC core.fn_dropifexists 'XTandemScores', 'cabig', 'VIEW', NULL
EXEC core.fn_dropifexists 'PeptidesView', 'cabig', 'VIEW', NULL
EXEC core.fn_dropifexists 'SpectraData', 'cabig', 'VIEW', NULL
EXEC core.fn_dropifexists 'Fractions', 'cabig', 'VIEW', NULL
EXEC core.fn_dropifexists 'MS2Runs', 'cabig', 'VIEW', NULL
EXEC core.fn_dropifexists 'MS2RunsFilter', 'cabig', 'VIEW', NULL
EXEC core.fn_dropifexists 'materialrunoutputs', 'cabig', 'VIEW', NULL
EXEC core.fn_dropifexists 'materialruninputs', 'cabig', 'VIEW', NULL
EXEC core.fn_dropifexists 'datarunoutputs', 'cabig', 'VIEW', NULL
EXEC core.fn_dropifexists 'dataruninputs', 'cabig', 'VIEW', NULL
EXEC core.fn_dropifexists 'runlist', 'cabig', 'VIEW', NULL
EXEC core.fn_dropifexists 'protocolparameter', 'cabig', 'VIEW', NULL
EXEC core.fn_dropifexists 'protocolapplicationparameter', 'cabig', 'VIEW', NULL
EXEC core.fn_dropifexists 'protocolapplication', 'cabig', 'VIEW', NULL
EXEC core.fn_dropifexists 'materialinput', 'cabig', 'VIEW', NULL
EXEC core.fn_dropifexists 'material', 'cabig', 'VIEW', NULL
EXEC core.fn_dropifexists 'experiment', 'cabig', 'VIEW', NULL
EXEC core.fn_dropifexists 'datainput', 'cabig', 'VIEW', NULL
EXEC core.fn_dropifexists 'data', 'cabig', 'VIEW', NULL
EXEC core.fn_dropifexists 'successorpredecessor', 'cabig', 'VIEW', NULL
EXEC core.fn_dropifexists 'actionsuccessor', 'cabig', 'VIEW', NULL
EXEC core.fn_dropifexists 'protocolstep', 'cabig', 'VIEW', NULL
EXEC core.fn_dropifexists 'runprotocol', 'cabig', 'VIEW', NULL
EXEC core.fn_dropifexists 'protocolaction', 'cabig', 'VIEW', NULL
EXEC core.fn_dropifexists 'protocoldefinition', 'cabig', 'VIEW', NULL
EXEC core.fn_dropifexists 'customproperties', 'cabig', 'VIEW', NULL
EXEC core.fn_dropifexists 'propertydomain', 'cabig', 'VIEW', NULL
EXEC core.fn_dropifexists 'domaindescriptor', 'cabig', 'VIEW', NULL
EXEC core.fn_dropifexists 'propertydescriptor', 'cabig', 'VIEW', NULL
EXEC core.fn_dropifexists 'propertyvalue', 'cabig', 'VIEW', NULL
EXEC core.fn_dropifexists 'Containers', 'cabig', 'VIEW', NULL
GO
