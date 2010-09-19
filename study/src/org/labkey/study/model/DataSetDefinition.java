/*
 * Copyright (c) 2006-2010 LabKey Corporation
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

package org.labkey.study.model;

import org.apache.commons.collections15.MultiMap;
import org.apache.commons.collections15.multimap.MultiHashMap;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.labkey.api.cache.CacheManager;
import org.labkey.api.collections.CaseInsensitiveHashMap;
import org.labkey.api.collections.CaseInsensitiveHashSet;
import org.labkey.api.data.*;
import org.labkey.api.exp.*;
import org.labkey.api.exp.api.ExperimentService;
import org.labkey.api.exp.property.Domain;
import org.labkey.api.exp.property.PropertyService;
import org.labkey.api.query.*;
import org.labkey.api.security.SecurityManager;
import org.labkey.api.security.SecurityPolicy;
import org.labkey.api.security.User;
import org.labkey.api.security.permissions.ReadPermission;
import org.labkey.api.security.permissions.ReadSomePermission;
import org.labkey.api.security.permissions.UpdatePermission;
import org.labkey.api.study.*;
import org.labkey.api.util.GUID;
import org.labkey.api.util.JobRunner;
import org.labkey.api.util.MemTracker;
import org.labkey.api.view.HttpView;
import org.labkey.api.view.UnauthorizedException;
import org.labkey.study.StudySchema;
import org.labkey.study.query.DataSetTable;
import org.labkey.study.query.DataSetsTable;
import org.labkey.study.query.StudyQuerySchema;

import java.sql.*;
import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * User: brittp
 * Date: Jan 6, 2006
 * Time: 10:29:31 AM
 */
public class DataSetDefinition extends AbstractStudyEntity<DataSetDefinition> implements Cloneable, DataSet
{
    // standard string to use in URLs etc.
    public static final String DATASETKEY = "datasetId";
    private static final Object MANAGED_KEY_LOCK = new Object();
    private static Logger _log = Logger.getLogger(DataSetDefinition.class);

    private StudyImpl _study;
    private int _dataSetId;
    private String _name;
    private String _typeURI;
    private String _category;
    private String _visitDatePropertyName;
    private String _keyPropertyName;
    private @NotNull KeyManagementType _keyManagementType = KeyManagementType.None;
    private String _description;
    private boolean _demographicData; //demographic information, sequenceNum
    private transient TableInfo _tableInfoProperties;
    private Integer _cohortId;
    private Integer _protocolId; // indicates that dataset came from an assay. Null indicates no source assay
    private String _fileName; // Filename from the original import  TODO: save this at import time and load it from db

    private static final String[] BASE_DEFAULT_FIELD_NAMES_ARRAY = new String[]
    {
        "ParticipantID",
        "ptid",
        "SequenceNum", // used in both date-based and visit-based studies
        "DatasetId",
        "SiteId",
        "Created",
        "Modified",
        "sourcelsid",
        "QCState",
        "visitRowId",
        "lsid",
        "Dataset",
        "ParticipantSequenceKey",
        // The following columns names don't refer to actual built-in dataset columns, but
        // they're used by import ('replace') or are commonly used/confused synonyms for built-in column names
        "replace",
        "visit",
        "participant"
    };

    private static final String[] DEFAULT_ABSOLUTE_DATE_FIELD_NAMES_ARRAY = new String[]
    {
        "Date",
        "VisitDate",
    };

    private static final String[] DEFAULT_RELATIVE_DATE_FIELD_NAMES_ARRAY = new String[]
    {
        "Day"
    };

    private static final String[] DEFAULT_VISIT_FIELD_NAMES_ARRAY = new String[]
    {
        "VisitSequenceNum"
    };

    // fields to hide on the dataset schema view
    private static final String[] HIDDEN_DEFAULT_FIELD_NAMES_ARRAY = new String[]
    {
        "sourcelsid",
        "QCState",
        "visitRowId",
        "lsid",
        "Dataset",
        "ParticipantSequenceKey"
    };

    private static final CaseInsensitiveHashSet DEFAULT_ABSOLUTE_DATE_FIELDS;
    private static final CaseInsensitiveHashSet DEFAULT_RELATIVE_DATE_FIELDS;
    private static final CaseInsensitiveHashSet DEFAULT_VISIT_FIELDS;
    private static final CaseInsensitiveHashSet HIDDEN_DEFAULT_FIELDS = new CaseInsensitiveHashSet(HIDDEN_DEFAULT_FIELD_NAMES_ARRAY);

    static
    {
        DEFAULT_ABSOLUTE_DATE_FIELDS = new CaseInsensitiveHashSet(BASE_DEFAULT_FIELD_NAMES_ARRAY);
        DEFAULT_ABSOLUTE_DATE_FIELDS.addAll(DEFAULT_ABSOLUTE_DATE_FIELD_NAMES_ARRAY);

        DEFAULT_RELATIVE_DATE_FIELDS = new CaseInsensitiveHashSet(BASE_DEFAULT_FIELD_NAMES_ARRAY);
        DEFAULT_RELATIVE_DATE_FIELDS.addAll(DEFAULT_ABSOLUTE_DATE_FIELD_NAMES_ARRAY);
        DEFAULT_RELATIVE_DATE_FIELDS.addAll(DEFAULT_RELATIVE_DATE_FIELD_NAMES_ARRAY);

        DEFAULT_VISIT_FIELDS = new CaseInsensitiveHashSet(BASE_DEFAULT_FIELD_NAMES_ARRAY);
        DEFAULT_VISIT_FIELDS.addAll(DEFAULT_VISIT_FIELD_NAMES_ARRAY);
    }

    public DataSetDefinition()
    {
    }


    public DataSetDefinition(StudyImpl study, int dataSetId, String name, String label, String category, String typeURI)
    {
        _study = study;
        setContainer(_study.getContainer());
        _dataSetId = dataSetId;
        _name = name;
        _label = label;
        _category = category;
        _typeURI = typeURI;
        _showByDefault = true;
    }

    public static boolean isDefaultFieldName(String fieldName, Study study)
    {
        String subjectCol = StudyService.get().getSubjectColumnName(study.getContainer());
        switch (study.getTimepointType())
        {
            case VISIT:
                return DEFAULT_VISIT_FIELDS.contains(fieldName) || subjectCol.equalsIgnoreCase(fieldName);
            case CONTINUOUS:
                return DEFAULT_ABSOLUTE_DATE_FIELDS.contains(fieldName) || subjectCol.equalsIgnoreCase(fieldName);
            case DATE:
            default:
                return DEFAULT_RELATIVE_DATE_FIELDS.contains(fieldName) || subjectCol.equalsIgnoreCase(fieldName);
        }
    }

    public static boolean showOnManageView(String fieldName, Study study)
    {
        return !HIDDEN_DEFAULT_FIELDS.contains(fieldName);
    }

    public Set<String> getDefaultFieldNames()
    {
        TimepointType timepointType = getStudy().getTimepointType();
        Set<String> fieldNames =
                timepointType == TimepointType.VISIT ? DEFAULT_VISIT_FIELDS :
                timepointType == TimepointType.CONTINUOUS ? DEFAULT_ABSOLUTE_DATE_FIELDS:
                DEFAULT_RELATIVE_DATE_FIELDS;

        return Collections.unmodifiableSet(fieldNames);
    }


    public String getName()
    {
        return _name;
    }

    public void setName(String name)
    {
        _name = name;
    }

    public String getFileName()
    {
        if (null == _fileName)
        {
            NumberFormat dsf = new DecimalFormat("dataset000.tsv");

            return dsf.format(getDataSetId());
        }
        else
        {
            return _fileName;
        }
    }

    public void setFileName(String fileName)
    {
        _fileName = fileName;
    }

    public String getCategory()
    {
        return _category;
    }

    public void setCategory(String category)
    {
        verifyMutability();
        _category = category;
    }

    public int getDataSetId()
    {
        return _dataSetId;
    }

    public void setDataSetId(int dataSetId)
    {
        verifyMutability();
        _dataSetId = dataSetId;
    }

    public String getTypeURI()
    {
        return _typeURI;
    }

    public void setTypeURI(String typeURI)
    {
        verifyMutability();
        _typeURI = typeURI;
    }


    public String getPropertyURI(String column)
    {
        PropertyDescriptor pd = DataSetDefinition.getStandardPropertiesMap().get(column);
        if (null != pd)
            return pd.getPropertyURI();
        return _typeURI + "." + column;
    }


    public VisitDataSetType getVisitType(int visitRowId)
    {
        VisitDataSet vds = getVisitDataSet(visitRowId);
        if (vds == null)
            return VisitDataSetType.NOT_ASSOCIATED;
        else if (vds.isRequired())
            return VisitDataSetType.REQUIRED;
        else
            return VisitDataSetType.OPTIONAL;
    }


    public List<VisitDataSet> getVisitDataSets()
    {
        return Collections.unmodifiableList(StudyManager.getInstance().getMapping(this));
    }


    public VisitDataSet getVisitDataSet(int visitRowId)
    {
        List<VisitDataSet> dataSets = getVisitDataSets();
        for (VisitDataSet vds : dataSets)
        {
            if (vds.getVisitRowId() == visitRowId)
                return vds;
        }
        return null;
    }


    public int getRowId()
    {
        return getDataSetId();
    }

    public Object getPrimaryKey()
    {
        return getRowId();
    }

    /**
     * Get table info representing dataset.  This relies on the DataSetDefinition being removed from
     * the cache if the dataset type changes.  The temptable version also relies on the dataset being
     * uncached when data is updated.
     *
     * see StudyManager.importDatasetTSV()
     */
    public TableInfo getTableInfo(User user) throws UnauthorizedException
    {
        return getTableInfo(user, true, true);
    }


    public TableInfo getTableInfo(@NotNull User user, boolean checkPermission, boolean materialized) throws UnauthorizedException
    {
        //noinspection ConstantConditions
        if (user == null)
            throw new IllegalArgumentException("user cannot be null");

        if (checkPermission && !canRead(user) && user != User.getSearchUser())
            HttpView.throwUnauthorized();

        if (materialized)
            return getMaterializedTempTableInfo(user, true);
        else
            return getJoinTableInfo(user);
    }


    public void materializeInBackground(final User user)
    {
        Runnable task = new Runnable()
        {
            public void run()
            {
                unmaterialize();
                JobRunner.getDefault().submit(new Runnable()
                    {
                        public void run()
                        {
                            getMaterializedTempTableInfo(user, true);
                        }
                    });
            }
        };

        if (getScope().isTransactionActive())
            getScope().addCommitTask(task);
        else
            task.run();
    }

    public boolean isDemographicData()
    {
        return _demographicData;
    }

    public void setDemographicData(boolean demographicData)
    {
        _demographicData = demographicData;
    }


    /**
     * materializedCache is a cache of the table that was materialized for this DatasetDefinition.
     */
    private static class MaterializedLockObject
    {
        private final String _name;
        private SchemaTableInfo _tinfoMaterialized = null;

        // for debugging
        TableInfo _tinfoOntology = null;
        private long _lastVerify = 0;

        public MaterializedLockObject(String name)
        {
            _name = name;
        }

        synchronized SchemaTableInfo getExitingTableInfo(DataSetDefinition dataset, User user)
        {
            long now = System.currentTimeMillis();
            if (_lastVerify + 5* CacheManager.MINUTE > now && _tinfoMaterialized != null)
                return _tinfoMaterialized;
            _lastVerify = now;
            if (isMaterialized(_name))
            {
                if (_tinfoMaterialized == null)
                {
                    if (_tinfoOntology == null)
                    {
                        _tinfoOntology = dataset.getJoinTableInfo(user);
                    }
                    _tinfoMaterialized = getMaterializedTableInfo(_tinfoOntology, _name);
                }
            }
            else
            {
                _tinfoMaterialized = null;
            }
            return _tinfoMaterialized;
        }
    }


    private static boolean isMaterialized(String tempTableName)
    {
        DbScope scope = StudySchema.getInstance().getDatasetSchema().getScope();
        Connection conn = null;
        ResultSet rs = null;
        try
        {
            conn = scope.getConnection();
            rs = conn.getMetaData().getTables(scope.getDatabaseName(), StudySchema.getInstance().getDatasetSchema().getName(), tempTableName, new String[]{"TABLE"});
            if (rs.next())
            {
                return true;
            }
        }
        catch (SQLException e)
        {
            throw new RuntimeSQLException(e);
        }
        finally
        {
            if (rs != null) { try { rs.close(); } catch (SQLException e) {} }
            if (conn != null) { try { scope.releaseConnection(conn); } catch (SQLException e) {} }
        }
        return false;
    }

    private static final Map<String, MaterializedLockObject> materializedCache = new HashMap<String,MaterializedLockObject>();


    public TableInfo getMaterializedTempTableInfo(User user, boolean forceMaterialization)
    {
        MaterializedLockObject mlo = getMaterializationLockObject();

        // prevent multiple threads from materializing the same dataset
        synchronized(mlo)
        {
            try
            {
                TableInfo currentFrom = getJoinTableInfo(user);
                SchemaTableInfo result = mlo.getExitingTableInfo(this, user);

                if (result != null)
                {
                    TableInfo cachedFrom = mlo._tinfoOntology;
                    if (!cachedFrom.getColumnNameSet().equals(currentFrom.getColumnNameSet()))
                    {
                        StringBuilder msg = new StringBuilder("unexpected difference in columns sets for dataset " + getName() + " in " + getContainer().getPath() + "\n");
                        msg.append("  cachedFrom:  ").append(StringUtils.join(new TreeSet<String>(cachedFrom.getColumnNameSet()),",")).append("\n");
                        msg.append("  currentFrom: ").append(StringUtils.join(new TreeSet<String>(currentFrom.getColumnNameSet()), ",")).append("\n");
                        _log.error(msg);
                        dropMaterializedTable();
                        result = null;
                    }
                }
                
                if (result == null && forceMaterialization)
                {
                    result = materialize(currentFrom);
                    result.setButtonBarConfig(currentFrom.getButtonBarConfig());

                    mlo._tinfoMaterialized = result;
                    mlo._tinfoOntology = currentFrom;
                }
                _log.debug("DataSetDefinition returning " + (result == null ? "null" : result.getSelectName()));
                return result;
            }
            catch (SQLException x)
            {
                throw new RuntimeSQLException(x);
            }
        }
    }

    public MaterializedLockObject getMaterializationLockObject()
    {
        synchronized(materializedCache)
        {
            String tempName = getCacheString();
            MaterializedLockObject mlo = materializedCache.get(tempName);
            if (null == mlo)
            {
                mlo = new MaterializedLockObject(tempName);
                materializedCache.put(tempName, mlo);
            }
            return mlo;
        }
    }

    private SchemaTableInfo materialize(TableInfo tinfoFrom)
            throws SQLException
    {
        //noinspection UnusedAssignment
        boolean debug=false;
        //noinspection ConstantConditions
        assert debug=true;

        SchemaTableInfo tinfoMat = getMaterializedTableInfo(tinfoFrom, getCacheString());

        Table.snapshot(tinfoFrom, tinfoMat.toString());
        String tempName = getCacheString();

        Table.execute(tinfoFrom.getSchema(), "CREATE INDEX " + tinfoMat.getSqlDialect().makeLegalIdentifier("IX_" + tempName + "_seq") +
                " ON " + tinfoMat + "(SequenceNum)", null);
        Table.execute(tinfoFrom.getSchema(), "CREATE INDEX " + tinfoMat.getSqlDialect().makeLegalIdentifier("IX_" + tempName + "_ptidsequencekey") +
                " ON " + tinfoMat + "(ParticipantSequenceKey)", null);
        Table.execute(tinfoFrom.getSchema(), "CREATE INDEX " + tinfoMat.getSqlDialect().makeLegalIdentifier("IX_" + tempName + "_ptid_seq") +
                " ON " + tinfoMat + "(" + StudyService.get().getSubjectColumnName(getContainer()) + ", SequenceNum)", null);

        //noinspection ConstantConditions
        if (debug)
        {
            // NOTE: any PropertyDescriptor we hold onto will look like a leak
            // CONSIDER: make MemTracker aware of this cache
            for (ColumnInfo col : tinfoFrom.getColumns())
            {
                if (col instanceof PropertyColumn)
                    assert MemTracker.remove(((PropertyColumn)col).getPropertyDescriptor());
            }
        }
        return tinfoMat;
    }

    private static SchemaTableInfo getMaterializedTableInfo(TableInfo tinfoFrom, String tempName)
    {
        SchemaTableInfo tinfoMat = new SchemaTableInfo(tempName, StudySchema.getInstance().getDatasetSchema());
        for (final ColumnInfo col : tinfoFrom.getColumns())
        {
            ColumnInfo colDirect = new ColumnInfo(col.getName())
            {
                @Override
                public String getSelectName()
                {
                    // It's very important that this match exactly what was used as the alias when generating the SELECT
                    // that fed into the temp table. Hence, we ask that column directly
                    return getSqlDialect().makeLegalIdentifier(col.getAlias());
                }
            };
            colDirect.copyAttributesFrom(col);
            colDirect.copyURLFrom(col, null, null);
            colDirect.setParentTable(tinfoMat);
            tinfoMat.addColumn(colDirect);
        }
        tinfoMat.setTableType(TableInfo.TABLE_TYPE_TABLE);
        tinfoMat.setPkColumnNames(tinfoFrom.getPkColumnNames());
        return tinfoMat;
    }


    public void unmaterialize()
    {
        Runnable task = new Runnable()
        {
            public void run()
            {
                MaterializedLockObject mlo;
                String tempName = getCacheString();
                if (isMaterialized(tempName))
                {
                    try
                    {
                        dropMaterializedTable();
                        _log.debug("DataSetDefinition unmaterialize(" + getName() + ")");
                    }
                    catch (SQLException e)
                    {
                        throw new RuntimeSQLException(e);
                    }
                }
                synchronized(materializedCache)
                {
                    mlo = materializedCache.get(tempName);
                }
                if (null == mlo)
                    return;
                synchronized (mlo)
                {
                    mlo._tinfoOntology = null;
                    mlo._tinfoMaterialized = null;
                }
            }
        };

        DbScope scope = getScope();
        if (scope.isTransactionActive())
            scope.addCommitTask(task);

        task.run();
    }

    private void dropMaterializedTable()
            throws SQLException
    {
        Table.execute(StudySchema.getInstance().getDatasetSchema(), "DROP TABLE studydataset." + getScope().getSqlDialect().makeLegalIdentifier(getCacheString()), new Object[0]);
    }


    private DbScope getScope()
    {
        return StudySchema.getInstance().getSchema().getScope();
    }


    private String getCacheString()
    {
        return "c" + getContainer().getRowId() + "_" + getName().toLowerCase();
    }

    private synchronized TableInfo getJoinTableInfo(User user)
    {
        if (null == _tableInfoProperties)
            _tableInfoProperties = new StudyDataTableInfo(this, user);
        return _tableInfoProperties;
    }


    public StudyImpl getStudy()
    {
        if (null == _study)
            _study = StudyManager.getInstance().getStudy(getContainer());
        return _study;
    }


    public boolean canRead(User user)
    {
        //if the study security type is basic read or basic write, use the container's policy instead of the
        //study's policy. This will enable us to "remember" the study-level role assignments in case we want
        //to switch back to them in the future
        SecurityType securityType = getStudy().getSecurityType();
        SecurityPolicy studyPolicy = (securityType == SecurityType.BASIC_READ || securityType == SecurityType.BASIC_WRITE) ?
                SecurityManager.getPolicy(getContainer()) : SecurityManager.getPolicy(getStudy());


        //need to check both the study's policy and the dataset's policy
        //users that have read permission on the study can read all datasets
        //users that have read-some permission on the study must also have read permission on this dataset
        return studyPolicy.hasPermission(user, ReadPermission.class) ||
                (studyPolicy.hasPermission(user, ReadSomePermission.class) && SecurityManager.getPolicy(this).hasPermission(user, ReadPermission.class));
    }

    public boolean canWrite(User user)
    {
        if (!canRead(user))
            return false;

        if (!getStudy().getContainer().getPolicy().hasPermission(user, UpdatePermission.class))
            return false;

        SecurityType securityType = getStudy().getSecurityType();

        if (securityType == SecurityType.BASIC_READ || securityType == SecurityType.ADVANCED_READ)
            return false; // Dataset rows are not editable

        if (securityType == SecurityType.BASIC_WRITE)
        {
            return true;
        }
        
        return SecurityManager.getPolicy(getStudy()).hasPermission(user, UpdatePermission.class) ||
            SecurityManager.getPolicy(this).hasPermission(user, UpdatePermission.class);
    }

    public String getVisitDatePropertyName()
    {
        if (null == _visitDatePropertyName && getStudy().getTimepointType() != TimepointType.VISIT)
            _visitDatePropertyName = "Date"; //Todo: Allow alternate names
        return _visitDatePropertyName;
    }

    public void setVisitDatePropertyName(String visitDatePropertyName)
    {
        _visitDatePropertyName = visitDatePropertyName;
    }

    /**
     * Returns the key names for display purposes.
     * If demographic data, visit keys are suppressed
     */
    public String[] getDisplayKeyNames()
    {
        List<String> keyNames = new ArrayList<String>();
        keyNames.add(StudyService.get().getSubjectColumnName(getContainer()));
        if (!isDemographicData())
        {
            keyNames.add(getStudy().getTimepointType() == TimepointType.VISIT ? "SequenceNum" : "Date");
        }
        if (getKeyPropertyName() != null)
            keyNames.add(getKeyPropertyName());

        return keyNames.toArray(new String[keyNames.size()]);
    }
    
    public String getKeyPropertyName()
    {
        return _keyPropertyName;
    }

    public void setKeyPropertyName(String keyPropertyName)
    {
        _keyPropertyName = keyPropertyName;
    }

    public void setKeyManagementType(@NotNull KeyManagementType type)
    {
        _keyManagementType = type;
    }

    @NotNull
    public KeyManagementType getKeyManagementType()
    {
        return _keyManagementType;
    }

    public String getDescription()
    {
        return _description;
    }

    public void setDescription(String description)
    {
        _description = description;
    }

    @NotNull
    @Override
    public String getResourceDescription()
    {
        return null == _description ? "The study dataset " + getName() : _description;
    }

    private static class AutoCompleteDisplayColumnFactory implements DisplayColumnFactory
    {
        private String _completionBase;

        public AutoCompleteDisplayColumnFactory(Container studyContainer, SpecimenService.CompletionType type)
        {
            _completionBase = SpecimenService.get().getCompletionURLBase(studyContainer, type);
        }

        public DisplayColumn createRenderer(ColumnInfo colInfo)
        {
            return new DataColumn(colInfo)
            {
                @Override
                protected String getAutoCompleteURLPrefix()
                {
                    return _completionBase;
                }
            };
        }
    }

    private static class StudyDataTableInfo extends SchemaTableInfo
    {
        private Container _container;
        private User _user;
        int _datasetId;
        SQLFragment _fromSql;

        StudyDataTableInfo(DataSetDefinition def, final User user)
        {
            super(def.getLabel(), StudySchema.getInstance().getSchema());
            _container = def.getContainer();
            _user = user;
            Study study = StudyManager.getInstance().getStudy(_container);
            _datasetId = def.getDataSetId();

            TableInfo studyData = StudySchema.getInstance().getTableInfoStudyData();
            TableInfo participantVisit = StudySchema.getInstance().getTableInfoParticipantVisit();
            final TableInfo datasetTable = StudySchema.getInstance().getTableInfoDataSet();
            // StudyData columns
            List<ColumnInfo> columnsBase = studyData.getColumns("lsid","participantid","ParticipantSequenceKey","sourcelsid", "created","modified");
            for (ColumnInfo col : columnsBase)
            {
                boolean ptid = "participantid".equals(col.getColumnName());
                if (!ptid)
                    col.setUserEditable(false);
                ColumnInfo wrapped = newDatasetColumnInfo(this, col);
                if (ptid)
                {
                    wrapped.setName(StudyService.get().getSubjectColumnName(_container));
                    wrapped.setLabel(StudyService.get().getSubjectColumnName(_container));
                    wrapped.setDisplayColumnFactory(new AutoCompleteDisplayColumnFactory(_container, SpecimenService.CompletionType.ParticipantId));
                    wrapped.setDimension(true);
                }
                columns.add(wrapped);
            }
            ColumnInfo sequenceNumCol = newDatasetColumnInfo(this, studyData.getColumn("sequenceNum"));
            sequenceNumCol.setDisplayColumnFactory(new AutoCompleteDisplayColumnFactory(_container, SpecimenService.CompletionType.VisitId));
            sequenceNumCol.setMeasure(false);

            if (study.getTimepointType() != TimepointType.VISIT)
            {
                sequenceNumCol.setNullable(true);
                sequenceNumCol.setHidden(true);
                sequenceNumCol.setUserEditable(false);
                ColumnInfo visitDateCol = newDatasetColumnInfo(this, studyData.getColumn("_visitDate"));
                visitDateCol.setName("Date");
                visitDateCol.setNullable(false);
                columns.add(visitDateCol);

                ColumnInfo dayColumn = null;
                if (study.getTimepointType() == TimepointType.DATE)
                {
                    dayColumn = newDatasetColumnInfo(this, participantVisit.getColumn("Day"));
                    dayColumn.setUserEditable(false);
                    dayColumn.setDimension(false);
                    dayColumn.setMeasure(false);
                    columns.add(dayColumn);
                }

                if (def.isDemographicData())
                {
                    visitDateCol.setHidden(true);
                    visitDateCol.setUserEditable(false);
                    if (dayColumn != null)
                        dayColumn.setHidden(true);
                }
            }

            if (def.isDemographicData())
            {
                sequenceNumCol.setHidden(true);
                sequenceNumCol.setUserEditable(false);
            }

            columns.add(sequenceNumCol);

            ColumnInfo qcStateCol = newDatasetColumnInfo(this, studyData.getColumn(DataSetTable.QCSTATE_ID_COLNAME));
            // UNDONE: make the QC column user editable.  This is turned off for now because StudyDataTableInfo is not
            // a FilteredTable, so it doesn't know how to restrict QC options to those in the current container.
            // Note that QC state can still be modified via the standard update UI.
            qcStateCol.setUserEditable(false);
            columns.add(qcStateCol);

            // Property columns
            ColumnInfo[] columnsLookup = OntologyManager.getColumnsForType(def.getTypeURI(), this, _container, _user);
            columns.addAll(Arrays.asList(columnsLookup));
            ColumnInfo visitRowId = newDatasetColumnInfo(this, participantVisit.getColumn("VisitRowId"));
            visitRowId.setHidden(true);
            visitRowId.setUserEditable(false);
            visitRowId.setMeasure(false);
            columns.add(visitRowId);

            // If we have an extra key, and it's server-managed, make it non-editable
            if (def.getKeyManagementType() != KeyManagementType.None)
            {
                for (ColumnInfo col : columns)
                {
                    if (col.getName().equals(def.getKeyPropertyName()))
                    {
                        col.setUserEditable(false);
                    }
                }
            }

            // Add the dataset table via a foreign key lookup
            String datasetSql = "(SELECT D.entityid FROM " + datasetTable + " D WHERE " +
                    "D.container ='" + _container.getId() + "' AND D.datasetid = " + _datasetId + ")";

            ColumnInfo datasetColumn = new ExprColumn(this, "Dataset", new SQLFragment(datasetSql), Types.VARCHAR);
            LookupForeignKey datasetFk = new LookupForeignKey("entityid")
            {
                public TableInfo getLookupTableInfo()
                {
                    return new DataSetsTable(new StudyQuerySchema(StudyManager.getInstance().getStudy(_container), user, true));
                }
            };
            datasetColumn.setFk(datasetFk);
            datasetColumn.setUserEditable(false);
            datasetColumn.setHidden(true);
            datasetColumn.setDimension(false);
            columns.add(datasetColumn);

            // HACK reset colMap
            colMap = null;

            setPkColumnNames(Arrays.asList("LSID"));

//          <UNDONE> just add a lookup column to the columnlist for VisitDate
            _fromSql = new SQLFragment(
                    "SELECT SD.container, SD.lsid, SD.ParticipantId AS " + StudyService.get().getSubjectColumnName(_container) + ", SD.ParticipantSequenceKey, SD.SourceLSID, SD.SequenceNum, SD.QCState, SD.Created, SD.Modified, SD._VisitDate AS Date, PV.Day, PV.VisitRowId\n" +
                    "  FROM " + studyData.getSelectName() + " SD LEFT OUTER JOIN " + participantVisit.getSelectName() + " PV ON SD.Container=PV.Container AND SD.ParticipantId=PV.ParticipantId AND SD.SequenceNum=PV.SequenceNum \n"+
                    "  WHERE SD.container=? AND SD.datasetid=?");
            _fromSql.add(_container);
            _fromSql.add(_datasetId);
        }

        @Override
        public ButtonBarConfig getButtonBarConfig()
        {
            // Check first to see if this table has explicit button configuration.  This currently will
            // never be the case, since dataset tableinfo's don't have a place to declare button config,
            // but future changes to enable hard dataset tables may enable this.
            ButtonBarConfig config = super.getButtonBarConfig();
            if (config != null)
                return config;

            // If no button config was found for this dataset, fall back to the button config on StudyData.  This
            // lets users configure buttons that should appear on all datasets.
            StudyQuerySchema schema = new StudyQuerySchema(StudyManager.getInstance().getStudy(_container), _user, true);
            try
            {
                TableInfo studyData = schema.getTable(StudyQuerySchema.STUDY_DATA_TABLE_NAME);
                return studyData.getButtonBarConfig();
            }
            catch (UnauthorizedException e)
            {
                return null;
            }
        }

        @Override
        public String getSelectName()
        {
            return null;
        }

        @Override
        @NotNull
        public SQLFragment getFromSQL()
        {
            return _fromSql;
        }
    }


    static ColumnInfo newDatasetColumnInfo(StudyDataTableInfo tinfo, ColumnInfo from)
    {
        return new ColumnInfo(from, tinfo);
    }


    private static final Set<PropertyDescriptor> standardPropertySet = new HashSet<PropertyDescriptor>();
    private static final Map<String, PropertyDescriptor> standardPropertyMap = new CaseInsensitiveHashMap<PropertyDescriptor>();

    public static Set<PropertyDescriptor> getStandardPropertiesSet()
    {
        synchronized(standardPropertySet)
        {
            if (standardPropertySet.isEmpty())
            {
                TableInfo info = StudySchema.getInstance().getTableInfoStudyData();
                for (ColumnInfo col : info.getColumns())
                {
                    String propertyURI = col.getPropertyURI();
                    if (propertyURI == null)
                        continue;
                    String name = col.getName();
                    // hack: _visitdate is private, but we want VisitDate (for now)
                    if (name.equalsIgnoreCase("_VisitDate"))
                        name = "VisitDate";
                    PropertyType type = PropertyType.getFromClass(col.getJavaObjectClass());
                    PropertyDescriptor pd = new PropertyDescriptor(
                            propertyURI, type.getTypeUri(), name, ContainerManager.getSharedContainer());
                    standardPropertySet.add(pd);
                }
            }
            return standardPropertySet;
        }
    }

    public Domain getDomain()
    {
        return PropertyService.get().getDomain(getContainer(), getTypeURI());
    }

    public static Map<String,PropertyDescriptor> getStandardPropertiesMap()
    {
        synchronized(standardPropertyMap)
        {
            if (standardPropertyMap.isEmpty())
            {
                for (PropertyDescriptor pd : getStandardPropertiesSet())
                {
                    standardPropertyMap.put(pd.getName(), pd);
                }
            }
            return standardPropertyMap;
        }
    }


    private static String uriForName(String name)
    {
        final String StudyURI = "http://cpas.labkey.com/Study#";
        assert getStandardPropertiesMap().get(name).getPropertyURI().equals(StudyURI + name);
        return getStandardPropertiesMap().get(name).getPropertyURI();
    }

    public static String getSequenceNumURI()
    {
        return uriForName("SequenceNum");
    }

    public static String getDatasetIdURI()
    {
        return uriForName("DatasetId");
    }

    public static String getParticipantIdURI()
    {
        return uriForName("ParticipantId");
    }

    public static String getVisitDateURI()
    {
        return uriForName("VisitDate");
    }

    public static String getSiteIdURI()
    {
        return uriForName("SiteId");
    }

    public static String getCreatedURI()
    {
        return uriForName("Created");
    }

    public static String getSourceLsidURI()
    {
        return uriForName("SourceLSID");
    }

    public static String getModifiedURI()
    {
        return uriForName("Modified");
    }

    public static String getQCStateURI()
    {
        return uriForName(DataSetTable.QCSTATE_ID_COLNAME);
    }

    @Override
    protected boolean supportsPolicyUpdate()
    {
        return true;
    }

    public Integer getCohortId()
    {
        return _cohortId;
    }

    public void setCohortId(Integer cohortId)
    {
        _cohortId = cohortId;
    }

    @Nullable
    public CohortImpl getCohort()
    {
        if (_cohortId == null)
            return null;
        return Table.selectObject(StudySchema.getInstance().getTableInfoCohort(), _cohortId, CohortImpl.class);
    }

    public Integer getProtocolId()
    {
        return _protocolId;
    }

    public void setProtocolId(Integer protocolId)
    {
        _protocolId = protocolId;
    }

    @Override
    public String toString()
    {
        return "DataSetDefinition: " + getLabel() + " " + getDataSetId();
    }

    public void deleteRows(User user, Collection<String> rowLSIDs)
    {
        Container c = getContainer();

        TableInfo data = StudySchema.getInstance().getTableInfoStudyData();
        SimpleFilter filter = new SimpleFilter();
        filter.addCondition("Container", c.getId());
        filter.addCondition("DatasetId", getDataSetId());
        filter.addInClause("LSID", rowLSIDs);

        DbScope scope =  StudySchema.getInstance().getSchema().getScope();
        boolean startTransaction = !scope.isTransactionActive();
        try
        {
            if (startTransaction)
                scope.beginTransaction();

            char sep = ' ';
            StringBuilder sb = new StringBuilder();
            for (int i=0; i<rowLSIDs.size(); i++)
            {
                sb.append(sep);
                sb.append('?');
                sep = ',';
            }
            List<Object> paramList = new ArrayList<Object>(rowLSIDs);
            OntologyManager.deleteOntologyObjects(StudySchema.getInstance().getSchema(), new SQLFragment(sb.toString(), paramList), c, false);
            Table.delete(data, filter);

            deleteFromMaterialized(user, rowLSIDs);

            if (startTransaction)
                scope.commitTransaction();

            StudyManager.fireDataSetChanged(this);
        }
        catch (SQLException s)
        {
            throw new RuntimeSQLException(s);
        }
        finally
        {
            if (startTransaction)
                scope.closeConnection();
        }
    }

    public void deleteFromMaterialized(User user, Collection<String> lsids) throws SQLException
    {
        TableInfo tempTableInfo = getMaterializedTempTableInfo(user, false);
        if (tempTableInfo != null)
        {
            SimpleFilter tempTableFilter = new SimpleFilter();
            tempTableFilter.addInClause("LSID", lsids);
            Table.delete(tempTableInfo, tempTableFilter);
        }
    }

    /**
     * dataMaps have keys which are property URIs, and values which have already been converted.
     */
    public List<String> importDatasetData(Study study, User user, List<Map<String, Object>> dataMaps, long lastModified, List<String> errors, boolean checkDuplicates, boolean ensureObjects, QCState defaultQCState, Logger logger)
            throws SQLException
    {
        if (dataMaps.size() == 0)
            return Collections.emptyList();

        TableInfo tinfo = getTableInfo(user, false, false);
        Map<String, QCState> qcStateLabels = new CaseInsensitiveHashMap<QCState>();

        boolean needToHandleQCState = tinfo.getColumn(DataSetTable.QCSTATE_ID_COLNAME) != null;

        if (needToHandleQCState)
        {
            for (QCState state : StudyManager.getInstance().getQCStates(study.getContainer()))
                qcStateLabels.put(state.getLabel(), state);
        }

        //
        // Try to collect errors early.
        // Try not to be too repetitive, stop each loop after one error
        //

        // In certain cases (e.g., QC Columns), we have multiple columns with the same
        // property URI. We don't want to complain about conversion errors multiple
        // times, so we keep a set around in case we run into one and only report it once.
        MultiMap<Integer, String> rowToConversionErrorURIs = new MultiHashMap<Integer, String>();

        int rowNumber = 0;
        for (Map<String, Object> dataMap : dataMaps)
        {
            rowNumber++;
            if (needToHandleQCState)
            {
                String qcStateLabel = (String) dataMap.get(DataSetTable.QCSTATE_LABEL_COLNAME);
                // We have a non-null QC state column value.  We need to check to see if this is a known state,
                // and mark it for addition if not.
                if (qcStateLabel != null && qcStateLabel.length() > 0 && !qcStateLabels.containsKey(qcStateLabel))
                    qcStateLabels.put(qcStateLabel, null);
            }

            for (ColumnInfo col : tinfo.getColumns())
            {
                // lsid is generated
                if (col.getName().equalsIgnoreCase("lsid"))
                    continue;

                Object val = dataMap.get(col.getPropertyURI());

                boolean valueMissing;

                if (val == null)
                {
                    valueMissing = true;
                }
                else if (val instanceof MvFieldWrapper)
                {
                    MvFieldWrapper mvWrapper = (MvFieldWrapper)val;

                    if (mvWrapper.isEmpty())
                    {
                        valueMissing = true;
                    }
                    else
                    {
                        valueMissing = false;

                        if (col.isMvEnabled() && !MvUtil.isValidMvIndicator(mvWrapper.getMvIndicator(), getContainer()))
                        {
                            String columnName = col.getName() + MvColumn.MV_INDICATOR_SUFFIX;
                            errors.add(columnName + " must be a valid MV indicator.");
                            break;
                        }
                    }
                }
                else
                {
                    valueMissing = false;
                }

                if (valueMissing && !col.isNullable() && col.isUserEditable())
                {
                    // Demographic data gets special handling for visit or date fields, depending on the type of study,
                    // since there is usually only one entry for demographic data per dataset
                    if (isDemographicData())
                    {
                        if (study.getTimepointType() != TimepointType.VISIT)
                        {
                            if (col.getName().equalsIgnoreCase("Date"))
                            {
                                dataMap.put(col.getPropertyURI(), study.getStartDate());
                                continue;
                            }
                        }
                        else
                        {
                            if (col.getName().equalsIgnoreCase("SequenceNum"))
                            {
                                dataMap.put(col.getPropertyURI(), 0);
                                continue;
                            }
                        }
                    }

                    errors.add("Row " + rowNumber + " does not contain required field " + col.getName() + ".");
                }
                else if (val == StudyManager.CONVERSION_ERROR)
                {
                    if (!rowToConversionErrorURIs.containsValue(rowNumber - 1, col.getPropertyURI()))
                    {
                        // Only emit the error once for a given property uri and row
                        errors.add("Row " + rowNumber + " data type error for field " + col.getName() + "."); // + " '" + String.valueOf(val) + "'.");
                        rowToConversionErrorURIs.put(rowNumber - 1, col.getPropertyURI());
                    }
                }
            }

            if (errors.size() > 0)
                return Collections.emptyList();
        }
        if (logger != null) logger.debug("checked for missing values");

        String keyPropertyURI = null;
        String keyPropertyName = getKeyPropertyName();

        if (keyPropertyName != null)
        {
            ColumnInfo col = tinfo.getColumn(keyPropertyName);
            if (null != col)
                keyPropertyURI = col.getPropertyURI();
        }

        if (checkDuplicates)
        {
            checkForDuplicates(study, user, dataMaps, errors, logger, keyPropertyURI, keyPropertyName);
        }
        if (errors.size() > 0)
            return Collections.emptyList();

        if (getKeyManagementType() == KeyManagementType.RowId)
        {
            // If additional keys are managed by the server, we need to synchronize around
            // increments, as we're imitating a sequence.
            synchronized (MANAGED_KEY_LOCK)
            {
                return insertData(study, user, dataMaps, lastModified, errors, ensureObjects, defaultQCState, logger, qcStateLabels, needToHandleQCState, keyPropertyURI);
            }
        }
        else
        {
            return insertData(study, user, dataMaps, lastModified, errors, ensureObjects, defaultQCState, logger, qcStateLabels, needToHandleQCState, keyPropertyURI);
        }
    }

    private void checkForDuplicates(Study study, User user, List<Map<String, Object>> dataMaps, List<String> errors, Logger logger, String keyPropertyURI, String keyPropertyName)
            throws SQLException
    {
        String participantIdURI = DataSetDefinition.getParticipantIdURI();
        String visitSequenceNumURI = DataSetDefinition.getSequenceNumURI();
        String visitDateURI = DataSetDefinition.getVisitDateURI();
        HashMap<String, Map> failedReplaceMap = checkAndDeleteDupes(user, study, dataMaps);

        if (null != failedReplaceMap && failedReplaceMap.size() > 0)
        {
            StringBuilder error = new StringBuilder();
            error.append("Only one row is allowed for each ").append(StudyService.get().getSubjectNounSingular(getContainer()));

            if (!isDemographicData())
            {
                error.append(study.getTimepointType() != TimepointType.DATE ? "/Date" : "/Visit");

                if (getKeyPropertyName() != null)
                    error.append("/").append(getKeyPropertyName()).append(" Triple.  ");
                else
                    error.append(" Pair.  ");
            }
            else if (getKeyPropertyName() != null)
            {
                error.append("/").append(getKeyPropertyName()).append(" Pair.  ");
            }

            error.append("Duplicates were found in the database or imported data.");
            errors.add(error.toString());

            for (Map.Entry<String, Map> e : failedReplaceMap.entrySet())
            {
                Map m = e.getValue();
                String err = "Duplicate: " + StudyService.get().getSubjectNounSingular(getContainer()) + " = " + m.get(participantIdURI);
                if (!isDemographicData())
                {
                    if (study.getTimepointType() != TimepointType.VISIT)
                        err = err + "Date = " + m.get(visitDateURI);
                    else
                        err = err + ", VisitSequenceNum = " + m.get(visitSequenceNumURI);
                }
                if (keyPropertyURI != null)
                    err += ", " + keyPropertyName + " = " + m.get(keyPropertyURI);
                errors.add(err);
            }
        }
        if (logger != null) logger.debug("checked for duplicates");
    }

    private List<String> insertData(Study study, User user, List<Map<String, Object>> dataMaps, long lastModified, List<String> errors, boolean ensureObjects, QCState defaultQCState, Logger logger, Map<String, QCState> qcStateLabels, boolean needToHandleQCState, String keyPropertyURI)
            throws SQLException
    {
        DbScope scope = ExperimentService.get().getSchema().getScope();
        DatasetImportHelper helper = null;
        boolean startedTransaction = false;

        try
        {
            if (!scope.isTransactionActive())
            {
                startedTransaction = true;
                scope.beginTransaction();
            }

            if (needToHandleQCState)
            {
                // We first insert new QC states for any previously unknown QC labels found in the data:
                Map<String, QCState> iterableStates = new HashMap<String, QCState>(qcStateLabels);

                for (Map.Entry<String, QCState> state : iterableStates.entrySet())
                {
                    if (state.getValue() == null)
                    {
                        QCState newState = new QCState();
                        // default to public data:
                        newState.setPublicData(true);
                        newState.setLabel(state.getKey());
                        newState.setContainer(study.getContainer());
                        newState = StudyManager.getInstance().insertQCState(user, newState);
                        qcStateLabels.put(state.getKey(), newState);
                    }
                }

                // All QC states should now be stored in the database.  Next we iterate the row maps,
                // swapping in the appropriate row id for each QC label, and applying the default QC state
                // to null QC rows if appropriate:
                String qcStatePropertyURI = DataSetDefinition.getQCStateURI();

                for (Map<String, Object> dataMap : dataMaps)
                {
                    // only update the QC state ID if it isn't already explicitly specified:
                    if (dataMap.get(qcStatePropertyURI) == null)
                    {
                        Object currentStateObj = dataMap.get(DataSetTable.QCSTATE_LABEL_COLNAME);
                        String currentStateLabel = currentStateObj != null ? currentStateObj.toString() : null;

                        if (currentStateLabel != null)
                        {
                            QCState state = qcStateLabels.get(currentStateLabel);
                            assert state != null : "QC State " + currentStateLabel + " was expected but not found.";
                            dataMap.put(qcStatePropertyURI, state.getRowId());
                        }
                        else if (defaultQCState != null)
                            dataMap.put(qcStatePropertyURI, defaultQCState.getRowId());
                    }
                }
                if (logger != null) logger.debug("handled qc state");
            }

            //
            // Use OntologyManager for bulk insert
            //
            // CONSIDER: it would be nice if we could use the Table/TableInfo methods here

            // Need to generate keys if the server manages them
            if (getKeyManagementType() == KeyManagementType.RowId)
            {
                int currentKey = getMaxKeyValue();

                // Sadly, may have to create new maps, since TabLoader's aren't modifiable
                for (Map<String, Object> dataMap : dataMaps)
                {
                    // Only insert if there isn't already a value
                    if (dataMap.get(keyPropertyURI) == null)
                    {
                        currentKey++;
                        dataMap.put(keyPropertyURI, currentKey);
                    }
                }
                if (logger != null) logger.debug("generated keys");
            }
            else if (getKeyManagementType() == KeyManagementType.GUID)
            {
                // Sadly, may have to create new maps, since TabLoader's aren't modifiable
                for (Map<String, Object> dataMap : dataMaps)
                {
                    // Only insert if there isn't already a value
                    if (dataMap.get(keyPropertyURI) == null)
                    {
                        dataMap.put(keyPropertyURI, GUID.makeGUID());
                    }
                }
                if (logger != null) logger.debug("generated keys");
            }

            String typeURI = getTypeURI();
            Container c = study.getContainer();
            PropertyDescriptor[] pds = OntologyManager.getPropertiesForType(typeURI, c);
            helper = new DatasetImportHelper(user, scope.getConnection(), c, this, lastModified);
            List<String> imported = OntologyManager.insertTabDelimited(c, user, null, helper, pds, dataMaps, ensureObjects, logger);

            insertIntoMaterialized(user, imported);

            if (startedTransaction)
            {
                if (logger != null) logger.debug("starting commit...");
                scope.commitTransaction();
                startedTransaction = false;
                if (logger != null) logger.debug("commit complete");
            }
            StudyManager.fireDataSetChanged(this);
            return imported;
        }
        catch (ValidationException ve)
        {
            for (ValidationError error : ve.getErrors())
                errors.add(error.getMessage());
            return Collections.emptyList();
        }
        finally
        {
            if (helper != null)
                helper.done();
            if (startedTransaction)
            {
                scope.closeConnection();
            }
        }
    }



    public void insertIntoMaterialized(User user, Collection<String> lsids)
            throws SQLException
    {
        TableInfo tempTableInfo = getMaterializedTempTableInfo(user, false);
        if (tempTableInfo != null)
        {
            // Update the materialized temp table if it's still around
            SimpleFilter tempTableFilter = new SimpleFilter();
            tempTableFilter.addInClause("LSID", lsids);
            SQLFragment sqlSelect = Table.getSelectSQL(getTableInfo(user, false, false), null, null, null);
            SQLFragment sqlSelectInto = new SQLFragment();
            sqlSelectInto.append("INSERT INTO ").append(tempTableInfo).append(" SELECT * FROM (");
            sqlSelectInto.append(sqlSelect);
            sqlSelectInto.append(") x ");
            sqlSelectInto.append(tempTableFilter.getSQLFragment(tempTableInfo.getSqlDialect()));

            Table.execute(tempTableInfo.getSchema(), sqlSelectInto);
        }
    }

    /**
     * If all the dupes can be replaced, delete them. If not return the ones that should NOT be replaced
     * and do not delete anything
     */
    private HashMap<String, Map> checkAndDeleteDupes(User user, Study study, List<Map<String, Object>> rows) throws SQLException
    {
        if (null == rows || rows.size() == 0)
            return null;

        Container c = study.getContainer();
        DatasetImportHelper helper = new DatasetImportHelper(user, null, c, this, 0);

        // duplicate keys found that should be deleted
        Set<String> deleteSet = new HashSet<String>();

        // duplicate keys found in error
        LinkedHashMap<String,Map> noDeleteMap = new LinkedHashMap<String,Map>();

        StringBuffer sbIn = new StringBuffer();
        String sep = "";
        Map<String, Map> uriMap = new HashMap<String, Map>();
        for (Map m : rows)
        {
            String uri = helper.getURI(m);
            if (null != uriMap.put(uri, m))
                noDeleteMap.put(uri,m);
            sbIn.append(sep).append("'").append(uri).append("'");
            sep = ", ";
        }

        TableInfo tinfo = StudySchema.getInstance().getTableInfoStudyData();
        SimpleFilter filter = new SimpleFilter();
        filter.addWhereClause("LSID IN (" + sbIn + ")", new Object[]{});

        Map[] results = Table.select(tinfo, Table.ALL_COLUMNS, filter, null, Map.class);
        for (Map orig : results)
        {
            String lsid = (String) orig.get("LSID");
            Map newMap = uriMap.get(lsid);
            boolean replace = Boolean.TRUE.equals(newMap.get("replace"));
            if (replace)
            {
                deleteSet.add(lsid);
            }
            else
            {
                noDeleteMap.put(lsid, newMap);
            }
        }

        // If we have duplicates, and we don't have an auto-keyed dataset,
        // then we cannot proceed.
        if (noDeleteMap.size() > 0 && getKeyManagementType() == KeyManagementType.None)
            return noDeleteMap;

        if (deleteSet.size() == 0)
            return null;

        SimpleFilter deleteFilter = new SimpleFilter();
        StringBuffer sbDelete = new StringBuffer();
        sep = "";
        for (String s : deleteSet)
        {
            sbDelete.append(sep).append("'").append(s).append("'");
            sep = ", ";
        }
        deleteFilter.addWhereClause("LSID IN (" + sbDelete + ")", new Object[]{});
        Table.delete(StudySchema.getInstance().getTableInfoStudyData(), deleteFilter);
        OntologyManager.deleteOntologyObjects(c, deleteSet.toArray(new String[deleteSet.size()]));

        return null;
    }

    /**
     * Gets the current highest key value for a server-managed key field.
     * If no data is returned, this method returns 0.
     */
    private int getMaxKeyValue() throws SQLException
    {
        TableInfo tInfo = StudySchema.getInstance().getTableInfoStudyData();
        Integer newKey = Table.executeSingleton(tInfo.getSchema(),
                "SELECT COALESCE(MAX(CAST(_key AS INTEGER)), 0) FROM " + tInfo +
                " WHERE container = ? AND datasetid = ?",
                new Object[] { getContainer(), getDataSetId() },
                Integer.class
                );
        return newKey.intValue();
    }

    @Override
    public boolean equals(Object o)
    {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        DataSetDefinition that = (DataSetDefinition) o;

        if (_dataSetId != that._dataSetId) return false;
        if (_study != null ? !_study.equals(that._study) : that._study != null) return false;

        return true;
    }

    @Override
    public int hashCode()
    {
        int result = _study != null ? _study.hashCode() : 0;
        result = 31 * result + _dataSetId;
        return result;
    }

    private static final Pattern TABLE_NAME_PATTERN = Pattern.compile("c(\\d+)_(.+)");

    public static void purgeOrphanedDatasets()
    {
        Connection conn = null;
        try
        {
            DbScope scope = StudySchema.getInstance().getDatasetSchema().getScope();
            conn = scope.getConnection();
            ResultSet tablesRS = conn.getMetaData().getTables(scope.getDatabaseName(), "studydataset", null, new String[]{"TABLE"});
            while (tablesRS.next())
            {
                String tableName = tablesRS.getString("TABLE_NAME");
                boolean delete = true;
                Matcher matcher = TABLE_NAME_PATTERN.matcher(tableName);
                if (matcher.matches())
                {
                    int containerRowId = Integer.parseInt(matcher.group(1));
                    String datasetName = matcher.group(2);
                    Container c = ContainerManager.getForRowId(containerRowId);
                    if (c != null)
                    {
                        StudyImpl study = StudyManager.getInstance().getStudy(c);
                        if (study != null)
                        {
                            for (DataSetDefinition dataset : study.getDataSets())
                            {
                                if (dataset.getName().equalsIgnoreCase(datasetName))
                                {
                                    delete = false;
                                }
                            }
                        }
                    }
                }
                if (delete)
                {
                    Statement statement = null;
                    try
                    {
                        statement = conn.createStatement();
                        statement.execute("DROP TABLE " + StudySchema.getInstance().getDatasetSchema().getName() + "." + scope.getSqlDialect().makeLegalIdentifier(tableName));
                    }
                    finally
                    {
                        if (statement != null) { try { statement.close(); } catch (SQLException e) {} }
                    }
                }
            }


        }
        catch (SQLException e)
        {
            throw new RuntimeSQLException(e);
        }
        finally
        {
            if (conn != null)
            {
                try { conn.close(); } catch (SQLException e) {}
            }
        }
    }
}
