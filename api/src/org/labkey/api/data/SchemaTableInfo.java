/*
 * Copyright (c) 2004-2011 Fred Hutchinson Cancer Research Center
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

package org.labkey.api.data;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.labkey.api.cache.DbCache;
import org.labkey.api.collections.CaseInsensitiveHashMap;
import org.labkey.api.collections.CaseInsensitiveHashSet;
import org.labkey.api.collections.NamedObjectList;
import org.labkey.api.data.dialect.PkMetaDataReader;
import org.labkey.api.data.dialect.SqlDialect;
import org.labkey.api.etl.DataIterator;
import org.labkey.api.etl.Pump;
import org.labkey.api.etl.TableInsertDataIterator;
import org.labkey.api.exp.property.Domain;
import org.labkey.api.exp.property.DomainKind;
import org.labkey.api.query.BatchValidationException;
import org.labkey.api.query.DetailsURL;
import org.labkey.api.query.FieldKey;
import org.labkey.api.query.QueryException;
import org.labkey.api.query.QueryService;
import org.labkey.api.query.QueryUpdateService;
import org.labkey.api.query.UserSchema;
import org.labkey.api.query.ValidationException;
import org.labkey.api.security.User;
import org.labkey.api.security.permissions.Permission;
import org.labkey.api.util.ResultSetUtil;
import org.labkey.api.util.SimpleNamedObject;
import org.labkey.api.util.StringExpression;
import org.labkey.api.view.ActionURL;
import org.labkey.data.xml.ColumnType;
import org.labkey.data.xml.TableType;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;


public class SchemaTableInfo implements TableInfo, UpdateableTableInfo
{
    private static final Logger _log = Logger.getLogger(SchemaTableInfo.class);

    String _name;
    String _title = null;
    String _titleColumn = null;
    boolean _hasDefaultTitleColumn = true;
    protected List<String> _pkColumnNames = new ArrayList<String>();
    List<ColumnInfo> _pkColumns;
    protected ArrayList<ColumnInfo> columns = new ArrayList<ColumnInfo>();
    protected Map<String, ColumnInfo> colMap = null;
    DbSchema parentSchema;
    private int _tableType = TABLE_TYPE_NOT_IN_DB;
    private String _versionColumnName = null;
    private String metaDataName = null;
    private List<FieldKey> defaultVisibleColumns = null;
    private String _description;

    protected SQLFragment selectName = null;
    private String _sequence = null;
    private int _cacheSize = DbCache.DEFAULT_CACHE_SIZE;

    private DetailsURL _gridURL;
    private DetailsURL _insertURL;
    private DetailsURL _importURL;
    private DetailsURL _deleteURL;
    private DetailsURL _updateURL;
    private DetailsURL _detailsURL;
    protected ButtonBarConfig _buttonBarConfig;
    private boolean _hidden;

    protected SchemaTableInfo(DbSchema parentSchema)
    {
        this.parentSchema = parentSchema;
    }


    public SchemaTableInfo(String tableName, DbSchema parentSchema)
    {
        this(parentSchema);

        _name = tableName;
        String selectName = getSqlDialect().makeLegalIdentifier(parentSchema.getName())
                + "." + getSqlDialect().makeLegalIdentifier(tableName);
        this.selectName = new SQLFragment(selectName);
    }


    public SchemaTableInfo(String tableName, String selectName, DbSchema parentSchema)
    {
        this(parentSchema);

        _name = tableName;
        this.selectName = new SQLFragment(selectName);
    }


    public String getName()
    {
        return _name;
    }

    public String getMetaDataName()
    {
        return metaDataName;
    }


    public void setMetaDataName(String metaDataName)
    {
        this.metaDataName = metaDataName;
    }

    public void setSelectName(String s)
    {
        selectName = new SQLFragment(s);
    }

    public void setSelectName(SQLFragment s)
    {
        selectName = s;
    }

    public String getSelectName()
    {
        return selectName.getSQL();
    }


    @NotNull
    public SQLFragment getFromSQL()
    {
        return new SQLFragment().append("SELECT * FROM ").append(selectName);
    }


    @NotNull
    public SQLFragment getFromSQL(String alias)
    {
        if (null != getSelectName())
            return new SQLFragment().append(getSelectName()).append(" ").append(alias);
        else
            return new SQLFragment().append("(").append(getFromSQL()).append(") ").append(alias);
    }


    public DbSchema getSchema()
    {
        return parentSchema;
    }


    /** getSchema().getSqlDialect() */
    public SqlDialect getSqlDialect()
    {
        return parentSchema.getSqlDialect();
    }


    public List<String> getPkColumnNames()
    {
        return _pkColumnNames;
    }

    public void setPkColumnNames(List<String> pkColumnNames)
    {
        _pkColumnNames = Collections.unmodifiableList(pkColumnNames);
        _pkColumns = null;
    }

    public List<ColumnInfo> getPkColumns()
    {
        if (null == _pkColumnNames)
            return null;

        if (null == _pkColumns)
        {
            List<ColumnInfo> cols = new ArrayList<ColumnInfo>(_pkColumnNames.size());

            for (String name : _pkColumnNames)
            {
                ColumnInfo col = getColumn(name);
                assert null != col;
                cols.add(col);
            }

            _pkColumns = Collections.unmodifiableList(cols);
        }

        return _pkColumns;
    }


    public ColumnInfo getVersionColumn()
    {
        if (null == _versionColumnName)
        {
            if (null != getColumn("_ts"))
                _versionColumnName = "_ts";
            else if (null != getColumn("Modified"))
                _versionColumnName = "Modified";
        }

        return null == _versionColumnName ? null : getColumn(_versionColumnName);
    }


    public String getVersionColumnName()
    {
        if (null == _versionColumnName)
        {
            if (null != getColumn("_ts"))
                _versionColumnName = "_ts";
            else if (null != getColumn("Modified"))
                _versionColumnName = "Modified";
        }

        return _versionColumnName;
    }


    public void setVersionColumnName(String colName)
    {
        _versionColumnName = colName;
    }

    @Override
    public boolean hasDefaultTitleColumn()
    {
        return _hasDefaultTitleColumn;
    }

    public String getTitleColumn()
    {
        if (null == _titleColumn && !columns.isEmpty())
        {
            for (ColumnInfo column : columns)
            {
                if (column.isStringType() && !column.getSqlTypeName().equalsIgnoreCase("entityid"))
                {
                    _titleColumn = column.getName();
                    break;
                }
            }
            if (null == _titleColumn)
                _titleColumn = columns.get(0).getName();
        }

        return _titleColumn;
    }

    public int getTableType()
    {
        return _tableType;
    }

    public int getCacheSize()
    {
        return _cacheSize;
    }

    public String toString()
    {
        return selectName.toString();
    }


    void setTableType(String tableType)
    {
        if (tableType.equals("TABLE"))
            _tableType = TABLE_TYPE_TABLE;
        else if (tableType.equals("VIEW"))
            _tableType = TABLE_TYPE_VIEW;
        else
            _tableType = TABLE_TYPE_NOT_IN_DB;
    }

    public void setTableType(int tableType)
    {
        _tableType = tableType;
    }

    public NamedObjectList getSelectList(String columnName)
    {
        if (columnName == null)
            return getSelectList();
        
        ColumnInfo column = getColumn(columnName);
        if (column == null /*|| column.isKeyField()*/)
            return new NamedObjectList();

        return getSelectList(Collections.<String>singletonList(column.getName()));
    }


    public NamedObjectList getSelectList()
    {
        return getSelectList(getPkColumnNames());
    }

    private NamedObjectList getSelectList(List<String> columnNames)
    {
        StringBuffer pkColumnSelect = new StringBuffer();
        String sep = "";
        for (String columnName : columnNames)
        {
            pkColumnSelect.append(sep);
            pkColumnSelect.append(columnName);
            sep = "+','+";
        }

        String cacheKey = "selectArray:" + pkColumnSelect;
        NamedObjectList list = (NamedObjectList) DbCache.get(this, cacheKey);
        if (null != list)
            return list;

        String titleColumn = getTitleColumn();

        ResultSet rs = null;
        list = new NamedObjectList();
        String sql = null;

        try
        {
            sql = "SELECT " + pkColumnSelect + " AS VALUE, " + titleColumn + " AS TITLE FROM " + selectName.getSQL() + " ORDER BY " + titleColumn;

            rs = Table.executeQuery(parentSchema, sql, null);

            while (rs.next())
            {
                list.put(new SimpleNamedObject(rs.getString(1), rs.getString(2)));
            }
        }
        catch (SQLException e)
        {
            _log.error(this + "\n" + sql, e);
        }
        finally
        {
            if (null != rs)
                try
                {
                    rs.close();
                }
                catch (SQLException x)
                {
                    _log.error("getSelectList", x);
                }
        }

        DbCache.put(this, cacheKey, list);
        return list;
    }

    public ColumnInfo getColumn(String colName)
    {
        if (null == colName)
            return null;

        // HACK: need to invalidate in case of addition (doesn't handle mixed add/delete, but I don't think we delete
        if (colMap != null && columns.size() != colMap.size())
            colMap = null;

        if (null == colMap)
        {
            Map<String, ColumnInfo> m = new CaseInsensitiveHashMap<ColumnInfo>();
            for (ColumnInfo colInfo : columns)
            {
                m.put(colInfo.getName(), colInfo);
            }
            colMap = m;
        }

        // TODO: Shouldn't do this -- ":" is a legal character in column names
        int colonIndex;
        if ((colonIndex = colName.indexOf(":")) != -1)
        {
            String first = colName.substring(0, colonIndex);
            String rest = colName.substring(colonIndex + 1);
            ColumnInfo fkColInfo = colMap.get(first);

            // Fall through if this doesn't look like an FK -- : is a legal character
            if (fkColInfo != null && fkColInfo.getFk() != null)
                return fkColInfo.getFkTableInfo().getColumn(rest);
        }

        return colMap.get(colName);
    }


    public void addColumn(ColumnInfo column)
    {
        columns.add(column);
//        assert !column.isAliasSet();       // TODO: Investigate -- had to comment this out since ExprColumn() sets alias
        assert null == column.getFieldKey().getParent();
        assert column.getName().equals(column.getFieldKey().getName());
        assert column.lockName();
        // set alias explicitly, so that getAlias() won't call makeLegalName() and mangle it
        column.setAlias(column.getName());
    }


    public List<ColumnInfo> getColumns()
    {
        return Collections.unmodifiableList(columns);
    }


    public List<ColumnInfo> getUserEditableColumns()
    {
        ArrayList<ColumnInfo> userEditableColumns = new ArrayList<ColumnInfo>(columns.size());
        for (ColumnInfo col : columns)
            if (col.isUserEditable())
                userEditableColumns.add(col);

        return Collections.unmodifiableList(userEditableColumns);
    }


    public List<ColumnInfo> getColumns(String colNames)
    {
        String[] colNameArray = colNames.split(",");
        return getColumns(colNameArray);
    }

    public List<ColumnInfo> getColumns(String... colNameArray)
    {
        List<ColumnInfo> ret = new ArrayList<ColumnInfo>(colNameArray.length);
        for (String name : colNameArray)
        {
            ret.add(getColumn(name.trim()));
        }
        return Collections.unmodifiableList(ret);
    }


    public Set<String> getColumnNameSet()
    {
        Set<String> nameSet = new HashSet<String>();
        for (ColumnInfo aColumnList : columns)
        {
            nameSet.add(aColumnList.getName());
        }

        return Collections.unmodifiableSet(nameSet);
    }


    public void loadFromMetaData(DatabaseMetaData dbmd, String catalogName, String schemaName) throws SQLException
    {
        loadColumnsFromMetaData(dbmd, catalogName, schemaName);

        ResultSet rs;

        if (getSqlDialect().treatCatalogsAsSchemas())
            rs = dbmd.getPrimaryKeys(schemaName, null, metaDataName);
        else
            rs = dbmd.getPrimaryKeys(catalogName, schemaName, metaDataName);

        // Use TreeMap to order columns by keySeq
        Map<Integer, String> pkMap = new TreeMap<Integer, String>();
        int columnCount = 0;
        PkMetaDataReader reader = getSqlDialect().getPkMetaDataReader(rs);

        try
        {
            while (rs.next())
            {
                columnCount++;
                String colName = reader.getName();
                ColumnInfo colInfo = getColumn(colName);
                assert null != colInfo;

                colInfo.setKeyField(true);
                int keySeq = reader.getKeySeq();

                // If we don't have sequence information (e.g., SAS doesn't return it) then use 1-based counter as a backup
                if (0 == keySeq)
                    keySeq = columnCount;

                pkMap.put(keySeq, colName);
            }
        }
        finally
        {
            ResultSetUtil.close(rs);
        }

        setPkColumnNames(new ArrayList<String>(pkMap.values()));
    }


    private void loadColumnsFromMetaData(DatabaseMetaData dbmd, String catalogName, String schemaName) throws SQLException
    {
        Collection<ColumnInfo> meta = ColumnInfo.createFromDatabaseMetaData(dbmd, catalogName, schemaName, this);
        for (ColumnInfo c : meta)
            addColumn(c);
    }


    void copyToXml(TableType xmlTable, boolean bFull)
    {
        xmlTable.setTableName(_name);
        if (_tableType == TABLE_TYPE_TABLE)
            xmlTable.setTableDbType("TABLE");
        else if (_tableType == TABLE_TYPE_VIEW)
            xmlTable.setTableDbType("VIEW");
        else
            xmlTable.setTableDbType("NOT_IN_DB");


        if (bFull)
        {
            // changed to write out the value of property directly, without the
            // default calculation applied by the getter
            if (null != _title)
                xmlTable.setTableTitle(_title);
            if (null != _pkColumnNames && _pkColumnNames.size() > 0)
                xmlTable.setPkColumnName(StringUtils.join(_pkColumnNames, ','));
            if (null != _titleColumn)
                xmlTable.setTitleColumn(_titleColumn);
            if (null != _versionColumnName)
                xmlTable.setVersionColumnName(_versionColumnName);
            if (_hidden)
                xmlTable.setHidden(true);
        }

        TableType.Columns xmlColumns = xmlTable.addNewColumns();
        ColumnType xmlCol;

        for (ColumnInfo columnInfo : columns)
        {
            xmlCol = xmlColumns.addNewColumn();
            columnInfo.copyToXml(xmlCol, bFull);
        }
    }


    // TODO: Remove merge param?  Always true...
    void loadFromXml(TableType xmlTable, boolean merge)
    {
        //If merging with DB MetaData, don't overwrite pk
        if (!merge || null == _pkColumnNames || _pkColumnNames.isEmpty())
        {
            String pkColumnName = xmlTable.getPkColumnName();
            if (null != pkColumnName && pkColumnName.length() > 0)
            {
                setPkColumnNames(Arrays.asList(pkColumnName.split(",")));
            }
        }
        if (!merge)
        {
            setTableType(xmlTable.getTableDbType());
        }

        //Override with the table name from the schema so casing is nice...
        _name = xmlTable.getTableName();
        _description = xmlTable.getDescription();
        _hidden = xmlTable.getHidden();
        _title = xmlTable.getTableTitle();
        _titleColumn = xmlTable.getTitleColumn();
        if (null != _titleColumn)
            _hasDefaultTitleColumn = false;
        if (xmlTable.isSetCacheSize())
            _cacheSize = xmlTable.getCacheSize();

        if (xmlTable.getGridUrl() != null)
        {
            _gridURL = DetailsURL.fromString(xmlTable.getGridUrl());
        }
        if (xmlTable.isSetImportUrl())
        {
            if (StringUtils.isBlank(xmlTable.getImportUrl()))
                _importURL = LINK_DISABLER;
            else
                _importURL = DetailsURL.fromString(xmlTable.getImportUrl());
        }
        if (xmlTable.getInsertUrl() != null)
        {
            _insertURL = DetailsURL.fromString(xmlTable.getInsertUrl());
        }
        if (xmlTable.getDeleteUrl() != null)
        {
            _deleteURL = DetailsURL.fromString(xmlTable.getDeleteUrl());
        }
        if (xmlTable.getUpdateUrl() != null)
        {
            _updateURL = DetailsURL.fromString(xmlTable.getUpdateUrl());
        }
        if (xmlTable.getTableUrl() != null)
        {
            _detailsURL = DetailsURL.fromString(xmlTable.getTableUrl());
        }

        ColumnType[] xmlColumnArray = xmlTable.getColumns().getColumnArray();

        if (!merge)
            columns = new ArrayList<ColumnInfo>();

        List<ColumnType> wrappedColumns = new ArrayList<ColumnType>();

        for (ColumnType xmlColumn : xmlColumnArray)
        {
            if (xmlColumn.getWrappedColumnName() != null)
            {
                wrappedColumns.add(xmlColumn);
            }
            else
            {
                ColumnInfo colInfo = null;

                if (merge && getTableType() != TABLE_TYPE_NOT_IN_DB)
                {
                    colInfo = getColumn(xmlColumn.getColumnName());
                    if (null != colInfo)
                        colInfo.loadFromXml(xmlColumn, true);
                }

                if (null == colInfo)
                {
                    colInfo = new ColumnInfo(xmlColumn.getColumnName(), this);
                    colInfo.setNullable(true); // default is isNullable()==false
                    addColumn(colInfo);
                    colInfo.loadFromXml(xmlColumn, false);
                }
            }
        }

        for (ColumnType wrappedColumnXml : wrappedColumns)
        {
            ColumnInfo column = getColumn(wrappedColumnXml.getWrappedColumnName());

            if (column != null && getColumn(wrappedColumnXml.getColumnName()) == null)
            {
                ColumnInfo wrappedColumn = new WrappedColumn(column, wrappedColumnXml.getColumnName());
                wrappedColumn.loadFromXml(wrappedColumnXml, false);
                addColumn(wrappedColumn);
            }
        }

        if (xmlTable.getButtonBarOptions() != null)
            _buttonBarConfig = new ButtonBarConfig(xmlTable.getButtonBarOptions());
    }


    public String getSequence()
    {
        return _sequence;
    }

    public void setSequence(String sequence)
    {
        assert null == _sequence : "Sequence already set for " + getName() + "! " + _sequence + " vs. " + sequence;
        _sequence = sequence;
    }

    public String decideAlias(String name)
    {
        return name;
    }

    public ActionURL getGridURL(Container container)
    {
        if (_gridURL != null)
            return _gridURL.copy(container).getActionURL();
        return null;
    }

    public ActionURL getInsertURL(Container container)
    {
        if (_insertURL != null)
            return _insertURL.copy(container).getActionURL();
        return null;
    }

    @Override
    public ActionURL getImportDataURL(Container container)
    {
        if (null == _importURL)
            return null;
        if (LINK_DISABLER == _importURL)
            return LINK_DISABLER_ACTION_URL;
        return _importURL.copy(container).getActionURL();
    }

    public ActionURL getDeleteURL(Container container)
    {
        if (_deleteURL != null)
            return _deleteURL.copy(container).getActionURL();
        return null;
    }

    public StringExpression getUpdateURL(Set<FieldKey> columns, Container container)
    {
        if (_updateURL != null && _updateURL.validateFieldKeys(columns))
        {
            return _updateURL.copy(container);
        }
        return null;
    }

    public StringExpression getDetailsURL(Set<FieldKey> columns, Container container)
    {
        if (_detailsURL != null && _detailsURL.validateFieldKeys(columns))
        {
            return _detailsURL.copy(container);
        }
        return null;
    }

    @Override
    public boolean hasDetailsURL()
    {
        return _detailsURL != null;
    }

    public Set<FieldKey> getDetailsURLKeys()
    {
        HashSet<FieldKey> set = new HashSet<FieldKey>();
        if (null != _detailsURL)
            set.addAll(_detailsURL.getFieldKeys());
        return set;
    }


    public boolean hasPermission(User user, Class<? extends Permission> perm)
    {
        return false;
    }

    public MethodInfo getMethod(String name)
    {
        return null;
    }

    public List<FieldKey> getDefaultVisibleColumns()
    {
        if (defaultVisibleColumns != null)
            return defaultVisibleColumns;
        return Collections.unmodifiableList(QueryService.get().getDefaultVisibleColumns(getColumns()));
    }

    public void setDefaultVisibleColumns(Iterable<FieldKey> keys)
    {
        defaultVisibleColumns = new ArrayList<FieldKey>();
        for (FieldKey key : keys)
            defaultVisibleColumns.add(key);
    }

    /** Used by SimpleUserSchema and external schemas to hide tables from the list of visible tables.  Not the same as isPublic(). */
    public boolean isHidden()
    {
        return _hidden;
    }

    public boolean isPublic()
    {
        //schema table infos are not public (i.e., not accessible from Query)
        return false;
    }

    public String getPublicName()
    {
        return null;
    }

    public String getPublicSchemaName()
    {
        return null;
    }

    public boolean needsContainerClauseAdded()
    {
        return true;
    }

    public ContainerFilter getContainerFilter()
    {
        return null;
    }

    public boolean isMetadataOverrideable()
    {
        return false;
    }

    @Override
    public void overlayMetadata(String tableName, UserSchema schema, Collection<QueryException> errors)
    {
        // no-op, we don't support metadata overrides
    }

    @Override
    public void overlayMetadata(TableType metadata, UserSchema schema, Collection<QueryException> errors)
    {
        // no-op, we don't support metadata overrides
    }

    public ButtonBarConfig getButtonBarConfig()
    {
        return _buttonBarConfig;
    }

    public void setButtonBarConfig(ButtonBarConfig config)
    {
        _buttonBarConfig = config;
    }
    
    public ColumnInfo getLookupColumn(ColumnInfo parent, String name)
    {
        ForeignKey fk = parent.getFk();
        if (fk == null)
            return null;
        return fk.createLookupColumn(parent, name);
    }

    public String getDescription()
    {
        return _description;
    }

    public void setDescription(String description)
    {
        _description = description;        
    }

    @Nullable
    public Domain getDomain()
    {
        return null;
    }

    @Nullable
    public DomainKind getDomainKind()
    {
        return null;
    }

    @Nullable
    public QueryUpdateService getUpdateService()
    {
        return null;
    }

    @Override @NotNull
    public Collection<QueryService.ParameterDecl> getNamedParameters()
    {
        return Collections.EMPTY_LIST;
    }

    @Override
    public void fireBatchTrigger(Container c, TriggerType type, boolean before, BatchValidationException errors, Map<String, Object> extraContext) throws BatchValidationException
    {
        throw new UnsupportedOperationException("Table triggers not yet supported on schema tables");
    }

    @Override
    public void fireRowTrigger(Container c, TriggerType type, boolean before, int rowNumber, Map<String, Object> newRow, Map<String, Object> oldRow, Map<String, Object> extraContext) throws ValidationException
    {
        throw new UnsupportedOperationException("Table triggers not yet supported on schema tables");
    }


    //
    // UpdateableTableInfo
    //

    @Override
    public boolean insertSupported()
    {
        return true;
    }

    @Override
    public boolean updateSupported()
    {
        return true;
    }

    @Override
    public boolean deleteSupported()
    {
        return true;
    }

    @Override
    public TableInfo getSchemaTableInfo()
    {
        return this;
    }

    @Override
    public ObjectUriType getObjectUriType()
    {
        return ObjectUriType.schemaColumn;
    }

    @Override
    public String getObjectURIColumnName()
    {
        return null;
    }

    @Override
    public String getObjectIdColumnName()
    {
        return null;
    }

    @Override
    public CaseInsensitiveHashMap<String> remapSchemaColumns()
    {
        return null;
    }

    @Override
    public CaseInsensitiveHashSet skipProperties()
    {
        return null;
    }

    @Override
    public int persistRows(DataIterator data, BatchValidationException errors)
    {
        TableInsertDataIterator insert = TableInsertDataIterator.create(data, this, errors);
        new Pump(insert, errors).run();
        return insert.getExecuteCount();
    }

    @Override
    public Parameter.ParameterMap insertStatement(Connection conn, User user) throws SQLException
    {
        return Table.insertStatement(conn, this, null, user, false, true);
    }

    @Override
    public Parameter.ParameterMap updateStatement(Connection conn, User user, Set<String> columns) throws SQLException
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public Parameter.ParameterMap deleteStatement(Connection conn) throws SQLException
    {
        return Table.deleteStatement(conn, this);
    }


    /** Move an existing column to a different spot in the ordered list */
    public void setColumnIndex(ColumnInfo c, int i)
    {
        if (!columns.remove(c))
        {
            throw new IllegalArgumentException("Column " + c + " is not part of table " + this);
        }
        columns.add(i, c);
    }
}
