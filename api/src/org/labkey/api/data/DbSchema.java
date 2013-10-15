/*
 * Copyright (c) 2004-2013 Fred Hutchinson Cancer Research Center
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

import org.apache.log4j.Logger;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.junit.Assert;
import org.junit.Test;
import org.labkey.api.cache.DbCache;
import org.labkey.api.collections.CaseInsensitiveHashMap;
import org.labkey.api.data.dialect.SqlDialect;
import org.labkey.api.module.Module;
import org.labkey.api.module.ModuleLoader;
import org.labkey.api.ms2.MS2Service;
import org.labkey.api.query.TableSorter;
import org.labkey.api.resource.Resource;
import org.labkey.api.resource.ResourceRef;
import org.labkey.api.security.SecurityPolicyManager;
import org.labkey.api.security.User;
import org.labkey.api.settings.AppProps;
import org.labkey.api.test.TestTimeout;
import org.labkey.api.util.JunitUtil;
import org.labkey.api.util.Pair;
import org.labkey.api.util.ResultSetUtil;
import org.labkey.api.util.TestContext;
import org.labkey.api.view.NotFoundException;
import org.labkey.data.xml.TableType;
import org.labkey.data.xml.TablesDocument;

import java.io.IOException;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

public class DbSchema
{
    private static final Logger _log = Logger.getLogger(DbSchema.class);

    private final String _name;
    private final DbSchemaType _type;
    private final DbScope _scope;
    private final Map<String, String> _metaDataTableNames;  // Union of all table names from database and schema.xml
    private final Map<String, TableType> _tableXmlMap = new CaseInsensitiveHashMap<>();

    private ResourceRef _resourceRef = null;

    protected DbSchema(String name, DbSchemaType type, DbScope scope, Map<String, String> metaDataTableNames)
    {
        _name = name;
        _type = type;
        _scope = scope;
        _metaDataTableNames = metaDataTableNames;
    }


    public static @NotNull DbSchema get(String fullyQualifiedSchemaName)
    {
        // Quick check to avoid creating Pair object in most common case
        int dot = fullyQualifiedSchemaName.indexOf('.');

        if (-1 == dot)
        {
            return DbScope.getLabkeyScope().getSchema(fullyQualifiedSchemaName);
        }
        else
        {
            Pair<DbScope, String> scopeAndSchemaName = getDbScopeAndSchemaName(fullyQualifiedSchemaName);

            return scopeAndSchemaName.first.getSchema(scopeAndSchemaName.second);
        }
    }


    // "core" returns <<labkey scope>, "core">
    // "external.myschema" returns <<external scope>, "myschema">
    public static Pair<DbScope, String> getDbScopeAndSchemaName(String fullyQualifiedSchemaName)
    {
        int dot = fullyQualifiedSchemaName.indexOf('.');

        if (-1 == dot)
        {
            return new Pair<>(DbScope.getLabkeyScope(), fullyQualifiedSchemaName);
        }
        else
        {
            String dsName = fullyQualifiedSchemaName.substring(0, dot);
            DbScope scope = DbScope.getDbScope(dsName);

            if (null == scope)
            {
                scope = DbScope.getDbScope(dsName + "DataSource");

                if (null == scope)
                {
                    throw new NotFoundException("Data source \"" + dsName + "\" has not been configured");
                }
            }

            return new Pair<>(scope, fullyQualifiedSchemaName.substring(dot + 1));
        }
    }


    public Resource getSchemaResource() throws IOException
    {
        return getSchemaResource(getDisplayName());
    }


    public Resource getSchemaResource(String fullyQualifiedSchemaName) throws IOException
    {
        Module module = ModuleLoader.getInstance().getModuleForSchemaName(fullyQualifiedSchemaName);

        if (null == module)
        {
            _log.debug("no module for schema '" + fullyQualifiedSchemaName + "'");
            return null;
        }

        return getSchemaResource(module, fullyQualifiedSchemaName);
    }


    protected Resource getSchemaResource(Module module, String xmlFilePrefix) throws IOException
    {
        Resource r = module.getModuleResource("/schemas/" + xmlFilePrefix + ".xml");
        return null != r && r.isFile() ? r : null;
    }


    public static @NotNull DbSchema createFromMetaData(DbScope scope, String requestedSchemaName, DbSchemaType type) throws SQLException
    {
        Map<String, String> metaDataTableNames = new CaseInsensitiveHashMap<>();

        String metaDataName = loadTableNames(scope, requestedSchemaName, metaDataTableNames);

        // If we found no tables and this is a case-sensitive database (e.g., PostgreSQL), then the caller
        // may be using the wrong casing; query all schemas and try to find a match. See #12210.
        if (metaDataTableNames.isEmpty() && scope.getSqlDialect().isCaseSensitive())
        {
            for (String name : scope.getSchemaNames())
            {
                // If we find this exact name then it really is a zero-table schema... continue on
                if (name.equals(requestedSchemaName))
                    break;

                // If we find a different casing, then use that version of the name and reload table meta data
                if (name.equalsIgnoreCase(requestedSchemaName))
                {
                    _log.warn("Could not find requested schema \"" + requestedSchemaName + "\"; resolving to schema \"" + name + "\"");
                    metaDataName = loadTableNames(scope, name, metaDataTableNames);
                    break;  // Stop at the first one... we don't support multiple schemas with the same name but different casing
                }
            }
        }

        scope.invalidateAllTables(metaDataName, type); // Need to invalidate the table cache

        if ("labkey".equals(metaDataName))
            return new LabKeyDbSchema(type, scope, metaDataTableNames);
        else
            return new DbSchema(metaDataName, type, scope, metaDataTableNames);
    }


    // Special subclass to handle the peculiarities of the "labkey" schema that gets created in all module-required
    // extenernal data sources. Key changes:
    // 1. Override getDisplayName() to eliminate the standard datasource prefix, so labkey-*-*.sql scripts are found
    // 2. Override getSchemaResource() to resolve labkey.xml
    public static class LabKeyDbSchema extends DbSchema
    {
        public LabKeyDbSchema(DbSchemaType type, DbScope scope, Map<String, String> metaDataTableNames)
        {
            super("labkey", type, scope, metaDataTableNames);
        }

        @Override
        public String getDisplayName()
        {
            return "labkey";
        }

        @Override
        public Resource getSchemaResource(String schemaName) throws IOException
        {
            // CoreModule does not claim the "labkey" schema because we don't want to install this schema in the labkey
            // datasource. Override here so we find labkey.xml; this eliminates warnings and supports junit tests.
            return getSchemaResource(ModuleLoader.getInstance().getCoreModule(), schemaName);
        }

        @Override
        public String toString()
        {
            return "LabKeyDbSchema in \"" + getScope().getDisplayName() + "\"";
        }
    }


    // Populates metaDataTableNames map with a list of table names from the requested schema. Returns the canonical name of this schema, according to the database.
    private static String loadTableNames(DbScope scope, String schemaName, final Map<String, String> metaDataTableNames) throws SQLException
    {
        TableMetaDataLoader loader = new TableMetaDataLoader(scope, schemaName, "%") {
            @Override
            protected void handleTable(String name, ResultSet rs, DatabaseMetaData dbmd) throws SQLException
            {
                metaDataTableNames.put(name, name);
            }
        };

        return loader.load();
    }


    // Base class that pulls table meta data from the database, based on a supplied table pattern.  This lets us share
    // code between schema load (when we capture just the table names for all tables) and table load (when we capture
    // all properties of just a single table).  We want consistent transaction, exception, and filtering behavior in
    // both cases.
    private static abstract class TableMetaDataLoader
    {
        private final String _tableNamePattern;
        private final String _requestedSchemaName;
        private final DbScope _scope;

        private TableMetaDataLoader(DbScope scope, String requestedSchemaName, String tableNamePattern)
        {
            _tableNamePattern = tableNamePattern;
            _requestedSchemaName = requestedSchemaName;
            _scope = scope;
        }

        protected abstract void handleTable(String name, ResultSet rs, DatabaseMetaData dbmd) throws SQLException;

        String load() throws SQLException
        {
            SqlDialect dialect = _scope.getSqlDialect();
            String dbName = _scope.getDatabaseName();

            String metaDataSchemaName = null;
            Connection conn = null;

            try
            {
                conn = _scope.getConnection();
                DatabaseMetaData dbmd = conn.getMetaData();

                String[] types = {"TABLE", "VIEW",};

                ResultSet rs;

                if (dialect.treatCatalogsAsSchemas())
                    rs = dbmd.getTables(_requestedSchemaName, null, _tableNamePattern, types);
                else
                    rs = dbmd.getTables(dbName, _requestedSchemaName, _tableNamePattern, types);

                try
                {
                    while (rs.next())
                    {
                        String tableName = rs.getString("TABLE_NAME").trim();

                        if (null == metaDataSchemaName)
                        {
                            // Get the canonical name for this schema... which may not match the requested name
                            if (dialect.treatCatalogsAsSchemas())
                                metaDataSchemaName = rs.getString("TABLE_CAT").trim();
                            else
                                metaDataSchemaName = rs.getString("TABLE_SCHEM").trim();
                        }

                        // Ignore system tables
                        if (dialect.isSystemTable(tableName))
                            continue;

                        // skip if it looks like one of our temp table names: name$<32hexchars>
                        if (tableName.length() > 33 && tableName.charAt(tableName.length() - 33) == '$')
                            continue;

                        handleTable(tableName, rs, dbmd);
                    }
                }
                finally
                {
                    ResultSetUtil.close(rs);
                }
            }
            catch (SQLException e)
            {
                _log.error("Exception loading schema \"" + _requestedSchemaName + "\" from database metadata", e);
                throw e;
            }
            finally
            {
                try
                {
                    if (null != conn && !_scope.isTransactionActive())
                        _scope.releaseConnection(conn);
                }
                catch (Exception x)
                {
                    _log.error("DbSchema.createFromMetaData()", x);
                }
            }

            return null != metaDataSchemaName ? metaDataSchemaName : _requestedSchemaName;
        }
    }


    @Nullable SchemaTableInfo loadTable(String tableName) throws SQLException
    {
        // When querying table metadata we must use the name from the database
        String metaDataTableName = _metaDataTableNames.get(tableName);

        // Didn't find a hard table with that name... maybe it's a query. See #12822
        if (null == metaDataTableName)
            return null;

        SchemaTableInfo ti = createTableFromDatabaseMetaData(metaDataTableName);
        TableType xmlTable = _tableXmlMap.get(tableName);

        if (null != xmlTable)
        {
            if (null == ti)
            {
                ti = new SchemaTableInfo(this, DatabaseTableType.NOT_IN_DB, xmlTable.getTableName());
            }

            try
            {
                ti.loadTablePropertiesFromXml(xmlTable);
            }
            catch (IllegalArgumentException e)
            {
                _log.error("Malformed XML in " + ti.getSchema() + "." + xmlTable.getTableName(), e);
            }
        }

        if (null != ti)
            ti.setLocked(true);
        return ti;
    }


    SchemaTableInfo createTableFromDatabaseMetaData(final String tableName) throws SQLException
    {
        SingleTableMetaDataLoader loader = new SingleTableMetaDataLoader(getScope(), getName(), tableName);

        loader.load();

        return loader.getTableInfo();
    }


    private class SingleTableMetaDataLoader extends TableMetaDataLoader
    {
        private final String _tableName;
        private SchemaTableInfo _ti = null;

        private SingleTableMetaDataLoader(DbScope scope, String schemaName, String tableName)
        {
            super(scope, schemaName, tableName);
            _tableName = tableName;
        }

        @Override
        protected void handleTable(String name, ResultSet rs, DatabaseMetaData dbmd) throws SQLException
        {
            assert _tableName.equalsIgnoreCase(name);
            DatabaseTableType tableType = DatabaseTableType.valueOf(DatabaseTableType.class, rs.getString("TABLE_TYPE"));
            _ti = new SchemaTableInfo(DbSchema.this, tableType, _tableName);
            String description = rs.getString("REMARKS");
            if (null != description && !"No comments".equals(description))  // Consider: Move "No comments" exclusion to SAS dialect?
                _ti.setDescription(description);
        }

        private SchemaTableInfo getTableInfo()
        {
            return _ti;
        }
    }


    public static Set<DbSchema> getAllSchemasToTest()
    {
        Set<DbSchema> schemas = new LinkedHashSet<>();
        List<Module> modules = ModuleLoader.getInstance().getModules();

        for (Module module : modules)
        {
            try
            {
                schemas.addAll(module.getSchemasToTest());
            }
            catch (Exception e)
            {
                _log.error("Exception retrieving schemas for module \"" + module + "\"", e);
            }
        }

        return schemas;
    }


    // Unqualified schema name
    public String getName()
    {
        return _name;
    }

    // Schema name qualified with data source display name (e.g., external.myschema). Resources like schema.xml files
    // and sql scripts are found using this name.
    public String getDisplayName()
    {
        return getDisplayName(_scope, getName());
    }

    // TODO: Provide mechanism to override this in schema.xml
    public String getQuerySchemaName()
    {
        return (_scope.isLabKeyScope() ? "" : _scope.getDisplayName() + "_") + getName();
    }

    // Schema name qualified with data source display name (e.g., external.myschema). Resources like schema.xml files
    // and sql scripts are found using this name.
    public static String getDisplayName(DbScope scope, String name)
    {
        return (scope.isLabKeyScope() ? "" : scope.getDisplayName() + ".") + name;
    }

    public SqlDialect getSqlDialect()
    {
        return _scope.getSqlDialect();
    }

    boolean isStale()
    {
        return isModuleSchema() && _resourceRef.isStale() && _resourceRef.getResource().exists();
    }

    public DbSchemaType getType()
    {
        return _type;
    }

    public boolean isModuleSchema()
    {
        return getType() == DbSchemaType.Module;
    }

    Resource getResource()
    {
        return _resourceRef != null ? _resourceRef.getResource() : null;
    }

    void setResource(Resource r)
    {
        if (_resourceRef == null || _resourceRef.getResource() != r)
            _resourceRef = new ResourceRef(r);
        else
            _resourceRef.updateVersionStamp();
    }

    void setTablesDocument(TablesDocument tablesDoc)
    {
        TableType[] xmlTables = tablesDoc.getTables().getTableArray();

        for (TableType xmlTable : xmlTables)
        {
            String xmlTableName = xmlTable.getTableName();
            _tableXmlMap.put(xmlTable.getTableName(), xmlTable);

            // Tables in schema.xml but not in the database need to be added to _tableNames
            if (!_metaDataTableNames.containsKey(xmlTableName))
            {
                _metaDataTableNames.put(xmlTableName, xmlTableName);
            }
        }
    }


    public Collection<String> getTableNames()
    {
        return Collections.unmodifiableCollection(new LinkedList<>(_metaDataTableNames.keySet()));
    }

    public SchemaTableInfo getTable(String tableName)
    {
        // Scope holds cache for all its tables
        return _scope.getTable(this, tableName);
    }

    /**
     * Get a topologically sorted list of TableInfos within this schema.
     * Not all existing schemas are supported yet since their FKs don't expose the query tableName they join to or they contain loops.
     *
     * @throws IllegalStateException if a loop is detected.
     */
    public List<TableInfo> getSortedTables()
    {
        return TableSorter.sort(this);
    }

    public DbScope getScope()
    {
        return _scope;
    }

    public void dropTableIfExists(String objName) throws SQLException
    {
        getSqlDialect().dropIfExists(this, objName, "TABLE", null);
        getSqlDialect().dropIfExists(this, objName, "VIEW", null);
    }

    public void dropIndexIfExists(String objName, String indexName) throws SQLException
    {
        getSqlDialect().dropIfExists(this, objName, "INDEX", indexName);
    }


    @Override
    public String toString()
    {
        return "DbSchema " + getDisplayName();
    }


    @TestTimeout(120)
    public static class TestCase extends Assert
    {
        // Compare schema XML vs. meta data for all module schemas
        @Test
        public void testSchemaXML() throws Exception
        {
            Set<DbSchema> schemas = DbSchema.getAllSchemasToTest();

            for (DbSchema schema : schemas)
                testSchemaXml(schema);
        }


        // Do a simple select from every table in every module schema. This ends up invoking validation code
        // in Table that checks PKs and columns, further validating the schema XML file.
        @Test
        public void testTableSelect()
        {
            Set<DbSchema> schemas = DbSchema.getAllSchemasToTest();

            for (DbSchema schema : schemas)
            {
                for (String tableName : schema.getTableNames())
                {
                    try
                    {
                        TableInfo table = schema.getTable(tableName);

                        if (null == table)
                            fail("Could not create table instance: " + tableName);

                        if (table.getTableType() == DatabaseTableType.NOT_IN_DB)
                            continue;

                        TableSelector selector = new TableSelector(table);
                        selector.setMaxRows(10);
                        selector.getMapCollection();
                    }
                    catch (Exception e)
                    {
                        throw new RuntimeException("Exception testing table " + schema.getDisplayName() + "." + tableName, e);
                    }
                }
            }
        }


        private void testSchemaXml(DbSchema schema) throws Exception
        {
            String sOut = TableXmlUtils.compareXmlToMetaData(schema, false, false);

            // Not using assertNotNull, because it appends non-legal HTML text to our message
            if (null != sOut)
                fail("<div>Errors in schema " + schema.getDisplayName()
                     + ".xml.  <a href=\"" + AppProps.getInstance().getContextPath() + "/admin/getSchemaXmlDoc.view?dbSchema="
                     + schema.getDisplayName() + "\">Click here for an XML doc with fixes</a>."
                     + "<br>"
                     + sOut + "</div>");

/* TODO: Uncomment once we change to all generic type names in schema .xml files

            StringBuilder typeErrors = new StringBuilder();

            for (TableInfo ti : schema.getTables())
            {
                for (ColumnInfo ci : ti.getColumns())
                {
                    String sqlTypeName = ci.getSqlTypeName();

                    if ("OTHER".equals(sqlTypeName))
                        typeErrors.append(ti.getName()).append(".").append(ci.getColumnName()).append(": getSqlTypeName() returned 'OTHER'<br>");

                    int sqlTypeInt = ci.getSqlTypeInt();

                    if (Types.OTHER == sqlTypeInt)
                        typeErrors.append(ti.getName()).append(".").append(ci.getColumnName()).append(": getSqlTypeInt() returned 'Types.OTHER'<br>");
                }
            }

            assertTrue("<div>Type errors in schema " + schema.getName() + ":<br><br>" + typeErrors + "<div>", "".equals(typeErrors.toString()));
*/
        }

        @Test
        public void testTransactions() throws Exception
        {
            TestSchema test = TestSchema.getInstance();
            DbSchema testSchema = test.getSchema();
            TableInfo testTable = test.getTableInfoTestTable();
            TestContext ctx = TestContext.get();

            assertNotNull(testTable);

            assertFalse("In transaction when shouldn't be.", testSchema.getScope().isTransactionActive());

            Map<String, Object> m = new HashMap<>();
            m.put("DatetimeNotNull", new Date());
            m.put("BitNotNull", Boolean.TRUE);
            m.put("Text", "Added by Transaction Test Suite");
            m.put("IntNotNull", 0);
            m.put("Container", JunitUtil.getTestContainer());

            Integer rowId;
            testSchema.getScope().beginTransaction();
            assertTrue("Not in transaction when should be.", testSchema.getScope().isTransactionActive());
            m = Table.insert(ctx.getUser(), testTable, m);
            rowId = ((Integer) m.get("RowId"));
            assertNotNull("Inserted Row doesn't have Id", rowId);
            assertTrue(rowId != 0);

            testSchema.getScope().commitTransaction();
            assertFalse("In transaction when shouldn't be.", testSchema.getScope().isTransactionActive());

            SimpleFilter filter = new SimpleFilter("RowId", rowId);
            ResultSet rs = Table.select(testTable, Table.ALL_COLUMNS, filter, null);
            assertTrue("Did not find inserted record.", rs.next());
            rs.close();

            testSchema.getScope().beginTransaction();
            m.put("IntNotNull", 1);
            m = Table.update(ctx.getUser(), testTable, m, rowId);
            assertTrue("Update is consistent in transaction?", (Integer) m.get("IntNotNull") == 1);
            testSchema.getScope().closeConnection();

            //noinspection unchecked
            Map<String, Object>[] maps = (Map<String, Object>[]) Table.select(testTable, Table.ALL_COLUMNS, filter, null, Map.class);
            assertTrue(maps.length == 1);
            m = maps[0];

            assertTrue("Rollback did not appear to work.", (Integer) m.get("IntNotNull") == 0);

            Table.delete(testTable, rowId);
        }

        @Test
        public void testCaching() throws Exception
        {
            TestSchema test = TestSchema.getInstance();
            DbSchema testSchema = test.getSchema();
            TableInfo testTable = test.getTableInfoTestTable();
            TestContext ctx = TestContext.get();

            assertNotNull(testTable);
            DbCache.clear(testTable);

            Map<String, Object> m = new HashMap<>();
            m.put("DatetimeNotNull", new Date());
            m.put("BitNotNull", Boolean.TRUE);
            m.put("Text", "Added by Caching Test Suite");
            m.put("IntNotNull", 0);
            m.put("Container", JunitUtil.getTestContainer());
            m = Table.insert(ctx.getUser(), testTable, m);
            Integer rowId1 = ((Integer) m.get("RowId"));

            String key = "RowId" + rowId1;
            DbCache.put(testTable, key, m);
            Map m2 = (Map) DbCache.get(testTable, key);
            assertEquals(m, m2);

            //Does cache get cleared on delete
            Table.delete(testTable, rowId1);
            m2 = (Map) DbCache.get(testTable, key);
            assertNull(m2);

            //Does cache get cleared on insert
            m.remove("RowId");
            m = Table.insert(ctx.getUser(), testTable, m);
            int rowId2 = ((Integer) m.get("RowId"));
            key = "RowId" + rowId2;
            DbCache.put(testTable, key, m);
            m.remove("RowId");
            m = Table.insert(ctx.getUser(), testTable, m);
            int rowId3 = ((Integer) m.get("RowId"));
            m2 = (Map) DbCache.get(testTable, key);
            assertNull(m2);

            //Make sure things are not inserted in transaction
            m.remove("RowId");
            testSchema.getScope().beginTransaction();
            m = Table.insert(ctx.getUser(), testTable, m);
            int rowId4 = ((Integer) m.get("RowId"));
            String key2 = "RowId" + rowId4;
            DbCache.put(testTable, key2, m);
            testSchema.getScope().closeConnection();
            m2 = (Map) DbCache.get(testTable, key2);
            assertNull(m2);

            // Clean up
            Table.delete(testTable, rowId2);
            Table.delete(testTable, rowId3);
        }

        @Test
        public void testDDLMethods() throws Exception
        {
            TestSchema test = TestSchema.getInstance();
            DbSchema testSchema = test.getSchema();
            String tempTableName = testSchema.getSqlDialect().getTempTablePrefix() + "TTemp";

            // create test objects
            //start with cleanup
            testSchema.getSqlDialect().dropSchema(testSchema, "testdrop");
            testSchema.getSqlDialect().dropSchema(testSchema,"testdrop2");
            testSchema.getSqlDialect().dropSchema(testSchema, "testdrop3");
            testSchema.dropTableIfExists(tempTableName);

            SqlExecutor executor = new SqlExecutor(testSchema);

            if (testSchema.getSqlDialect().isSqlServer())
            {
                // test the 3 ways to create a schema on SQLServer
                executor.execute("EXEC sp_addapprole 'testdrop', 'password'");
                executor.execute("CREATE SCHEMA testdrop2");
                executor.execute(testSchema.getSqlDialect().getCreateSchemaSql("testdrop3"));
            }
            else if (testSchema.getSqlDialect().isPostgreSQL())
            {
                executor.execute("CREATE SCHEMA testdrop");
                executor.execute("CREATE SCHEMA testdrop2");
                executor.execute("CREATE SCHEMA testdrop3");
            }
            else
                return;

            executor.execute("CREATE TABLE testdrop.T0 (c0 INT NOT NULL PRIMARY KEY)");
            executor.execute("CREATE TABLE testdrop.T (c1 CHAR(1), fk_c0 INT REFERENCES testdrop.T0(c0))");
            executor.execute("CREATE INDEX T_c1 ON testdrop.T(c1)");
            executor.execute("CREATE VIEW testdrop.V AS SELECT c1 FROM testdrop.T");
            String sqlCreateTempTable = "CREATE " + testSchema.getSqlDialect().getTempTableKeyword() + " TABLE "
                                        + tempTableName + "(ctemp INT)";
            executor.execute(sqlCreateTempTable);

            executor.execute("CREATE TABLE testdrop2.T0 (c0 INT PRIMARY KEY)");
            executor.execute("CREATE TABLE testdrop2.T (c1 CHAR(10), fk_c0 INT REFERENCES testdrop2.T0(c0))");
            executor.execute("CREATE TABLE testdrop3.T (c1 CHAR(10), fk_c0 INT REFERENCES testdrop2.T0(c0))");
            executor.execute("CREATE INDEX T_c1 ON testdrop2.T(c1)");

            testSchema = DbSchema.createFromMetaData(DbScope.getLabkeyScope(), "testdrop", DbSchemaType.Bare);

            //these exist; ensure they are dropped by re-creating them
            testSchema.dropIndexIfExists("T", "T_c1");
            executor.execute("CREATE INDEX T_c1 ON testdrop.T(c1)");

            testSchema.dropTableIfExists("v");
            executor.execute("CREATE VIEW testdrop.V AS SELECT c0 FROM testdrop.T0");

            testSchema.dropTableIfExists("T");
            executor.execute("CREATE TABLE testdrop.T (c1 CHAR(1))");

            testSchema.dropTableIfExists(tempTableName);
            executor.execute(sqlCreateTempTable);

            testSchema.getSqlDialect().dropSchema(testSchema, "testdrop");

            // these don't exist
            testSchema.dropIndexIfExists("T", "T_notexist") ;
            testSchema.dropTableIfExists("V1");
            testSchema.dropTableIfExists("Tnot");
            testSchema.getSqlDialect().dropSchema(testSchema, "testdrop");

            testSchema.getSqlDialect().dropSchema(testSchema, "testdrop2");
            testSchema.getSqlDialect().dropSchema(testSchema, "testdrop3");
        }

        @Test   // See #12210
        public void testSchemaCasing() throws Exception
        {
            // If schema cache is case-sensitive then this should clear all capitalizations
            DbScope.getLabkeyScope().invalidateSchema("core", DbSchemaType.Module);

            DbSchema core1 = DbSchema.get("Core");
            DbSchema core2 = DbSchema.get("CORE");
            DbSchema core3 = DbSchema.get("cOrE");
            DbSchema canonical = DbSchema.get("core");

            verify("Core", canonical, core1);
            verify("CORE", canonical, core2);
            verify("cOrE", canonical, core3);
        }

        private void verify(String requestedName, DbSchema expected, DbSchema test)
        {
            assertNotNull(test);
            assertTrue(test.getTableNames().size() > 20);
            assertTrue("\"" + requestedName + "\" schema does not match \"" + expected.getDisplayName() + "\" schema", test == expected);
        }
    }

    private static Integer checkContainerColumns(String dbSchemaName, SQLFragment sbSqlCmd, String tempTableName, String moduleName, Integer rowId) throws SQLException
    {
        int row = rowId;
        DbSchema curSchema = DbSchema.get(dbSchemaName);
        SQLFragment sbSql = new SQLFragment();

        for (String tableName : curSchema.getTableNames())
        {
            TableInfo t = curSchema.getTable(tableName);

            if (null == t || t.getTableType()!= DatabaseTableType.TABLE)
                continue;

            for (ColumnInfo col : t.getColumns())
            {
                if (col.getName().equalsIgnoreCase("Container"))
                {
                    sbSql.append( " INSERT INTO "+ tempTableName );
                    sbSql.append(" SELECT " + String.valueOf(++row) + " AS rowId, '" + t.getSelectName() + "' AS TableName, ");
                    List<ColumnInfo> pkColumns = t.getPkColumns();

                    if (pkColumns.size() == 1)
                    {
                        ColumnInfo pkColumn = pkColumns.get(0);
                        sbSql.append(" '" + pkColumn.getSelectName());
                        sbSql.append("' AS FirstPKColName, ");
                        sbSql.append(" CAST( " + t.getSelectName() + "." + pkColumn.getSelectName() + " AS VARCHAR(100)) "
                                + " AS FirstPKValue ,");
                    }
                    else
                    {
                        String tmp = "unknown PK";
                        if (pkColumns.size() > 1)
                            tmp = "multiCol PK ";
                        if(t.getName().equals("ACLs"))
                            tmp = "objectid ";
                        sbSql.append(" '" + tmp + "' AS FirstPKColName, ");
                        sbSql.append(" NULL AS FirstPKValue ,");
                    }
                    sbSql.append(" '" + moduleName + "' AS ModuleName, ");
                    sbSql.append(" CAST( " + t.getSelectName() + "." + col.getName() + " AS VARCHAR(100)) AS OrphanedContainer ");
                    sbSql.append(" FROM " + t.getSelectName());
                    sbSql.append( " LEFT OUTER JOIN " + " core.Containers C ");
                    sbSql.append(" ON (" + t.getSelectName() + ".Container = C.EntityId ) ");
                    sbSql.append( " WHERE C.EntityId IS NULL ");

                    // special handling of MS2 soft deletes
                    if (null != t.getColumn("Deleted"))
                    {
                        sbSql.append( " AND Deleted = ? ");
                        sbSql.add(Boolean.FALSE);
                    }
                    else if (t.getSchema().getName().equals("ms2") && null != t.getColumn("Run"))
                    {
                        sbSql.append(" AND Run IN (SELECT Run FROM ").append(MS2Service.get().getRunsTableName()).append(" WHERE Deleted = ? ) ");
                        sbSql.add(Boolean.FALSE);
                    }

                    sbSql.append(";\n");
                    break;
                }
            }
        }

        sbSqlCmd.append(sbSql);

        return row;
    }

    public static String checkAllContainerCols(User user, boolean bfix) throws SQLException
    {
        List<Module> modules = ModuleLoader.getInstance().getModules();
        ResultSet rs1 = null;
        Integer lastRowId = 0;
        DbSchema coreSchema = CoreSchema.getInstance().getSchema();

        List<ColumnInfo> listColInfos = new ArrayList<>();
        ColumnInfo col = new ColumnInfo("RowId");
        col.setSqlTypeName("INT");
        col.setNullable(false);
        listColInfos.add(col);

        TempTableInfo tTemplate = new TempTableInfo(coreSchema, "cltmp", listColInfos, Collections.singletonList("RowId"));
        String tempTableName = tTemplate.getTempTableName();

        String createTempTableSql =
                "CREATE TABLE " + tempTableName + " ( " +
                        "\tRowId INT NOT NULL,  \n" +
                        "\tTableName VARCHAR(300) NOT NULL,\n" +
                        "\tFirstPKColName VARCHAR(100) NULL,\n" +
                        "\tFirstPKValue VARCHAR(100) NULL,\n" +
                        "\tModuleName VARCHAR(50) NOT NULL,\n" +
                        "\tOrphanedContainer VARCHAR(60) NULL) ;\n\n";

        StringBuilder sbOut = new StringBuilder();

        try
        {
            SQLFragment sbCheck = new SQLFragment();

            for (Module module : modules)
            {
                Set<DbSchema> schemas = module.getSchemasToTest();

                for (DbSchema schema : schemas)
                    lastRowId = checkContainerColumns(schema.getDisplayName(), sbCheck, tempTableName, module.getName(), lastRowId);
            }

            tTemplate.track();
            new SqlExecutor(coreSchema).execute(createTempTableSql);
            new SqlExecutor(coreSchema).execute(sbCheck);

            if (bfix)
            {
                // create a recovered objects project
                Random random = new Random();
                int r = random.nextInt();
                String cName = "/_RecoveredObjects" +  String.valueOf(r).substring(1,5);
                Container recovered = ContainerManager.ensureContainer(cName);

                Set<Module> modulesOfOrphans = new HashSet<>();

                rs1 = Table.executeQuery(coreSchema, "SELECT TableName, OrphanedContainer, ModuleName FROM " + tempTableName
                        + " WHERE OrphanedContainer IS NOT NULL GROUP BY TableName, OrphanedContainer, ModuleName", new Object[]{});

                while (rs1.next())
                {
                    modulesOfOrphans.add(ModuleLoader.getInstance().getModule(rs1.getString(3)));
                    String sql = "UPDATE " + rs1.getString(1) + " SET Container = ? WHERE Container = ?";

                    try
                    {
                        Table.execute(coreSchema, sql, recovered.getId(), rs1.getString(2));
                        //remove the ACLs that were there
                        SecurityPolicyManager.removeAll(recovered);
                        sbOut.append("<br> Recovered objects from table ");
                        sbOut.append(rs1.getString(1));
                        sbOut.append(" to project ");
                        sbOut.append(recovered.getName());
                    }
                    catch (SQLException se)
                    {
                        sbOut.append("<br> Failed attempt to recover some objects from table ");
                        sbOut.append(rs1.getString(1));
                        sbOut.append(" due to error ").append(se.getMessage());
                        sbOut.append(". Retrying recovery may work.  ");
                    }
                }

                recovered.setActiveModules(modulesOfOrphans, user);

                return sbOut.toString();
            }
            else
            {
                rs1 = Table.executeQuery(coreSchema, " SELECT * FROM " + tempTableName
                        + " WHERE OrphanedContainer IS NOT NULL ORDER BY 1,3 ;", new Object[]{});

                while (rs1.next())
                {
                    sbOut.append("<br/>&nbsp;&nbsp;&nbsp;ERROR:  ");
                    sbOut.append(rs1.getString(1));
                    sbOut.append(" &nbsp;&nbsp;&nbsp;&nbsp; ");
                    sbOut.append(rs1.getString(2));
                    sbOut.append(" = ");
                    sbOut.append(rs1.getString(3));
                    sbOut.append("&nbsp;&nbsp;&nbsp;Container:  ");
                    sbOut.append(rs1.getString(5));
                    sbOut.append("\n");
                }

                return sbOut.toString();
            }
        }
        finally
        {
            ResultSetUtil.close(rs1);
        }
    }
}
