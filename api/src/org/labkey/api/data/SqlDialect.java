/*
 * Copyright (c) 2005-2008 Fred Hutchinson Cancer Research Center
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

import junit.framework.Test;
import junit.framework.TestSuite;
import org.apache.commons.lang.ObjectUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.labkey.api.module.ModuleContext;
import org.labkey.api.util.CaseInsensitiveHashMap;
import org.labkey.api.util.CaseInsensitiveHashSet;
import org.labkey.api.util.SystemMaintenance;

import javax.servlet.ServletException;
import javax.sql.DataSource;
import java.lang.reflect.Method;
import java.sql.*;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * User: arauch
 * Date: Dec 28, 2004
 * Time: 8:58:25 AM
 */

// Isolate the big SQL differences between database servers
public abstract class SqlDialect
{
    protected static final Logger _log = Logger.getLogger(SqlDialect.class);
    private static List<SqlDialect> _dialects = new CopyOnWriteArrayList<SqlDialect>();

    public static final String GENERIC_ERROR_MESSAGE = "The database experienced an unexpected problem. Please check your input and try again.";
    public static final String INPUT_TOO_LONG_ERROR_MESSAGE = "The input you provided was too long.";
    protected Set<String> reservedWordSet = new CaseInsensitiveHashSet();
    private Map<String, Integer> sqlTypeNameMap = new CaseInsensitiveHashMap<Integer>();
    private Map<Integer, String> sqlTypeIntMap = new HashMap<Integer, String>();

    static final private Pattern s_patStringLiteral = Pattern.compile("\\'([^\\']|(\'\'))*\\'");
    static final private Pattern s_patQuotedIdentifier = Pattern.compile("\\\"([^\\\"]|(\\\"\\\"))*\\\"");
    static final private Pattern s_patParameter = Pattern.compile("\\?");

    public static void register(SqlDialect dialect)
    {
        _dialects.add(dialect);
    }


    static
    {
        SystemMaintenance.addTask(new DatabaseMaintenanceTask());
    }


    private static class DatabaseMaintenanceTask implements SystemMaintenance.MaintenanceTask
    {
        public String getMaintenanceTaskName()
        {
            return "Database maintenance";
        }

        public void run()
        {
            Map<String, DbScope> scopes = DbSchema.getDbScopes();

            for (DbScope scope : scopes.values())
            {
                Connection conn = null;
                String sql = scope.getSqlDialect().getDatabaseMaintenanceSql();
                DataSource ds = scope.getDataSource();

                String url = null;

                try
                {
                    DataSourceProperties props = new DataSourceProperties(ds);
                    url = props.getUrl();
                    _log.info("Database maintenance on " + url + " started");
                }
                catch (Exception e)
                {
                    // Shouldn't happen, but we can survive without the url
                    _log.error("Exception retrieving url", e);
                }

                try
                {
                    if (null != sql)
                    {
                        conn = ds.getConnection();
                        Table.execute(conn, sql, null);
                    }
                }
                catch(SQLException e)
                {
                    // Nothing to do here... table layer will log any errors
                }
                finally
                {
                    try {  if (null != conn) conn.close(); } catch (SQLException e) { /**/ }
                }

                if (null != url)
                    _log.info("Database maintenance on " + url + " complete");
            }
        }
    }


    protected SqlDialect()
    {
        initializeSqlTypeNameMap();
        initializeSqlTypeIntMap();
    }


    private void initializeSqlTypeNameMap()
    {
        sqlTypeNameMap.put("ARRAY", Types.ARRAY);
        sqlTypeNameMap.put("BIGINT", Types.BIGINT);
        sqlTypeNameMap.put("BINARY", Types.BINARY);
        sqlTypeNameMap.put("BIT", Types.BIT);
        sqlTypeNameMap.put("BLOB", Types.BLOB);
        sqlTypeNameMap.put("BOOLEAN", Types.BOOLEAN);
        sqlTypeNameMap.put("CHAR", Types.CHAR);
        sqlTypeNameMap.put("CLOB", Types.CLOB);
        sqlTypeNameMap.put("DATALINK", Types.DATALINK);
        sqlTypeNameMap.put("DATE", Types.DATE);
        sqlTypeNameMap.put("DECIMAL", Types.DECIMAL);
        sqlTypeNameMap.put("DISTINCT", Types.DISTINCT);
        sqlTypeNameMap.put("DOUBLE", Types.DOUBLE);
        sqlTypeNameMap.put("DOUBLE PRECISION", Types.DOUBLE);
        sqlTypeNameMap.put("FLOAT", Types.FLOAT);
        sqlTypeNameMap.put("INTEGER", Types.INTEGER);
        sqlTypeNameMap.put("JAVA_OBJECT", Types.JAVA_OBJECT);
        sqlTypeNameMap.put("LONGVARBINARY", Types.LONGVARBINARY);
        sqlTypeNameMap.put("LONGVARCHAR", Types.LONGVARCHAR);
        sqlTypeNameMap.put("NULL", Types.NULL);
        sqlTypeNameMap.put("NUMERIC", Types.NUMERIC);
        sqlTypeNameMap.put("OTHER", Types.OTHER);
        sqlTypeNameMap.put("REAL", Types.REAL);
        sqlTypeNameMap.put("REF", Types.REF);
        sqlTypeNameMap.put("SMALLINT", Types.SMALLINT);
        sqlTypeNameMap.put("STRUCT", Types.STRUCT);
        sqlTypeNameMap.put("TIME", Types.TIME);
        sqlTypeNameMap.put("TINYINT", Types.TINYINT);
        sqlTypeNameMap.put("VARBINARY", Types.VARBINARY);
        sqlTypeNameMap.put("VARCHAR", Types.VARCHAR);

        addSqlTypeNames(sqlTypeNameMap);
    }


    private void initializeSqlTypeIntMap()
    {
        sqlTypeIntMap.put(Types.ARRAY, "ARRAY");
        sqlTypeIntMap.put(Types.BIGINT, "BIGINT");
        sqlTypeIntMap.put(Types.BINARY, "BINARY");
        sqlTypeIntMap.put(Types.BLOB, "BLOB");
        sqlTypeIntMap.put(Types.CLOB, "CLOB");
        sqlTypeIntMap.put(Types.DATALINK, "DATALINK");
        sqlTypeIntMap.put(Types.DATE, "DATE");
        sqlTypeIntMap.put(Types.DECIMAL, "DECIMAL");
        sqlTypeIntMap.put(Types.DISTINCT, "DISTINCT");
        sqlTypeIntMap.put(Types.INTEGER, "INTEGER");
        sqlTypeIntMap.put(Types.JAVA_OBJECT, "JAVA_OBJECT");
        sqlTypeIntMap.put(Types.NULL, "NULL");
        sqlTypeIntMap.put(Types.NUMERIC, "NUMERIC");
        sqlTypeIntMap.put(Types.OTHER, "OTHER");
        sqlTypeIntMap.put(Types.REAL, "REAL");
        sqlTypeIntMap.put(Types.REF, "REF");
        sqlTypeIntMap.put(Types.SMALLINT, "SMALLINT");
        sqlTypeIntMap.put(Types.STRUCT, "STRUCT");
        sqlTypeIntMap.put(Types.TIME, "TIME");
        sqlTypeIntMap.put(Types.TINYINT, "TINYINT");
        sqlTypeIntMap.put(Types.VARBINARY, "VARBINARY");

        addSqlTypeInts(sqlTypeIntMap);
    }


    protected abstract void addSqlTypeNames(Map<String, Integer> sqlTypeNameMap);
    protected abstract void addSqlTypeInts(Map<Integer, String> sqlTypeIntMap);

    public int sqlTypeIntFromSqlTypeName(String sqlTypeName)
    {
        Integer i = sqlTypeNameMap.get(sqlTypeName);

        if (null != i)
            return i.intValue();
        else
        {
            _log.info("Unknown SQL Type Name \"" + sqlTypeName + "\"; using String instead.");
            return Types.OTHER;
        }
    }


    public String sqlTypeNameFromSqlTypeInt(int sqlTypeInt)
    {
        String sqlTypeName = sqlTypeIntMap.get(sqlTypeInt);

        return null != sqlTypeName ? sqlTypeName : "OTHER";
    }


    protected String getDatabaseMaintenanceSql()
    {
        return null;
    }


    public static class SqlDialectNotSupportedException extends ServletException
    {
        private SqlDialectNotSupportedException(String message)
        {
            super(message);
        }
    }


    /**
     * Getting the SqlDialect from the driver class name won't return the version
     * specific dialect -- use getFromMetaData() if possible.
     */
    public static SqlDialect getFromDriverClassName(String driverClassName) throws SqlDialectNotSupportedException
    {
        for (SqlDialect dialect : _dialects)
            if (dialect.claimsDriverClassName(driverClassName))
                return dialect;

        throw new SqlDialectNotSupportedException("Driver class name: " + driverClassName);
    }


    public static SqlDialect getFromMetaData(DatabaseMetaData md) throws SQLException, SqlDialectNotSupportedException
    {
        return getFromProductName(md.getDatabaseProductName(), md.getDatabaseMajorVersion(), md.getDatabaseMinorVersion());
    }


    private static SqlDialect getFromProductName(String dataBaseProductName, int majorVersion, int minorVersion) throws SqlDialectNotSupportedException
    {
        for (SqlDialect dialect : _dialects)
            if (dialect.claimsProductNameAndVersion(dataBaseProductName, majorVersion, minorVersion))
                return dialect;

        throw new SqlDialectNotSupportedException("Product name and version: " + dataBaseProductName + " " + majorVersion + "." + minorVersion);
    }

    public static boolean isConstraintException(SQLException x)
    {
        String sqlState = x.getSQLState();
        if (!sqlState.startsWith("23"))
            return false;
        return sqlState.equals("23000") || sqlState.equals("23505") || sqlState.equals("23503");
    }

    protected abstract boolean claimsDriverClassName(String driverClassName);

    protected abstract boolean claimsProductNameAndVersion(String dataBaseProductName, int majorVersion, int minorVersion);

    // Do dialect-specific work after schema load
    public abstract void prepareNewDbSchema(DbSchema schema);

    protected abstract String getProductName();

    public abstract String getSQLScriptPath(boolean source);

    public abstract void appendStatement(StringBuilder sql, String statement);

    public abstract void appendSelectAutoIncrement(StringBuilder sql, TableInfo table, String columnName);

    /**
     * Limit a SELECT query to the specified number of rows (0 == no limit).
     * @param sql a SELECT query
     * @param rowCount return the first rowCount number of rows (0 == no limit).
     * @return the query
     */
    public abstract SQLFragment limitRows(SQLFragment sql, int rowCount);

    public void limitRows(StringBuilder builder, int rowCount)
    {
        SQLFragment frag = new SQLFragment();
        frag.append(builder);
        limitRows(frag, rowCount);
        builder.replace(0, builder.length(), frag.getSQL());
    }

    /**
     * Composes the fragments into a SQL query that will be limited by rowCount
     * starting at the given 0-based offset.
     * 
     * @param select must not be null
     * @param from must not be null
     * @param filter may be null
     * @param order may be null
     * @param rowCount 0 means all rows, >0 limits result set
     * @param offset 0 based
     * @return the query
     */
    public abstract SQLFragment limitRows(SQLFragment select, SQLFragment from, SQLFragment filter, String order, int rowCount, long offset);

    /** Does the dialect support limitRows() with an offset? */
    public abstract boolean supportOffset();

    public abstract String execute(DbSchema schema, String procedureName, String parameters);

    public abstract String getConcatenationOperator();

    /**
     * Return the operator which supports, in addition to the usual LIKE things '%', and '_', also supports
     * character classes. (i.e. [abc] matching a,b or c)
     * If you do not need the functionality of character classes, then "LIKE" will work just fine with all SQL dialects.
     */
    public abstract String getCharClassLikeOperator();

    public abstract String getCaseInsensitiveLikeOperator();

    public abstract String getVarcharLengthFunction();

    public abstract String getStdDevFunction();

    public abstract String getClobLengthFunction();

    public abstract String getStringIndexOfFunction(String stringToFind, String stringToSearch);

    public abstract String getSubstringFunction(String s, String start, String length);

    public abstract void runSql(DbSchema schema, String sql, UpgradeCode upgradeCode, ModuleContext moduleContext) throws SQLException;

    public abstract String getMasterDataBaseName();

    public abstract String getDefaultDateTimeDatatype();

    public abstract String getUniqueIdentType();

    public abstract String getTempTableKeyword();

    public abstract String getTempTablePrefix();

    public abstract String getGlobalTempTablePrefix();

    public abstract boolean isNoDatabaseException(SQLException e);

    public abstract boolean isSortableDataType(String sqlDataTypeName);

    public abstract String getDropIndexCommand(String tableName, String indexName);

    public abstract String getCreateDatabaseSql(String dbName);

    public abstract String getCreateSchemaSql(String schemaName);

    /** @param part the java.util.Calendar field for the unit of time, such as Calendar.DATE or Calendar.MINUTE */
    public abstract String getDateDiff(int part, String value1, String value2);

    /** @param expression The expression with datetime value for which a date value is desired */
    public abstract String getDateTimeToDateCast(String expression);

    public abstract String getRoundFunction(String valueToRound);

    // Do nothing by default
    public void prepareNewDatabase(DbSchema schema) throws ServletException
    {
    }

    public void handleCreateDatabaseException(SQLException e) throws ServletException
    {
        throw(new ServletException("Can't create database", e));
    }

    /**
     * Wrap one or more INSERT statements to allow explicit specification
     * of values for auto-incrementing columns (e.g. IDENTITY in SQL Server
     * or SERIAL in Postgres). The input StringBuffer is modified to
     * wrap the statements in dialect-specific code to allow this.
     *
     * @param statements the insert statements. If more than one,
     *                   they must have been joined by appendStatement
     *                   and must all refer to the same table.
     * @param tinfo      table used in the insert(s)
     */
    public abstract void overrideAutoIncrement(StringBuilder statements, TableInfo tinfo);

    protected String getSystemTableNames()
    {
        return "";
    }

    private Set<String> systemTableSet = new CaseInsensitiveHashSet(Arrays.asList(getSystemTableNames().split(",")));

    public boolean isSystemTable(String tableName)
    {
        return systemTableSet.contains(tableName);
    }


    // Just return name by default... subclasses can override and (for example) put quotes around keywords
    public String getColumnSelectName(String columnName)
    {
        if (reservedWordSet.contains(columnName))
            return "\"" + columnName.toLowerCase() + "\"";
        else
            return columnName;
    }

    // Just return name by default... subclasses can override and (for example) put quotes around keywords
    public String getTableSelectName(String tableName)
    {
        return tableName;
    }

    // Just return name by default... subclasses can override and (for example) put quotes around keywords
    public String getOwnerSelectName(String ownerName)
    {
        return ownerName;
    }

    // String version for convenience
    public String appendSelectAutoIncrement(String sql, TableInfo tinfo, String columnName)
    {
        StringBuilder sbSql = new StringBuilder(sql);
        appendSelectAutoIncrement(sbSql, tinfo, columnName);
        return sbSql.toString();
    }


    public final void checkSqlScript(String sql, double version) throws SQLSyntaxException
    {
        if (version <= 2.10)
            return;

        Collection<String> errors = new ArrayList<String>();
        String lower = sql.toLowerCase();
        String lowerNoWhiteSpace = lower.replaceAll("\\s", "");

        if (lowerNoWhiteSpace.contains("primarykey,"))
            errors.add("Do not designate PRIMARY KEY on the column definition line; this creates a PK with an arbitrary name, making it more difficult to change it later.  Instead, create the PK as a named contraint (e.g., PK_MyTable).");

        checkSqlScript(lower, lowerNoWhiteSpace, errors);

        if (!errors.isEmpty())
            throw new SQLSyntaxException(errors);
    }


    abstract protected void checkSqlScript(String lower, String lowerNoWhiteSpace, Collection<String> errors);

    protected class SQLSyntaxException extends SQLException
    {
        private Collection<String> _errors;

        protected SQLSyntaxException(Collection<String> errors)
        {
            _errors = errors;
        }

        @Override
        public String getMessage()
        {
            return StringUtils.join(_errors.iterator(), '\n');
        }
    }

    /**
     * Transform the JDBC error message into something the user is more likely
     * to understand.
     */
    public abstract String sanitizeException(SQLException ex);

    public abstract String getAnalyzeCommandForTable(String tableName);

    protected abstract String getSIDQuery();

    public Integer getSPID(Connection result) throws SQLException
    {
        PreparedStatement stmt = null;
        ResultSet rs = null;
        try
        {
            stmt = result.prepareStatement(getSIDQuery());
            rs = stmt.executeQuery();
            if (!rs.next())
            {
                throw new SQLException("SID query returned no results");
            }
            return rs.getInt(1);
        }
        finally
        {
            if (stmt != null) { try { stmt.close(); } catch (SQLException e) {} }
            if (rs != null) { try { rs.close(); } catch (SQLException e) {} }
        }
    }

    public abstract String getBooleanDatatype();


    // We need to determine the database name from a data source, so we've implemented a helper that parses
    // the JDBC connection string for each driver we support.  This is necessary because, unfortunately, there
    // appears to be no standard, reliable way to ask a JDBC driver for individual components of the URL or
    // to programmatically assemble a new connection URL.  Driver.getPropertyInfo(), for example, doesn't
    // return the database name on PostgreSQL if it's specified as part of the URL.
    //
    // Currently, JdbcHelper only finds the database name.  It could be extended if we require querying
    // other components or if replacement/reassembly becomes necessary.

    public static SqlDialect getSqlDialect(DataSource ds) throws ServletException
    {
        try
        {
            DataSourceProperties props = new DataSourceProperties(ds);
            return getFromDriverClassName(props.getDriverClassName());
        }
        catch (Exception e)
        {
            throw new ServletException("Error determining SqlDialect from DataSource", e);
        }
    }


    public String getDatabaseName(DataSource ds) throws ServletException
    {
        try
        {
            DataSourceProperties props = new DataSourceProperties(ds);
            String url = props.getUrl();
            return getDatabaseName(url);
        }
        catch (Exception e)
        {
            throw new ServletException("Error retrieving url property from DataSource", e);
        }
    }


    public String getDatabaseName(String url) throws ServletException
    {
        return getJdbcHelper(url).getDatabase();
    }


    public abstract JdbcHelper getJdbcHelper(String url) throws ServletException;

    public static abstract class JdbcHelper
    {
        protected String _database;

        public String getDatabase()
        {
            return _database;
        }
    }

    /**
     * Drop a schema if it exists.
     * Throws an exception if schema exists, and could not be dropped. 
     */
    public void dropSchema(DbSchema schema, String schemaName) throws SQLException
    {
        Object[] parameters = new Object[]{"*", schemaName, "SCHEMA", null};
        String sql = schema.getSqlDialect().execute(CoreSchema.getInstance().getSchema(), "fn_dropifexists", "?, ?, ?, ?");
        Table.execute(schema, sql, parameters);
    }

    /**
     * Drop an object (table, view) or subobject (index) if it exists
     *
     * @param schema  dbSchema in which the object lives
     * @param objectName the name of the table or view to be dropped, or the table on which the index is defined
     * @param objectType "TABLE", "VIEW", "INDEX"
     * @param subObjectName index name;  ignored if not an index
     */
    public void dropIfExists (DbSchema schema, String objectName, String objectType, String subObjectName) throws SQLException
    {
        Object[] parameters = new Object[]{objectName, schema.getOwner(), objectType, subObjectName};
        String sql = schema.getSqlDialect().execute(CoreSchema.getInstance().getSchema(), "fn_dropifexists", "?, ?, ?, ?");
        Table.execute(schema, sql, parameters);
    }

    /**
     * Returns a SQL fragment for the integer expression indicating the (1-based) first occurrence of littleString in bigString
     */
    abstract public SQLFragment sqlLocate(SQLFragment littleString, SQLFragment bigString);

    /**
     * Returns a SQL fragment for the integer expression indicating the (1-based) first occurrence of littleString in bigString starting at (1-based) startIndex.
     */
    abstract public SQLFragment sqlLocate(SQLFragment littleString, SQLFragment bigString, SQLFragment startIndex);

    abstract public boolean allowSortOnSubqueryWithoutLimit();

    protected Pattern patStringLiteral()
    {
        return s_patStringLiteral;
    }

    protected Pattern patQuotedIdentifier()
    {
        return s_patQuotedIdentifier;
    }

    protected String quoteStringLiteral(String str)
    {
        return "'" + StringUtils.replace(str, "'", "''") + "'";
    }

    /**
     * Substitute the parameter values into the SQL statement.
     * Iterates through the SQL string
     */
    public String substituteParameters(SQLFragment frag)
    {
        CharSequence sql = frag.getSqlCharSequence();
        Matcher matchIdentifier = patQuotedIdentifier().matcher(sql);
        Matcher matchStringLiteral = patStringLiteral().matcher(sql);
        Matcher matchParam = s_patParameter.matcher(sql);

        StringBuilder ret = new StringBuilder();
        List<Object> params = new ArrayList<Object>(frag.getParams());
        int ich = 0;
        while (ich < sql.length())
        {
            int ichSkipTo = sql.length();
            int ichSkipPast = sql.length();
            if (matchIdentifier.find(ich))
            {
                if (matchIdentifier.start() < ichSkipTo)
                {
                    ichSkipTo = matchIdentifier.start();
                    ichSkipPast = matchIdentifier.end();
                }
            }
            if (matchStringLiteral.find(ich))
            {
                if (matchStringLiteral.start() < ichSkipTo)
                {
                    ichSkipTo = matchStringLiteral.start();
                    ichSkipPast = matchStringLiteral.end();
                }
            }
            if (matchParam.find(ich))
            {
                if (matchParam.start() < ichSkipTo)
                {
                    ret.append(frag.getSqlCharSequence().subSequence(ich, matchParam.start()));
                    ret.append(" ");
                    ret.append(quoteStringLiteral(ObjectUtils.toString(params.remove(0))));
                    ret.append(" ");
                    ich = matchParam.start() + 1;
                    continue;
                }
            }
            ret.append(frag.getSqlCharSequence().subSequence(ich, ichSkipPast));
            ich = ichSkipPast;
        }
        return ret.toString();
    }


    // Trying to be DataSource implementation agnostic here.  DataSource interface doesn't provide access to any of
    // these properties, but we don't want to cast to a specific implementation class, so use reflection to get them.
    public static class DataSourceProperties
    {
        private DataSource _ds;

        public DataSourceProperties(DataSource ds)
        {
            _ds = ds;
        }

        private String getProperty(String methodName) throws ServletException
        {

            try
            {
                Method getUrl = _ds.getClass().getMethod(methodName);
                return (String)getUrl.invoke(_ds);
            }
            catch (Exception e)
            {
                throw new ServletException("Unabled to retrieve DataSource property via " + methodName, e);
            }
        }


        public String getUrl() throws ServletException
        {
            return getProperty("getUrl");
        }


        public String getDriverClassName() throws ServletException
        {
            return getProperty("getDriverClassName");
        }


        public String getUsername() throws ServletException
        {
            return getProperty("getUsername");
        }


        public String getPassword() throws ServletException
        {
            return getProperty("getPassword");
        }
    }


    public String sqlTypeNameFromSqlType(int sqlType)
    {
        boolean postgres = isPostgreSQL();

        switch (sqlType)
        {
            case Types.ARRAY:
                return "ARRAY";
            case Types.BIGINT:
                return "BIGINT";
            case Types.BINARY:
                return "BINARY";
            case Types.BLOB:
                return "BLOB";
            case Types.BIT:
            case Types.BOOLEAN:
                return postgres ? "BOOLEAN" : "BIT";
            case Types.CHAR:
                return postgres ? "CHAR" : "NCHAR";
            case Types.CLOB:
                return "CLOB";
            case Types.DATALINK:
                return "DATALINK";
            case Types.DATE:
                return "DATE";
            case Types.DECIMAL:
                return "DECIMAL";
            case Types.DISTINCT:
                return "DISTINCT";
            case Types.DOUBLE:
            case Types.FLOAT:
                return postgres ? "DOUBLE PRECISION" : "FLOAT";
            case Types.INTEGER:
                return "INTEGER";
            case Types.JAVA_OBJECT:
                return "JAVA_OBJECT";
            case Types.LONGVARBINARY:
                return postgres ? "LONGVARBINARY" : "IMAGE";
            case Types.LONGVARCHAR:
                return postgres ? "LONGVARCHAR" : "NTEXT";
            case Types.NULL:
                return "NULL";
            case Types.NUMERIC:
                return "NUMERIC";
            case Types.OTHER:
                return "OTHER";
            case Types.REAL:
                return "REAL";
            case Types.REF:
                return "REF";
            case Types.SMALLINT:
                return "SMALLINT";
            case Types.STRUCT:
                return "STRUCT";
            case Types.TIME:
                return "TIME";
            case Types.TIMESTAMP:
                return postgres ? "TIMESTAMP" : "DATETIME";  // DATETIME in mssql TIMESTAMP in pgsql
            case Types.TINYINT:
                return "TINYINT";
            case Types.VARBINARY:
                return "VARBINARY";
            case Types.VARCHAR:
                return postgres ? "VARCHAR" : "NVARCHAR";
            default:
                return "OTHER";
        }
    }


    public abstract void initializeConnection(Connection conn) throws SQLException;
    public abstract void purgeTempSchema(Map<String, TempTableTracker> createdTableNames);
    public abstract boolean isCaseSensitive();
    public abstract boolean isSqlServer();
    public abstract boolean isPostgreSQL();
    public abstract TestSuite getTestSuite();


    // JUnit test case
    public static class SqlDialectTestCase extends junit.framework.TestCase
    {
        public static Test suite()
        {
            return CoreSchema.getInstance().getSqlDialect().getTestSuite();
        }
    }



    public static class TestUpgradeCode implements UpgradeCode
    {
        private int _counter = 0;

        @SuppressWarnings({"UnusedDeclaration"})
        public void upgradeCode(ModuleContext moduleContext)
        {
            _counter++;
        }

        public int getCounter()
        {
            return _counter;
        }
    }
}
