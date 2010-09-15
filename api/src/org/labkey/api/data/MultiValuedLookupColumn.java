package org.labkey.api.data;

import org.apache.commons.lang.StringUtils;
import org.labkey.api.query.AliasManager;
import org.labkey.api.query.FieldKey;

import java.util.LinkedHashMap;
import java.util.Map;

/**
* User: adam
* Date: Sep 14, 2010
* Time: 1:10:47 PM
*/
public class MultiValuedLookupColumn extends LookupColumn
{
    private final ColumnInfo _display;
    private final ForeignKey _rightFk;
    private final ColumnInfo _junctionKey;

    public MultiValuedLookupColumn(FieldKey fieldKey, ColumnInfo parentPkColumn, ColumnInfo childKey, ColumnInfo junctionKey, ForeignKey fk, ColumnInfo display)
    {
        super(parentPkColumn, childKey, display);
        _display = display;
        _rightFk = fk;
        _junctionKey = junctionKey;
        copyAttributesFrom(display);
        copyURLFrom(display, parentPkColumn.getFieldKey(), null);
        setFieldKey(fieldKey);
    }

    // We don't traverse FKs from a multi-valued column
    @Override
    public ForeignKey getFk()
    {
        return null;
    }

    @Override
    public DisplayColumn getRenderer()
    {
        return new MultiValuedDisplayColumn(super.getRenderer());
    }

    @Override
    public DisplayColumnFactory getDisplayColumnFactory()
    {
        return new DisplayColumnFactory()
        {
            @Override
            public DisplayColumn createRenderer(ColumnInfo colInfo)
            {
                return new MultiValuedDisplayColumn(MultiValuedLookupColumn.super.getDisplayColumnFactory().createRenderer(colInfo));
            }
        };
    }

    @Override
    public SQLFragment getValueSql(String tableAliasName)
    {
        return new SQLFragment(getTableAlias(tableAliasName) + "." + _display.getAlias());
    }

    protected void addLookupSql(SQLFragment strJoin, TableInfo lookupTable)
    {
        String keyColumnName = _lookupKey.getSelectName();

        strJoin.append("\n\t(\n\t\t");
        strJoin.append("SELECT child.");
        strJoin.append(keyColumnName);

        // Select and aggregate all columns in the far right table for now.  TODO: Select only required columns.
        for (ColumnInfo col : _rightFk.getLookupTableInfo().getColumns())
        {
            ColumnInfo lc = _rightFk.createLookupColumn(_junctionKey, col.getName());
            strJoin.append(", \n\t\t\t");
            strJoin.append(getAggregateFunction(lc.getValueSql("child").toString()));
            strJoin.append(" AS ");
            strJoin.append(lc.getAlias());
        }

        strJoin.append("\n\t\t\tFROM (");
        strJoin.append(_lookupKey.getParentTable().getFromSQL());
        strJoin.append(") child");

        Map<String, SQLFragment> joins = new LinkedHashMap<String, SQLFragment>();
        _lookupColumn.declareJoins("child", joins);

        for (SQLFragment fragment : joins.values())
        {
            strJoin.append(StringUtils.replace(fragment.toString(), "\n\t", "\n\t\t"));
        }

        // TODO: Add ORDER BY?

        strJoin.append("\n\t\tGROUP BY child.");
        strJoin.append(keyColumnName);
        strJoin.append("\n\t)");
    }

    @Override
    // The multivalued column joins take place within the aggregate function sub-select; we don't want super class
    // including these columns as top-level joins.
    protected boolean includeLookupJoins()
    {
        return false;
    }

    @Override
    public String getTableAlias(String baseAlias)
    {
        return AliasManager.makeLegalName(baseAlias + "$" + this.getName(), getSqlDialect());
    }

    // By default, use GROUP_CONCAT aggregate function, which returns a common-separated list of values.  Override this
    // and (for non-varchar aggregate function) getSqlTypeName() to apply a different aggregate.
    protected String getAggregateFunction(String selectName)
    {
        return getSqlDialect().getGroupConcatAggregateFunction(selectName);
    }

    @Override  // Must match the type of the aggregate function specified above.
    public String getSqlTypeName()
    {
        return "varchar";
    }
}
