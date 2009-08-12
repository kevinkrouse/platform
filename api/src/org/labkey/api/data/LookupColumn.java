/*
 * Copyright (c) 2006-2009 LabKey Corporation
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

import org.labkey.api.query.FieldKey;
import org.labkey.api.query.RowIdForeignKey;

import java.util.Map;

public class LookupColumn extends ColumnInfo
{
    /**
     * Create a lookup column to a "real" table - one that actually exists
     * in the underlying database
     */
    static public LookupColumn create(ColumnInfo foreignKey, ColumnInfo lookupKey, ColumnInfo lookupColumn, boolean prefixColumnCaption)
    {
        if (lookupKey == null || lookupColumn == null)
            return null;
        LookupColumn ret = new LookupColumn(foreignKey, lookupKey, lookupColumn);
        ret.copyAttributesFrom(lookupColumn);
        if (prefixColumnCaption)
        {
            ret.setCaption(foreignKey.getCaption() + " " + lookupColumn.getCaption());
        }
        else
        {
            ret.setCaption(lookupColumn.getCaption());
        }
        if (ret.getFk() instanceof RowIdForeignKey)
        {
            ret.setFk(null);
        }
        return ret;
    }

    protected ColumnInfo foreignKey;
    protected ColumnInfo lookupKey;
    protected ColumnInfo lookupColumn;
    protected boolean joinOnContainer;

    public LookupColumn(ColumnInfo foreignKey, ColumnInfo lookupKey, ColumnInfo lookupColumn, boolean joinOnContainer)
    {
        // Bug 1166: always report that our parent table is the leftmost table, so the dataregion knows which
        // table to select from
        super(lookupColumn.getName(), foreignKey.getParentTable());
        this.foreignKey = foreignKey;
        this.lookupKey = lookupKey;
        assert lookupKey.getValueSql("test") != null;
        this.lookupColumn = lookupColumn;
        setSqlTypeName(lookupColumn.getSqlTypeName());
        setName(new FieldKey(FieldKey.fromString(foreignKey.getName()), lookupColumn.getName()).toString());
        setAlias(foreignKey.getAlias() + "$" + lookupColumn.getAlias());
        this.joinOnContainer = joinOnContainer;
    }

    public LookupColumn(ColumnInfo foreignKey, ColumnInfo lookupKey, ColumnInfo lookupColumn)
    {
        this(foreignKey, lookupKey, lookupColumn, false);
    }

    public SQLFragment getValueSql()
    {
        return lookupColumn.getValueSql(getTableAlias());
    }


    public SQLFragment getValueSql(String tableAliasName)
    {
        return lookupColumn.getValueSql(getTableAlias());
    }


    public SQLFragment getJoinCondition(String tableAliasName)
    {
        return getJoinConditionHelper(
            foreignKey.getTableAlias(), foreignKey.getValueSql(tableAliasName), foreignKey.getSqlTypeInt(),
            getTableAlias(), lookupKey.getValueSql(getTableAlias()), lookupKey.getSqlTypeInt(),
            joinOnContainer, getSqlDialect().isPostgreSQL()
        );
    }


    public static SQLFragment getJoinConditionHelper(String tableAliasName, SQLFragment fkSql, int fkType,
            String joinAlias, SQLFragment pkSql, int pkType,
            boolean joinOnContainer, boolean isPostgreSQL)
    {
        SQLFragment condition = new SQLFragment();
        boolean typeMismatch = fkType != pkType;
        condition.append("(");
        if (isPostgreSQL && typeMismatch)
            condition.append("CAST((").append(fkSql).append(") AS VARCHAR)");
        else
            condition.append(fkSql);
        condition.append(" = ");

        if (isPostgreSQL && typeMismatch)
            condition.append("CAST((").append(pkSql).append(") AS VARCHAR)");
        else
            condition.append(pkSql);

        if (joinOnContainer)
        {
            condition.append(" AND ").append(tableAliasName);
            condition.append(".Container = ").append(joinAlias).append(".Container");
        }
        condition.append(")");
        return condition;
    }

    
    @SuppressWarnings({"ConstantConditions"})
    public void declareJoins(String baseAlias, Map<String, SQLFragment> map)
    {
        boolean assertEnabled = false;
        assert assertEnabled = true;

        String colTableAlias = getTableAlias();

        if (map.containsKey(colTableAlias))
        {
            if (!assertEnabled)
                return;
            // if asserts enabled, fall through
        }

        foreignKey.declareJoins(baseAlias, map);
        TableInfo lookupTable = lookupKey.getParentTable();
        SQLFragment strJoin = new SQLFragment("\n\tLEFT OUTER JOIN ");

        String selectName = lookupTable.getSelectName();
        if (null != selectName)
            strJoin.append(selectName);
        else
        {
            strJoin.append("(");
            strJoin.append(lookupTable.getFromSQL());
            strJoin.append(")");
        }

        strJoin.append(" AS ").append(colTableAlias);
        strJoin.append(" ON ");
        strJoin.append(getJoinCondition(baseAlias));
        assert null == map.get(colTableAlias) || map.get(colTableAlias).getSQL().equals(strJoin.getSQL());
        map.put(colTableAlias, strJoin);
    }


    public String getTableAlias()
    {
        return foreignKey.getAlias() + "$";
    }

    public void setJoinOnContainer(boolean joinOnContainer)
    {
        this.joinOnContainer = joinOnContainer;
    }

    public String getColumnName()
    {
        return lookupColumn.getName();
    }
}
