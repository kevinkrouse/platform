/*
 * Copyright (c) 2006-2012 LabKey Corporation
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

package org.labkey.query.sql;

import org.labkey.api.data.ColumnInfo;
import org.labkey.api.data.DisplayColumn;
import org.labkey.api.data.DisplayColumnFactory;
import org.labkey.api.data.JdbcType;
import org.labkey.api.data.MultiValuedDisplayColumn;
import org.labkey.api.data.dialect.SqlDialect;

import java.util.List;

public class QAggregate extends QExpr
{
    public static final String COUNT = "count";
    public static final String GROUP_CONCAT = "group_concat";

    public enum Type
    {
        COUNT, SUM, MIN, MAX, AVG, GROUP_CONCAT ,
        STDDEV
            {
                @Override
                String getFunction(SqlDialect d)
                {
                    return d.getStdDevFunction();
                }
            },
        STDERR
            {
                @Override
                String getFunction(SqlDialect d)
                {
                    return null;
                }
            }
        // CONSIDER STDDEVP, VAR, VARP
        ;

        String getFunction(SqlDialect d)
        {
            return name();
        }
    }

    private Type _type;
    private boolean _distinct;
    private String _delimiter = null;

    public QAggregate()
    {
        super(QNode.class);
    }


    public Type getType()
    {
        if (null == _type)
        {
            String function = getTokenText();
            _type = Type.valueOf(function.toUpperCase());
        }
        return _type;
    }
    

    public void appendSql(SqlBuilder builder)
    {
        Type type = getType();

        if (type == Type.GROUP_CONCAT)
        {
            SqlBuilder nestedBuilder = new SqlBuilder(builder.getDbSchema());
            for (QNode child : children())
            {
                ((QExpr)child).appendSql(nestedBuilder);
            }
            builder.append(builder.getDialect().getGroupConcat(nestedBuilder, _distinct, true, null == _delimiter ? "," : _delimiter));
        }
        else if (type == Type.STDERR)
        {
            assert !_distinct;
            // verify that NULL/0 is NULL not #DIV0
            // postgres[ok]
            // sqlserver[?]
            builder.append(" (" + Type.STDDEV.getFunction(builder.getDialect()) + "(");
            for (QNode child : children())
                ((QExpr)child).appendSql(builder);
            builder.append(")/SQRT(COUNT(");
            for (QNode child : children())
                ((QExpr)child).appendSql(builder);
            builder.append(")))");
        }
        else
        {
            String function = type.getFunction(builder.getDialect());
            builder.append(" " + function + "(");
            if (_distinct)
            {
                builder.append("DISTINCT ");
            }
            for (QNode child : children())
            {
                ((QExpr)child).appendSql(builder);
            }
            builder.append(")");
        }
    }

    public void appendSource(SourceBuilder builder)
    {
        builder.append(" " + getTokenText() + "(");
        if (_distinct)
        {
            builder.append("DISTINCT ");
        }
        for (QNode child : children())
        {
            child.appendSource(builder);
        }
        builder.append(")");
    }

    public JdbcType getSqlType()
    {
        if (getType() == Type.COUNT)
        {
            return JdbcType.INTEGER;
        }
        if (getType() == Type.GROUP_CONCAT)
        {
            return JdbcType.VARCHAR;
        }
		if (getFirstChild() != null)
			return ((QExpr)getFirstChild()).getSqlType();
        return JdbcType.OTHER;
    }

    public boolean isAggregate()
    {
        return true;
    }

    public ColumnInfo createColumnInfo(SQLTableInfo table, String alias)
    {
        ColumnInfo ret = super.createColumnInfo(table, alias);
        if (getType() == Type.MAX || getType() == Type.MIN)
        {
            List<QNode> children = childList();
            if (children.size() == 1 && children.get(0) instanceof QField)
            {
                QField field = (QField) children.get(0);
                field.getRelationColumn().copyColumnAttributesTo(ret);
                // but not these attributes, maybe I should have a white-list instead of a black-list
                ret.setLabel(null);
                ret.setURL(null);
                ret.setMvColumnName(null);
                ret.setDisplayColumnFactory(ColumnInfo.DEFAULT_FACTORY);
                ret.setFk(null);
            }
        }
        if (getType() == Type.GROUP_CONCAT)
        {
            final DisplayColumnFactory originalFactory = ret.getDisplayColumnFactory();
            ret.setDisplayColumnFactory(new DisplayColumnFactory()
            {
                @Override
                public DisplayColumn createRenderer(ColumnInfo colInfo)
                {
                    return new MultiValuedDisplayColumn(originalFactory.createRenderer(colInfo));
                }
            });
        }
        return ret;
    }

    public void setDistinct(boolean distinct)
    {
        _distinct = distinct;
    }

    public void setDelimiter(String delimiter)
    {
        _delimiter = delimiter;
    }

    @Override
    public boolean equalsNode(QNode other)
    {
        return other instanceof QAggregate &&
                ((QAggregate) other).getType() == getType() &&
                _distinct == ((QAggregate)other)._distinct;
    }

    @Override
    public boolean isConstant()
    {
        return false;
    }
}
