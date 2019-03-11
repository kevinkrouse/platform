/*
 * Copyright (c) 2006-2018 LabKey Corporation
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

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.labkey.api.data.ColumnInfo;
import org.labkey.api.data.DisplayColumn;
import org.labkey.api.data.DisplayColumnFactory;
import org.labkey.api.data.JdbcType;
import org.labkey.api.data.MultiValuedDisplayColumn;
import org.labkey.api.data.SQLFragment;
import org.labkey.api.data.dialect.SqlDialect;

import java.util.Collection;
import java.util.Iterator;
import java.util.List;

public class QAggregate extends QExpr
{
    public static final String COUNT = "count";
    public static final String GROUP_CONCAT = "group_concat";

    public enum Type
    {
        COUNT, SUM, MIN, MAX, AVG, GROUP_CONCAT,
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
            },

        BOOL_AND
            {
                @Override
                boolean dialectSupports(@Nullable SqlDialect d)
                {
                    return null != d && d.isPostgreSQL();
                }
            },
        BOOL_OR
            {
                @Override
                boolean dialectSupports(@Nullable SqlDialect d)
                {
                    return null != d && d.isPostgreSQL();
                }
            },
        BIT_AND
            {
                @Override
                boolean dialectSupports(@Nullable SqlDialect d)
                {
                    return null != d && d.isPostgreSQL();
                }
            },
        BIT_OR
            {
                @Override
                boolean dialectSupports(@Nullable SqlDialect d)
                {
                    return null != d && d.isPostgreSQL();
                }
            },
        CORR
            {
                @Override
                boolean dialectSupports(@Nullable SqlDialect d)
                {
                    return null != d && d.isPostgreSQL();
                }
            },
        COVAR_POP
            {
                @Override
                boolean dialectSupports(@Nullable SqlDialect d)
                {
                    return null != d && d.isPostgreSQL();
                }
            },
        COVAR_SAMP
            {
                @Override
                boolean dialectSupports(@Nullable SqlDialect d)
                {
                    return null != d && d.isPostgreSQL();
                }
            },
        REGR_AVGX
            {
                @Override
                boolean dialectSupports(@Nullable SqlDialect d)
                {
                    return null != d && d.isPostgreSQL();
                }
            },
        REGR_AVGY
            {
                @Override
                boolean dialectSupports(@Nullable SqlDialect d)
                {
                    return null != d && d.isPostgreSQL();
                }
            },
        REGR_COUNT
            {
                @Override
                boolean dialectSupports(@Nullable SqlDialect d)
                {
                    return null != d && d.isPostgreSQL();
                }
            },
        REGR_INTERCEPT
            {
                @Override
                boolean dialectSupports(@Nullable SqlDialect d)
                {
                    return null != d && d.isPostgreSQL();
                }
            },
        REGR_SLOPE
            {
                @Override
                boolean dialectSupports(@Nullable SqlDialect d)
                {
                    return null != d && d.isPostgreSQL();
                }
            },
        REGR_SXX
            {
                @Override
                boolean dialectSupports(@Nullable SqlDialect d)
                {
                    return null != d && d.isPostgreSQL();
                }
            },
        REGR_R2
            {
                @Override
                boolean dialectSupports(@Nullable SqlDialect d)
                {
                    return null != d && d.isPostgreSQL();
                }
            },
        REGR_SXY
            {
                @Override
                boolean dialectSupports(@Nullable SqlDialect d)
                {
                    return null != d && d.isPostgreSQL();
                }
            },
        REGR_SYY
            {
                @Override
                boolean dialectSupports(@Nullable SqlDialect d)
                {
                    return null != d && d.isPostgreSQL();
                }
            },
        EVERY
            {
                @Override
                boolean dialectSupports(@Nullable SqlDialect d)
                {
                    return null != d && d.isPostgreSQL();
                }
            },
        MEDIAN               // Only Postgres so far
            {
                @Override
                String getFunction(SqlDialect d)
                {
                    return d.getMedianFunction();
                }

                @Override
                boolean dialectSupports(SqlDialect d)
                {
                    return null != d && d.isPostgreSQL();
                }
            },
        MODE                // Only Postgres so far
            {
                @Override
                boolean dialectSupports(SqlDialect d)
                {
                    return null != d && d.isPostgreSQL();
                }
            },
        STDDEV_POP
            {
                @Override
                String getFunction(SqlDialect d)
                {
                    return d.getStdDevPopFunction();
                }
            },
        STDDEV_SAMP
            {
                @Override
                boolean dialectSupports(@Nullable SqlDialect d)
                {
                    return null != d && d.isPostgreSQL();
                }
            },
        VARIANCE
            {
                @Override
                String getFunction(SqlDialect d)
                {
                    return d.getVarianceFunction();
                }
            },
        VAR_POP
            {
                @Override
                String getFunction(SqlDialect d)
                {
                    return d.getVarPopFunction();
                }
            },
        VAR_SAMP
            {
                @Override
                boolean dialectSupports(@Nullable SqlDialect d)
                {
                    return null != d && d.isPostgreSQL();
                }
            }
        ;

        String getFunction(SqlDialect d)
        {
            return name();
        }

        boolean dialectSupports(@Nullable SqlDialect d)
        {
            return true;
        }
    }

    private Type _type;
    private boolean _distinct;

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

    @Override
    public void appendSql(SqlBuilder builder, Query query)

    /* ** Possible for SQL Server Median
    {
        appendSql(builder, query, null, null);
    }

    @Override
    public void appendSql(SqlBuilder builder, Query query, @Nullable QuerySelect querySelect, @Nullable QuerySelect.SelectColumn selectColumn)
    */

    {
        Type type = getType();

        if (type == Type.GROUP_CONCAT)
        {
            SqlBuilder nestedBuilder = new SqlBuilder(builder.getDialect());
            Iterator<QNode> iter = children().iterator();
            ((QExpr)iter.next()).appendSql(nestedBuilder, query);

            SQLFragment gcSql;

            // Don't blow up if database doesn't support GROUP_CONCAT, #15554
            if (builder.getDialect().supportsGroupConcat())
            {
                if (iter.hasNext())
                {
                    SqlBuilder delimiter = new SqlBuilder(builder.getDialect());
                    ((QExpr)iter.next()).appendSql(delimiter, query);
                    gcSql = builder.getDialect().getGroupConcat(nestedBuilder, _distinct, true, delimiter.getSQL());
                }
                else
                {
                    gcSql = builder.getDialect().getGroupConcat(nestedBuilder, _distinct, true);
                }
            }
            else
            {
                gcSql = new SQLFragment("'<GROUP_CONCAT function not supported on this database>'");
            }

            builder.append(gcSql);
        }
        else if (type == Type.STDERR)
        {
            assert !_distinct;
            // verify that NULL/0 is NULL not #DIV0
            // postgres[ok]
            // sqlserver[?]
            builder.append(" (").append(Type.STDDEV.getFunction(builder.getDialect())).append("(");
            for (QNode child : children())
                ((QExpr)child).appendSql(builder, query);
            builder.append(")/SQRT(COUNT(");
            for (QNode child : children())
                ((QExpr)child).appendSql(builder, query);
            builder.append(")))");
        }
        else if (type == Type.MEDIAN)
        {
            if (builder.getDialect().isSqlServer()) //  && null == querySelect)       // Possible way to support SQL Server Median
            {
                query.reportError("Cannot construct Median query in this context.");
            }
            else
            {
                assert !_distinct;
                builder.append(" (").append(type.getFunction(builder.getDialect())).append("(0.5) WITHIN GROUP (ORDER BY (");
                for (QNode child : children())
                {
                    ((QExpr) child).appendSql(builder, query);
                }
                builder.append("))");
                extraForSqlServerMedian(builder);
                builder.append(")");
            }
        }
        else if (type == Type.MODE)
        {
            assert !_distinct;
            builder.append(" (").append(type.getFunction(builder.getDialect())).append("() WITHIN GROUP (ORDER BY (");
            for (QNode child : children())
            {
                ((QExpr)child).appendSql(builder, query);
            }
            builder.append(")))");
        }
        else
        {
            String function = type.getFunction(builder.getDialect());
            builder.append(" ").append(function).append("(");
            if (_distinct)
            {
                builder.append("DISTINCT ");
            }
            String sep = "";
            for (QNode child : children())
            {
                builder.append(sep);
                ((QExpr)child).appendSql(builder, query);
                sep = ", ";
            }
            builder.append(")");
        }
    }

    private void extraForSqlServerMedian(SqlBuilder builder)
    {
        /* ** Possible way to support SQL Server Median
        if (builder.getDialect().isSqlServer() && null != querySelect && null != selectColumn)
        {
            querySelect.addMedianColumn(selectColumn);
            builder.append(" OVER(");
            Collection<QuerySelect.SelectColumn> groupByColumns = querySelect.getGroupByColumns().values();
            if (groupByColumns.size() > 0)
            {
                builder.append("PARTITION BY ");
                String sep = "";
                for (QuerySelect.SelectColumn col : querySelect.getGroupByColumns().values())
                {
                    builder.append(sep);
                    col.getResolvedField().appendSql(builder, query);
                    sep = ", ";
                }
            }
            builder.append(")");
        }
        */
    }

    public void appendSource(SourceBuilder builder)
    {
        builder.append(" ").append(getTokenText()).append("(");
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

    @Override @NotNull
    public JdbcType getJdbcType()
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
			return ((QExpr)getFirstChild()).getJdbcType();
        return JdbcType.OTHER;
    }

    public boolean isAggregate()
    {
        return true;
    }

    public ColumnInfo createColumnInfo(SQLTableInfo table, String alias, Query query)
    {
        ColumnInfo ret = super.createColumnInfo(table, alias, query);
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

    public boolean isDistinct()
    {
        return _distinct;
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
