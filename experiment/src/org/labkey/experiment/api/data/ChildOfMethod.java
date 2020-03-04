package org.labkey.experiment.api.data;

import org.labkey.api.data.JdbcType;
import org.labkey.api.data.SQLFragment;
import org.labkey.api.data.dialect.SqlDialect;
import org.labkey.api.query.AbstractMethodInfo;

public class ChildOfMethod extends AbstractMethodInfo
{
    public static final String NAME = "ExpChildOf";

    public ChildOfMethod()
    {
        super(JdbcType.BOOLEAN);
    }

    @Override
    public SQLFragment getSQL(SqlDialect dialect, SQLFragment[] arguments)
    {
        SQLFragment fieldKeyFrag = arguments[0];
        SQLFragment lsidFrag = arguments[1];
        return LineageHelper.createInSQL(fieldKeyFrag, lsidFrag, LineageHelper.createChildOfOptions());
    }

}
