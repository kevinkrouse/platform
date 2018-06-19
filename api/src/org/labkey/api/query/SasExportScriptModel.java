/*
 * Copyright (c) 2009-2017 LabKey Corporation
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
package org.labkey.api.query;

import org.apache.commons.lang3.StringUtils;
import org.labkey.api.data.CompareType;

import java.util.List;

/**
 * User: adam
 * Date: Jan 27, 2009
 * Time: 3:13:06 PM
 */
public class SasExportScriptModel extends ExportScriptModel
{
    public SasExportScriptModel(QueryView view)
    {
        super(view);
    }

    public String getFilters()
    {
        List<String> filterExprs = getFilterExpressions();

        if (filterExprs.isEmpty())
            return null;

        StringBuilder filtersExpr = new StringBuilder("%labkeyMakeFilter(");
        String sep = "";

        for(String mf : filterExprs)
        {
            filtersExpr.append(sep);
            filtersExpr.append(mf);
            sep = ",";
        }
        filtersExpr.append(")");

        return filtersExpr.toString();
    }

    protected String makeFilterExpression(String name, CompareType operator, String value)
    {
        if (operator.isDataValueRequired())
            return "\"" + name + "\",\"" + operator.getScriptName() + "\",\"" + value + "\"";
        else
            return "\"" + name + "\",\"" + operator.getScriptName() + "\"";
    }

    @Override
    public String getScriptExportText()
    {
        StringBuilder sb = new StringBuilder();
        String indent = StringUtils.repeat(" ", 8);

        sb.append("/*").append("\n");
        sb.append(" * SAS Script generated by ").append(getInstallationName()).append(" on ").append(getCreatedOn()).append("\n");
        sb.append(" *").append("\n");
        sb.append(" * This script makes use of the SAS/LabKey macros and jar files that must be configured on your").append("\n");
        sb.append(" * SAS installation. See https://www.labkey.org/Documentation/wiki-page.view?name=sasAPI").append("\n");
        sb.append(" * for configuration information.").append("\n");
        sb.append(" */").append("\n");
        sb.append("\n");
        sb.append("/*  Select rows into a data set called 'mydata' */").append("\n");
        sb.append("\n");

        if (hasQueryParameters())
        {
            sb.append("/*  WARNING: This appears to be a parameterized query, but the SAS/LabKey macros do not yet support query parameters! */").append("\n");
            sb.append("\n");
        }

        sb.append("%labkeySelectRows(dsn=mydata,").append("\n");
        sb.append(indent).append("baseUrl=").append(doubleQuote(getBaseUrl())).append(",").append("\n");
        sb.append(indent).append("folderPath=").append(doubleQuote(getFolderPath())).append(",").append("\n");
        sb.append(indent).append("schemaName=").append(doubleQuote(getSchemaName())).append(",").append("\n");
        sb.append(indent).append("queryName=").append(doubleQuote(getQueryName()));
        if (null != getViewName()) {
            sb.append(",\n");
            sb.append(indent).append("viewName=").append(doubleQuote(getViewName()));
        }

        if (hasSort()) {
            sb.append(",\n");
            sb.append(indent).append("sort=").append(doubleQuote(getSort()));
        }

        if (null != getFilters()) {
            sb.append(",\n");
            sb.append(indent).append("filter=").append(getFilters());
        }

        if (hasContainerFilter()) {
            sb.append(",\n");
            sb.append(indent).append("containerFilter=").append(doubleQuote(getContainerFilterTypeName()));
        }

        sb.append(");\n");

        return sb.toString();
    }
}
