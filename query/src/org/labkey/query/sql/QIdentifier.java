/*
 * Copyright (c) 2006-2007 LabKey Corporation
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

import org.labkey.api.query.FieldKey;
import org.labkey.query.sql.SqlTokenTypes;
import org.apache.commons.lang.StringUtils;

public class QIdentifier extends QFieldKey
{
    public QIdentifier()
    {
    }

    public QIdentifier(String str)
    {
        if (QParser.isLegalIdentifier(str))
        {
            setTokenType(SqlTokenTypes.IDENT);
            setText(str);
            return;
        }
        setTokenType(SqlTokenTypes.QUOTED_IDENTIFIER);
        setText(quote(str));
    }

    public FieldKey getFieldKey()
    {
        return new FieldKey(null, getIdentifier());
    }

    public String getIdentifier()
    {
        if (getTokenType() == SqlTokenTypes.IDENT)
            return getTokenText();
        return unquote(getTokenText());
    }

    private String unquote(String str)
    {
        if (str.length() < 2)
            throw new IllegalArgumentException();
        if (!str.startsWith("\"") || !str.endsWith("\""))
            throw new IllegalArgumentException();
        str = str.substring(1, str.length() - 1);
        str = StringUtils.replace(str, "\"\"", "\"");
        return str;
    }

    private String quote(String str)
    {
        return "\"" + StringUtils.replace(str, "\"", "\"\"") + "\"";
    }


    public void appendSource(SourceBuilder builder)
    {
        builder.append(getTokenText());
    }

    public String getValueString()
    {
        return getTokenText();
    }
}
