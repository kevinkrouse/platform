/*
 * Copyright (c) 2011 LabKey Corporation
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

package org.labkey.api.data.dialect;

import org.labkey.api.data.SQLFragment;

import java.util.regex.Pattern;

/*
* User: adam
* Date: Aug 13, 2011
* Time: 3:51:09 PM
*/

// Methods for escaping and parsing SQL identifiers and string literals, based on a particular database's rules.
public interface DialectStringHandler
{
    public String quoteStringLiteral(String str);
    public String substituteParameters(SQLFragment frag);
}
