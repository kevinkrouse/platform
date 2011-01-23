/*
 * Copyright (c) 2010 LabKey Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.labkey.filecontent.message;

import org.apache.commons.lang.time.DateUtils;
import org.labkey.api.message.digest.PeriodicMessageDigest;

/**
 * Created by IntelliJ IDEA.
 * User: klum
 * Date: Jan 14, 2011
 * Time: 12:13:28 PM
 */

/**
 * A message digest that executes every fifteen minutes
 */
public class ShortMessageDigest extends PeriodicMessageDigest
{
    private static final ShortMessageDigest _instance = new ShortMessageDigest();

    public static ShortMessageDigest getInstance()
    {
        return _instance;
    }

    private ShortMessageDigest()
    {
        super("FifteenMinuteDigest", DateUtils.MILLIS_PER_MINUTE * 15);
    }

}
