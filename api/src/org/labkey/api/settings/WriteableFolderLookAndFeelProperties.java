/*
 * Copyright (c) 2008-2013 LabKey Corporation
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
package org.labkey.api.settings;

import org.apache.commons.lang3.time.FastDateFormat;
import org.labkey.api.data.Container;

import java.text.DecimalFormat;

import static org.labkey.api.settings.LookAndFeelFolderProperties.DEFAULT_DATE_FORMAT;
import static org.labkey.api.settings.LookAndFeelFolderProperties.DEFAULT_NUMBER_FORMAT;
import static org.labkey.api.settings.LookAndFeelProperties.LOOK_AND_FEEL_SET_NAME;

/**
 * User: adam
 * Date: Aug 1, 2008
 * Time: 9:35:40 PM
 */

// Handles only the properties that can be set at the folder level
public class WriteableFolderLookAndFeelProperties extends AbstractWriteableSettingsGroup
{
    WriteableFolderLookAndFeelProperties(Container c)
    {
        makeWriteable(c);
    }

    protected String getType()
    {
        return "look and feel settings";
    }

    protected String getGroupName()
    {
        return LOOK_AND_FEEL_SET_NAME;
    }

    // Make public
    public void save()
    {
        super.save();
    }

    public void clear()
    {
        getProperties().clear();
    }

    // Validate inside the set method, since this is called from multiple places
    public void setDefaultDateFormat(String defaultDateFormat) throws IllegalArgumentException
    {
        FastDateFormat.getInstance(defaultDateFormat);
        storeStringValue(DEFAULT_DATE_FORMAT, defaultDateFormat);
    }

    // Convenience method to support import: validate and save just this property
    public static void saveDefaultDateFormat(Container c, String defaultDateFormat) throws IllegalArgumentException
    {
        WriteableFolderLookAndFeelProperties props = LookAndFeelProperties.getWriteableFolderInstance(c);
        props.setDefaultDateFormat(defaultDateFormat);
        props.save();
    }

    // Validate inside the set method, since this is called from multiple places
    public void setDefaultNumberFormat(String defaultNumberFormat) throws IllegalArgumentException
    {
        new DecimalFormat(defaultNumberFormat);
        storeStringValue(DEFAULT_NUMBER_FORMAT, defaultNumberFormat);
    }

    // Convenience method to support import: validate and save just this property
    public static void saveDefaultNumberFormat(Container c, String defaultNumberFormat) throws IllegalArgumentException
    {
        WriteableFolderLookAndFeelProperties props = LookAndFeelProperties.getWriteableFolderInstance(c);
        props.setDefaultNumberFormat(defaultNumberFormat);
        props.save();
    }
}
