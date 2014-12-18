/*
 * Copyright (c) 2014 LabKey Corporation
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
package org.labkey.mothership;

import org.labkey.api.data.UpgradeCode;
import org.labkey.api.module.ModuleContext;
import org.labkey.api.settings.AppProps;
import org.labkey.api.settings.WriteableAppProps;
import org.labkey.api.util.ExceptionReportingLevel;
import org.labkey.api.util.UsageReportingLevel;

/**
 * Created by: jeckels
 * Date: 11/27/14
 */
public class MothershipUpgradeCode implements UpgradeCode
{
    // invoked by mothership-14.30-14.31.sql
    @SuppressWarnings({"UnusedDeclaration"})
    public void reconfigureExceptionReporting(final ModuleContext context)
    {
        // We now support reporting to both the local server and to labkey.org
        // For existing servers with the mothership module that are running in dev mode,
        // assume they should only report to local, which is consistent with previous behavior
        if (AppProps.getInstance().isDevMode())
        {
            WriteableAppProps appProps = AppProps.getWriteableInstance();
            appProps.setSelfReportExceptions(true);
            appProps.setExceptionReportingLevel(ExceptionReportingLevel.NONE);
            appProps.setUsageReportingLevel(UsageReportingLevel.NONE);
            appProps.save();
        }
    }

}
