/*
 * Copyright (c) 2007-2015 LabKey Corporation
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

package org.labkey.announcements.model;

import org.labkey.api.data.Container;
import org.labkey.api.message.settings.MessageConfigService.UserPreference;

/**
 * User: adam
 * Date: Mar 4, 2007
 * Time: 10:00:34 PM
 */
public class IndividualEmailPrefsSelector extends EmailPrefsSelector
{
    public IndividualEmailPrefsSelector(Container c)
    {
        super(c);
    }


    @Override
    protected boolean includeEmailPref(UserPreference up)
    {
        return super.includeEmailPref(up) && (up.getEmailOptionId() == 0);
    }
}
