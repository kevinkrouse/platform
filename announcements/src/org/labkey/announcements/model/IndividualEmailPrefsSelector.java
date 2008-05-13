/*
 * Copyright (c) 2007 LabKey Corporation
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

import org.labkey.announcements.model.AnnouncementManager.EmailPref;
import org.labkey.announcements.model.Announcement;
import org.labkey.api.data.Container;
import org.labkey.api.security.User;

import javax.servlet.ServletException;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/**
 * User: adam
 * Date: Mar 4, 2007
 * Time: 10:00:34 PM
 */
public class IndividualEmailPrefsSelector extends EmailPrefsSelector
{
    public IndividualEmailPrefsSelector(Container c) throws SQLException
    {
        super(c);
    }


    @Override
    protected boolean includeEmailPref(AnnouncementManager.EmailPref ep)
    {
        return super.includeEmailPref(ep) && ((ep.getEmailOptionId() & AnnouncementManager.EMAIL_NOTIFICATION_TYPE_DIGEST) == 0);
    }


    public List<User> getNotificationUsers(Announcement ann) throws ServletException, SQLException
    {
        List<User> authorized = new ArrayList<User>(_emailPrefs.size());

        for (EmailPref ep : _emailPrefs)
            if (shouldSend(ann, ep))
                authorized.add(ep.getUser());

        return authorized;
    }
}
