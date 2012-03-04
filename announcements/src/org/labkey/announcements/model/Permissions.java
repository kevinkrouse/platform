/*
 * Copyright (c) 2006-2012 LabKey Corporation
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

import org.jetbrains.annotations.Nullable;
import org.labkey.api.data.SimpleFilter;

/**
 * User: adam
 * Date: Nov 1, 2006
 * Time: 4:45:34 PM
 */
public interface Permissions
{
    public boolean allowResponse(AnnouncementModel ann);
    public boolean allowRead(@Nullable AnnouncementModel ann);
    public boolean allowInsert();
    public boolean allowUpdate(AnnouncementModel ann);
    public boolean allowDeleteMessage(AnnouncementModel ann);
    public boolean allowDeleteAnyThread();
    public SimpleFilter getThreadFilter();
    public boolean includeGroups();
}
