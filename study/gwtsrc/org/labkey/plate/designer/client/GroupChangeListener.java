/*
 * Copyright (c) 2007-2008 LabKey Corporation
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

package org.labkey.plate.designer.client;

import org.labkey.plate.designer.client.model.GWTWellGroup;

/**
 * User: brittp
 * Date: Feb 7, 2007
 * Time: 4:17:33 PM
 */
public interface GroupChangeListener
{
    void groupAdded(GWTWellGroup group);

    void groupRemoved(GWTWellGroup group);

    void activeGroupChanged(GWTWellGroup previouslyActive, GWTWellGroup currentlyActive);

    void activeGroupTypeChanged(String type);
}
