/*
 * Copyright (c) 2012-2014 LabKey Corporation
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
package org.labkey.api.laboratory;

import org.labkey.api.data.Container;
import org.labkey.api.security.User;
import org.labkey.api.view.ActionURL;

/**
 * User: bimber
 * Date: 11/21/12
 * Time: 5:07 PM
 */
public interface ImportingNavItem extends NavItem
{
    public ActionURL getImportUrl(Container c, User u);

    public ActionURL getSearchUrl(Container c, User u);

    public ActionURL getBrowseUrl(Container c, User u);

    public boolean isImportIntoWorkbooks(Container c, User u);
}
