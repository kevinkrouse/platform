/*
 * Copyright (c) 2008 LabKey Corporation
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
package org.labkey.api.view;

import org.labkey.api.data.Container;
import org.labkey.api.security.LoginUrls;
import org.labkey.api.util.PageFlowUtil;

/**
 * User: adam
 * Date: Aug 27, 2008
 * Time: 3:00:45 PM
 */

// Thrown when admin is impersonating within a project and attempts to access a folder outside that project.  Used to
//  provide a more helpful error message.
public class ForbiddenProjectException extends UnauthorizedException
{
    public ForbiddenProjectException(String url, Container c)
    {
        super("You are not allowed to access this folder while impersonating within a different project.", url, c);
    }
}
