/*
 * Copyright (c) 2004-2009 Fred Hutchinson Cancer Research Center
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

import org.apache.commons.lang.StringUtils;

import javax.servlet.http.HttpServletResponse;

public class UnauthorizedException extends RuntimeException
{
    public UnauthorizedException()
    {
        this(null);
    }

    public UnauthorizedException(String message)
    {
        super(StringUtils.defaultIfEmpty(message, "" + HttpServletResponse.SC_UNAUTHORIZED + ": User does not have permission to perform this operation"));
    }
}