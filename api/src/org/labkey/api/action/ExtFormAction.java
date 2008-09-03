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
package org.labkey.api.action;

/*
* User: Dave
* Date: Sep 3, 2008
* Time: 10:59:49 AM
*/

/**
 * Base class for API Actions that will received data posted from an Ext form.
 * This class ensures that the validation errors are reported back to the form
 * in the way that Ext forms require.
 */
public abstract class ExtFormAction<FORM> extends ApiAction<FORM>
{
    public ExtFormAction()
    {
    }

    public ExtFormAction(Class<? extends FORM> formClass)
    {
        super(formClass);
    }

    public ApiResponseWriter createResponseWriter()
    {
        return new ExtFormResponseWriter(getViewContext().getResponse(), getContentTypeOverride());
    }
}