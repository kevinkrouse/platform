/*
 * Copyright (c) 2006-2008 LabKey Corporation
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

package org.labkey.query.controllers;

import org.apache.struts.action.ActionMapping;
import org.labkey.api.query.QueryAction;
import org.labkey.api.query.QueryForm;
import org.labkey.api.view.ActionURL;
import org.labkey.api.view.ViewContext;

import javax.servlet.http.HttpServletRequest;

public class SourceForm extends QueryForm
{
    public String ff_queryText;
    public String ff_metadataText;
    public QueryAction ff_redirect = QueryAction.sourceQuery;

    public SourceForm()
    {
    }

    public SourceForm(ViewContext context)
    {
        setViewContext(context);
        setContainer(context.getContainer());
        setUser(context.getUser());
    }

    public void reset(ActionMapping actionMapping, HttpServletRequest request)
    {
        super.reset(actionMapping, request);
    }

    public void setFf_queryText(String text)
    {
        ff_queryText = text;
    }

    public void setFf_metadataText(String text)
    {
        ff_metadataText = text;
    }
    public void setFf_redirect(String action)
    {
        ff_redirect = QueryAction.valueOf(action);
    }

    public ActionURL getForwardURL()
    {
        return getQueryDef().urlFor(ff_redirect);
    }
}
