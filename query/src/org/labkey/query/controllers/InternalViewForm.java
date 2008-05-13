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

import org.labkey.api.view.ViewForm;
import org.labkey.api.view.HttpView;
import org.labkey.api.view.ViewContext;
import org.labkey.api.security.ACL;
import org.labkey.api.security.User;
import org.apache.struts.action.ActionMapping;
import org.labkey.query.persist.CstmView;
import org.labkey.query.persist.QueryManager;

import javax.servlet.http.HttpServletRequest;
import java.awt.*;

public class InternalViewForm extends ViewForm
{
    private int _customViewId;
    CstmView _view;

    public void reset(ActionMapping actionMapping, HttpServletRequest request)
    {
        super.reset(actionMapping, request);
    }

    public CstmView getViewAndCheckPermission() throws Exception
    {
        if (_view != null)
            return _view;
        QueryManager mgr = QueryManager.get();
        CstmView view = mgr.getCustomView(_customViewId);
        checkEdit(getContext(), view);
        _view = view;
        return _view;
    }

    public int getCustomViewId()
    {
        return _customViewId;
    }

    public void setCustomViewId(int id)
    {
        _customViewId = id;
    }

    static public void checkEdit(ViewContext context, CstmView view) throws Exception
    {
        if (view == null)
        {
            HttpView.throwNotFound();
        }
        if (!view.getContainerId().equals(context.getContainer().getId()))
            HttpView.throwUnauthorized();
        if (view.getCustomViewOwner() == null)
        {
            if (!context.hasPermission(ACL.PERM_UPDATE))
                HttpView.throwUnauthorized();
        }
        else
        {
            if (view.getCustomViewOwner().intValue() != context.getUser().getUserId())
            {
                HttpView.throwUnauthorized();
            }
        }

    }
}
