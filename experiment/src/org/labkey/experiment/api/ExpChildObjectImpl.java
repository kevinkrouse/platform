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

package org.labkey.experiment.api;

import org.labkey.api.exp.api.ExpObject;
import org.labkey.api.exp.api.ExpChildObject;
import org.labkey.api.exp.PropertyDescriptor;
import org.labkey.api.exp.OntologyManager;
import org.labkey.api.util.URLHelper;
import org.labkey.api.security.User;

public class ExpChildObjectImpl extends ExpObjectImpl implements ExpChildObject
{
    ExpObject _owner;
    ExpObject _parent;
    PropertyDescriptor _pd;
    String _objectURI;
    public ExpChildObjectImpl(ExpObject owner, ExpObject parent, PropertyDescriptor pd, String objectURI)
    {
        _owner = owner;
        _parent = parent;
        _pd = pd;
        _objectURI = objectURI;
    }

    public String getContainerId()
    {
        return _owner.getContainer().getId();
    }
    
    public void setContainerId(String containerId)
    {
        throw new UnsupportedOperationException();
    }

    public String getLSID()
    {
        return _objectURI;
    }

    public void setLSID(String lsid)
    {
        _objectURI = lsid;
    }
    
    public void setName(String name)
    {
        throw new UnsupportedOperationException();
    }

    public String getName()
    {
        return null;
    }

    protected ExpObject getOwnerObject()
    {
        return _owner;
    }

    public int getRowId()
    {
        throw new UnsupportedOperationException();
    }

    public URLHelper detailsURL()
    {
        return null;
    }

    public User getCreatedBy()
    {
        return _parent.getCreatedBy();
    }

    public void delete(User user) throws Exception
    {
        OntologyManager.deleteProperty(_parent.getLSID(), _pd.getPropertyURI(), getContainer(), _pd.getContainer());
    }
}
