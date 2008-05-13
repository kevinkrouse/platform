/*
 * Copyright (c) 2006-2007 LabKey Corporation
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

import org.labkey.api.exp.api.ExpProtocolAction;
import org.labkey.api.exp.api.ExpProtocol;
import org.labkey.api.exp.api.ExperimentService;
import org.labkey.experiment.api.ProtocolAction;
import org.labkey.api.data.SimpleFilter;
import org.labkey.api.data.Table;
import org.labkey.api.security.User;
import org.apache.log4j.Logger;

import java.sql.SQLException;
import java.sql.ResultSet;
import java.util.*;

public class ExpProtocolActionImpl implements ExpProtocolAction
{
    static final private Logger _log = Logger.getLogger(ExpProtocolActionImpl.class);
    ProtocolAction _action;
    static public ExpProtocolActionImpl fromRowId(int id)
    {
        ProtocolAction action = Table.selectObject(ExperimentServiceImpl.get().getTinfoProtocolAction(), id, ProtocolAction.class);
        if (action == null)
            return null;
        return new ExpProtocolActionImpl(action);
    }

    public ExpProtocolActionImpl(ProtocolAction action)
    {
        _action = action;
    }

    public ExpProtocol getParentProtocol()
    {
        return ExperimentService.get().getExpProtocol(_action.getParentProtocolId());
    }

    public ExpProtocol getChildProtocol()
    {
        return ExperimentService.get().getExpProtocol(_action.getChildProtocolId());
    }

    public int getRowId()
    {
        return _action.getRowId();
    }

    public int getActionSequence()
    {
        return _action.getSequence();
    }

    public ExpProtocolAction[] getPredecessors()
    {
        ResultSet rs = null;
        try
        {
            List<ExpProtocolAction> ret = new ArrayList();
            SimpleFilter filter = new SimpleFilter();
            filter.addCondition("ActionId", getRowId());
            rs = Table.select(ExperimentServiceImpl.get().getTinfoProtocolActionPredecessor(), Collections.singleton("PredecessorId"), filter, null);
            while (rs.next())
            {
                ret.add(fromRowId(rs.getInt(1)));
            }
            return ret.toArray(new ExpProtocolAction[0]);
        }
        catch (SQLException e)
        {
            _log.error("Error", e);
            return new ExpProtocolAction[0];
        }
        finally
        {
            if (rs != null) { try { rs.close(); } catch (SQLException e) {} }
        }

    }

    public ExpProtocolAction[] getSuccessors()
    {
        ResultSet rs = null;
        try
        {
            List<ExpProtocolAction> ret = new ArrayList();
            SimpleFilter filter = new SimpleFilter();
            filter.addCondition("PredecessorId", getRowId());
            rs = Table.select(ExperimentServiceImpl.get().getTinfoProtocolActionPredecessor(), Collections.singleton("ActionId"), filter, null);
            while (rs.next())
            {
                ret.add(fromRowId(rs.getInt(1)));
            }
            return ret.toArray(new ExpProtocolAction[0]);
        }
        catch (SQLException e)
        {
            _log.error("Error", e);
            return new ExpProtocolAction[0];
        }
        finally
        {
            if (rs != null) { try { rs.close(); } catch (SQLException e) {} }
        }
    }

    public void addSuccessor(User user, ExpProtocolAction successor) throws Exception
    {
        Map<String, Integer> map = new HashMap();
        map.put("PredecessorId", getRowId());
        map.put("ActionId", successor.getRowId());
        Table.insert(user, ExperimentServiceImpl.get().getTinfoProtocolActionPredecessor(), map);
    }
}
