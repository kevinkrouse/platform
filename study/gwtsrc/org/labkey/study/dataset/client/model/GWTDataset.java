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

package org.labkey.study.dataset.client.model;

import com.google.gwt.user.client.rpc.IsSerializable;
import org.labkey.api.gwt.client.util.BooleanProperty;
import org.labkey.api.gwt.client.util.IntegerProperty;
import org.labkey.api.gwt.client.util.StringProperty;

import java.util.Map;

/**
 * Created by IntelliJ IDEA.
 * User: matthewb
 * Date: Apr 30, 2007
 * Time: 9:51:51 AM
 */
public class GWTDataset implements IsSerializable
{
    private IntegerProperty _datasetId = new IntegerProperty(0);
    private StringProperty _name = new StringProperty();
    private StringProperty _typeURI = new StringProperty();
    private StringProperty _category = new StringProperty();
    private StringProperty _visitDatePropertyName = new StringProperty();
    private StringProperty _keyPropertyName = new StringProperty();
    private BooleanProperty _isDemographicData = new BooleanProperty();
    private StringProperty _label = new StringProperty();
    private IntegerProperty _cohortId = new IntegerProperty(0);
    private BooleanProperty _showByDefault = new BooleanProperty();
    private StringProperty _description = new StringProperty();

    /**
     * @gwt.typeArgs <java.lang.String, java.lang.String>
     */
    private Map _cohortMap;

    /**
     * @gwt.typeArgs <java.lang.String, java.lang.String>
     */
    private Map _visitDateMap;


    public GWTDataset()
    {
    }

    public String getKeyPropertyName()
    {
        return _keyPropertyName.getString();
    }

    public void setKeyPropertyName(String keyPropertyName)
    {
        this._keyPropertyName.set(keyPropertyName);
    }

    public int getDatasetId()
    {
        return _datasetId.getInt();
    }

    public void setDatasetId(int datasetId)
    {
        this._datasetId.setInt(datasetId);
    }

    public String getName()
    {
        return _name.getString();
    }

    public void setName(String name)
    {
        this._name.set(name);
    }

    public String getTypeURI()
    {
        return _typeURI.getString();
    }

    public void setTypeURI(String typeURI)
    {
        this._typeURI.set(typeURI);
    }

    public String getCategory()
    {
        return _category.getString();
    }

    public void setCategory(String category)
    {
        this._category.set(category);
    }

    public String getVisitDatePropertyName()
    {
        return _visitDatePropertyName.getString();
    }

    public void setVisitDatePropertyName(String visitDatePropertyName)
    {
        this._visitDatePropertyName.set(visitDatePropertyName);
    }

    public boolean getDemographicData()
    {
        return _isDemographicData.getBool();
    }

    public void setDemographicData(boolean demographicData)
    {
        _isDemographicData.setBool(demographicData);
    }

    public String getLabel()
    {
        return _label.getString();
    }

    public void setLabel(String label)
    {
        _label.set(label);
    }

    public Integer getCohortId()
    {
        return _cohortId.getInteger();
    }

    public void setCohortId(Integer cohortId)
    {
        _cohortId.set(cohortId);
    }

    public boolean getShowByDefault()
    {
        return _showByDefault.getBool();
    }

    public void setShowByDefault(boolean showByDefault)
    {
        _showByDefault.setBool(showByDefault);
    }

    public String getDescription()
    {
        return _description.getString();
    }

    public void setDescription(String description)
    {
        _description.set(description);
    }

    public Map getCohortMap()
    {
        return _cohortMap;
    }

    public void setCohortMap(Map cohortMap)
    {
        _cohortMap = cohortMap;
    }

    public Map getVisitDateMap()
    {
        return _visitDateMap;
    }

    public void setVisitDateMap(Map visitDateMap)
    {
        _visitDateMap = visitDateMap;
    }
}
