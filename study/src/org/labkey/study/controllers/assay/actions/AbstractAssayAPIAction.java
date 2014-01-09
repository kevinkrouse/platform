/*
 * Copyright (c) 2009-2014 LabKey Corporation
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
package org.labkey.study.controllers.assay.actions;

import org.json.JSONObject;
import org.labkey.api.action.ApiAction;
import org.labkey.api.action.ApiResponse;
import org.labkey.api.action.SimpleApiJsonForm;
import org.labkey.api.data.Container;
import org.labkey.api.exp.api.AssayJSONConverter;
import org.labkey.api.exp.api.ExpProtocol;
import org.labkey.api.exp.api.ExperimentService;
import org.labkey.api.study.assay.AssayProvider;
import org.labkey.api.study.assay.AssayService;
import org.labkey.api.util.Pair;
import org.labkey.api.view.NotFoundException;
import org.springframework.validation.BindException;

import java.util.List;

/**
 * User: jeckels
 * Date: Jan 15, 2009
 */
public abstract class AbstractAssayAPIAction<FORM extends SimpleApiJsonForm> extends ApiAction<FORM>
{

    public final ApiResponse execute(FORM form, BindException errors) throws Exception
    {
        if (form.getJsonObject() == null)
        {
            form.bindProperties(new JSONObject());
        }

        Pair<ExpProtocol, AssayProvider> pair = getProtocolProvider(form.getJsonObject(), getContainer());
        ExpProtocol protocol = pair.first;
        AssayProvider provider = pair.second;

        return executeAction(protocol, provider, form, errors);
    }

    public static Pair<ExpProtocol, AssayProvider> getProtocolProvider(JSONObject json, Container c)
    {
        int assayId = json.getInt(AssayJSONConverter.ASSAY_ID);
        return getProtocolProvider(assayId, c);
    }

    public static Pair<ExpProtocol, AssayProvider> getProtocolProvider(Integer assayId, Container c)
    {
        if (assayId == null)
        {
            throw new IllegalArgumentException("assayId parameter required");
        }

        ExpProtocol protocol = ExperimentService.get().getExpProtocol(assayId);
        if (protocol == null)
        {
            throw new NotFoundException("Could not find assay id " + assayId);
        }

        List<ExpProtocol> availableAssays = AssayService.get().getAssayProtocols(c);
        if (!availableAssays.contains(protocol))
        {
            throw new NotFoundException("Assay id " + assayId + " is not visible for folder " + c);
        }

        AssayProvider provider = AssayService.get().getProvider(protocol);
        if (provider == null)
        {
            throw new NotFoundException("Could not find assay provider for assay id " + assayId);
        }

        return Pair.of(protocol, provider);
    }

    protected abstract ApiResponse executeAction(ExpProtocol assay, AssayProvider provider, FORM form, BindException errors) throws Exception;
}
