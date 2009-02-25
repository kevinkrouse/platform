/*
 * Copyright (c) 2009 LabKey Corporation
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

package org.labkey.api.study.assay;

import org.labkey.api.data.DataRegion;
import org.labkey.api.exp.api.ExpProtocol;
import org.labkey.api.study.actions.AssayHeaderView;
import org.labkey.api.study.query.ResultsQueryView;
import org.labkey.api.view.VBox;
import org.labkey.api.view.ViewContext;

/**
 * User: kevink
 */
public class AssayResultsView extends VBox
{
    private AssayProvider _provider;
    private ExpProtocol _protocol;
    private ResultsQueryView _resultsView;
    private boolean _minimizeLinks;

    public AssayResultsView(AssayProvider provider, ExpProtocol protocol)
    {
        _provider = provider;
        _protocol = protocol;
        initalize();
    }

    public AssayResultsView(ExpProtocol protocol, boolean minimizeLinks)
    {
        _protocol = protocol;
        _provider = AssayService.get().getProvider(_protocol);
        _minimizeLinks = minimizeLinks;
        initalize();
    }

    protected void initalize()
    {
        ViewContext context = getViewContext();

        _resultsView = _provider.createResultsQueryView(context, _protocol);
        AssayHeaderView headerView = new AssayHeaderView(_protocol, _provider, _minimizeLinks, _resultsView.getTable().getContainerFilter());
        if (_minimizeLinks)
        {
            _resultsView.setButtonBarPosition(DataRegion.ButtonBarPosition.NONE);
            _resultsView.setShowRecordSelectors(false);
        }
        else
        {
            _resultsView.setButtonBarPosition(DataRegion.ButtonBarPosition.BOTH);
        }

        addView(headerView);

        if (!_provider.allowUpload(context.getUser(), context.getContainer(), _protocol))
            addView(_provider.getDisallowedUploadMessageView(context.getUser(), context.getContainer(), _protocol));

        addView(_resultsView);
    }
}
