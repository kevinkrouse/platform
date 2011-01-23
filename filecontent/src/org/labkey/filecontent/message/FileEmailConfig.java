/*
 * Copyright (c) 2010 LabKey Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.labkey.filecontent.message;

import org.labkey.api.action.ReturnUrlForm;
import org.labkey.api.action.SpringActionController;
import org.labkey.api.data.DataRegionSelection;
import org.labkey.api.message.settings.AbstractConfigTypeProvider;
import org.labkey.api.message.settings.MessageConfigService;
import org.labkey.api.util.ReturnURLString;
import org.labkey.api.view.HttpView;
import org.labkey.api.view.JspView;
import org.labkey.api.view.ViewContext;
import org.springframework.validation.BindException;
import org.springframework.validation.Errors;

import java.util.Set;

/**
 * Created by IntelliJ IDEA.
 * User: klum
 * Date: Jan 19, 2011
 * Time: 3:01:52 PM
 */
public class FileEmailConfig extends AbstractConfigTypeProvider implements MessageConfigService.ConfigTypeProvider
{
    public static final String TYPE = "files";

    @Override
    public String getType()
    {
        return TYPE;
    }

    @Override
    public String getName()
    {
        // appears in the config tab
        return getType();
    }

    @Override
    public HttpView createConfigPanel(ViewContext context, MessageConfigService.PanelInfo info) throws Exception
    {
        EmailConfigForm form = new EmailConfigForm();

        form.setDataRegionSelectionKey(info.getDataRegionSelectionKey());
        form.setReturnUrl(new ReturnURLString(info.getReturnUrl().getLocalURIString()));

        return new JspView<EmailConfigForm>("/org/labkey/filecontent/view/fileNotifySettings.jsp", form);
    }

    @Override
    public void validateCommand(ViewContext context, Errors errors)
    {
        Set<String> selected = DataRegionSelection.getSelected(context, false);

        if (selected.isEmpty())
            errors.reject(SpringActionController.ERROR_MSG, "There are no users selected for this update.");
    }

    @Override
    public boolean handlePost(ViewContext context, BindException errors) throws Exception
    {
        return false;  //To change body of implemented methods use File | Settings | File Templates.
    }

    public static class EmailConfigForm  extends ReturnUrlForm
    {
        int _defaultEmailOption;
        int _individualEmailOption;
        String _dataRegionSelectionKey;

        public int getDefaultEmailOption()
        {
            return _defaultEmailOption;
        }

        public void setDefaultEmailOption(int defaultEmailOption)
        {
            _defaultEmailOption = defaultEmailOption;
        }

        public int getIndividualEmailOption()
        {
            return _individualEmailOption;
        }

        public void setIndividualEmailOption(int individualEmailOption)
        {
            _individualEmailOption = individualEmailOption;
        }

        public String getDataRegionSelectionKey()
        {
            return _dataRegionSelectionKey;
        }

        public void setDataRegionSelectionKey(String dataRegionSelectionKey)
        {
            _dataRegionSelectionKey = dataRegionSelectionKey;
        }
    }
}
