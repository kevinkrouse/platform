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

import org.labkey.api.action.LabkeyError;
import org.labkey.api.action.SimpleErrorView;
import org.labkey.api.action.SimpleViewAction;
import org.labkey.api.exp.api.ExpProtocol;
import org.labkey.api.exp.api.ExperimentService;
import org.labkey.api.exp.api.ExpData;
import org.labkey.api.view.HttpView;
import org.labkey.api.view.NotFoundException;
import org.labkey.api.view.ActionURL;
import org.labkey.api.view.NavTree;
import org.labkey.api.pipeline.PipeRoot;
import org.labkey.api.pipeline.PipelineService;
import org.labkey.api.util.NetworkDrive;
import org.labkey.api.util.PageFlowUtil;
import org.labkey.api.data.DataRegionSelection;
import org.labkey.api.data.Container;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.validation.BindException;

import java.io.File;
import java.io.FileFilter;
import java.util.*;

/**
 * User: jeckels
 * Date: Apr 13, 2009
 */
public abstract class PipelineDataCollectorRedirectAction extends SimpleViewAction<PipelineDataCollectorRedirectAction.UploadRedirectForm>
{
    /** @return filter to apply to the files in the selected directory */
    protected abstract FileFilter getFileFilter();

    /** @return URL to actually handle the upload after the file list is stuck in the session */
    protected abstract ActionURL getUploadURL(ExpProtocol protocol);

    public ModelAndView getView(UploadRedirectForm form, BindException errors) throws Exception
    {
        Container container = getViewContext().getContainer();
        // Can't trust the form's getPath() because it translates the empty string into null, and we
        // need to know if the parameter was present
        String path = getViewContext().getRequest().getParameter("path");
        List<File> files = new ArrayList<File>();
        if (path != null)
        {
            PipeRoot root = PipelineService.get().findPipelineRoot(container);
            if (root == null)
            {
                throw new NotFoundException("No pipeline root is available");
            }
            File f = root.resolvePath(path);
            if (!NetworkDrive.exists(f))
            {
                HttpView.throwNotFound("Unable to find file: " + path);
            }

            File[] selectedFiles = f.listFiles(getFileFilter());
            if (selectedFiles != null)
            {
                files.addAll(Arrays.asList(selectedFiles));
            }
        }
        else
        {
            int[] dataIds = PageFlowUtil.toInts(DataRegionSelection.getSelected(getViewContext(), true));

            for (int dataId : dataIds)
            {
                ExpData data = ExperimentService.get().getExpData(dataId);
                if (data == null || !data.getContainer().equals(container))
                {
                    throw new NotFoundException("Could not find all selected datas");
                }

                File f = data.getFile();
                if (f != null && f.isFile())
                {
                    files.add(f);
                }
            }
        }

        if (files.isEmpty())
        {
            HttpView.throwNotFound("Could not find any matching files");
        }
        files = validateFiles(errors, files);

        if (errors.getErrorCount() > 0)
        {
            return new SimpleErrorView(errors);
        }
        
        Collections.sort(files);
        List<Map<String, File>> maps = new ArrayList<Map<String, File>>();
        for (File file : files)
        {
            maps.add(Collections.singletonMap(file.getName(), file));
        }
        PipelineDataCollector.setFileCollection(getViewContext().getRequest().getSession(true), container, form.getProtocol(), maps);
        HttpView.throwRedirect(getUploadURL(form.getProtocol()));
        return null;
    }

    /**
     *
     * @param errors any fatal errors with this set of files
     * @param files the selected files
     * @return the subset of the files that should actually be loaded
     */
    protected abstract List<File> validateFiles(BindException errors, List<File> files);

    public NavTree appendNavTrail(NavTree root)
    {
        return root.addChild("Assay Upload Attempt");
    }

    public static class UploadRedirectForm
    {
        private int _protocolId;
        private String _path;

        public int getProtocolId()
        {
            return _protocolId;
        }

        public ExpProtocol getProtocol()
        {
            ExpProtocol result = ExperimentService.get().getExpProtocol(_protocolId);
            if (result == null)
            {
                HttpView.throwNotFound("Could not find protocol");
            }
            return result;
        }

        public void setProtocolId(int protocolId)
        {
            _protocolId = protocolId;
        }

        public String getPath()
        {
            return _path;
        }

        public void setPath(String path)
        {
            _path = path;
        }
    }

}
