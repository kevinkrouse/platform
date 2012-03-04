/*
 * Copyright (c) 2007-2012 LabKey Corporation
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

package org.labkey.study.designer;

import gwt.client.org.labkey.study.designer.client.model.GWTTimepoint;
import org.apache.log4j.Logger;
import org.labkey.api.data.Container;
import org.labkey.api.exp.OntologyManager;
import org.labkey.api.gwt.server.BaseRemoteService;
import org.labkey.api.reports.model.ViewCategory;
import org.labkey.api.reports.model.ViewCategoryManager;
import org.labkey.api.security.permissions.AdminPermission;
import org.labkey.api.security.permissions.UpdatePermission;
import org.labkey.api.study.DataSet;
import org.labkey.api.study.Study;
import org.labkey.api.study.StudyService;
import org.labkey.api.study.TimepointType;
import org.labkey.api.study.Visit;
import org.labkey.api.util.ExceptionUtil;
import org.labkey.api.util.UnexpectedException;
import org.labkey.api.view.UnauthorizedException;
import org.labkey.api.view.ViewContext;
import org.labkey.study.assay.AssayPublishManager;
import org.labkey.study.controllers.designer.DesignerController;
import gwt.client.org.labkey.study.designer.client.StudyDefinitionService;
import gwt.client.org.labkey.study.designer.client.model.GWTAssayDefinition;
import gwt.client.org.labkey.study.designer.client.model.GWTStudyDefinition;
import gwt.client.org.labkey.study.designer.client.model.GWTStudyDesignVersion;
import org.labkey.study.model.DataSetDefinition;
import org.labkey.study.model.StudyImpl;
import org.labkey.study.model.StudyManager;
import org.labkey.study.model.VisitImpl;
import org.labkey.study.xml.StudyDesignDocument;

import java.sql.SQLException;
import java.util.Collections;
import java.util.List;

/**
 * Created by IntelliJ IDEA.
 * User: Mark Igra
 * Date: Feb 14, 2007
 * Time: 9:21:22 PM
 */
public class StudyDefinitionServiceImpl extends BaseRemoteService implements StudyDefinitionService
{
    private static Logger _log = Logger.getLogger(StudyDefinitionServiceImpl.class);

    public StudyDefinitionServiceImpl(ViewContext context)
    {
        super(context);
    }

    public GWTStudyDesignVersion save(GWTStudyDefinition def)
    {
        if (!getContainer().hasPermission(getUser(), UpdatePermission.class))
        {
            GWTStudyDesignVersion result = new GWTStudyDesignVersion();
            result.setSaveSuccessful(false);
            result.setErrorMessage("You do not have permission to save");
            return result;
        }
        try
        {
            StudyDesignDocument design = XMLSerializer.toXML(def);
            StudyDesignVersion version = new StudyDesignVersion();
            version.setXML(design.toString());
            version.setStudyId(def.getCavdStudyId());
            version.setLabel(def.getStudyName());
            GWTStudyDesignVersion result = StudyDesignManager.get().saveStudyDesign(getUser(), getContainer(), version).toGWTVersion(_context);
            result.setSaveSuccessful(true);
            return result;
        }
        catch (SaveException se)
        {
            GWTStudyDesignVersion result = new GWTStudyDesignVersion();
            result.setSaveSuccessful(false);
            result.setErrorMessage(se.getMessage());
            return result;
        }
        catch (SQLException x)
        {
            _log.error(x);
            ExceptionUtil.logExceptionToMothership(getThreadLocalRequest(), x);
            GWTStudyDesignVersion result = new GWTStudyDesignVersion();
            result.setSaveSuccessful(false);
            result.setErrorMessage("Save failed: " + x.getMessage());
            return result;
        }

    }

    public GWTStudyDefinition getBlank()
    {
        try
        {
            GWTStudyDefinition def = DesignerController.getTemplate(getUser(), getContainer());
            //Lock the assays
            for (int i = 0; i < def.getAssays().size(); i++)
                ((GWTAssayDefinition) def.getAssays().get(i)).setLocked(true);
            def.setCavdStudyId(0);
            def.setRevision(0);
            def.setStudyName(null);

            return def;
        }
        catch (Exception e)
        {
            throw UnexpectedException.wrap(e);
        }
    }

    public GWTStudyDefinition getRevision(int studyId, int revision)
    {
        try
        {
            Container container = getContainer();
            StudyDesignVersion version;
            if (revision >= 0)
                version = StudyDesignManager.get().getStudyDesignVersion(container, studyId, revision);
            else
                version = StudyDesignManager.get().getStudyDesignVersion(container, studyId);

            GWTStudyDefinition template = getTemplate();
            GWTStudyDefinition def = XMLSerializer.fromXML(version.getXML(), template.getCavdStudyId() == studyId ? null : template);
            def.setCavdStudyId(version.getStudyId());
            def.setRevision(version.getRevision());
            StudyDesignInfo info = StudyDesignManager.get().getStudyDesign(getContainer(), studyId);
            StudyDesignManager.get().mergeStudyProperties(def, info);
            return def;
        }
        catch (Exception e)
        {
            throw UnexpectedException.wrap(e);
        }
    }

    public GWTStudyDefinition getTemplate()
    {
        try
        {
            return DesignerController.getTemplate(getUser(), getContainer());
        }
        catch (Exception e)
        {
            throw UnexpectedException.wrap(e);
        }
    }

    public GWTStudyDesignVersion[] getVersions(int studyId)
    {
        try
        {
            StudyDesignVersion[] versions = StudyDesignManager.get().getStudyDesignVersions(getContainer(), studyId);
            GWTStudyDesignVersion[] gwtVersions = new GWTStudyDesignVersion[versions.length];
            for (int i = 0; i < versions.length; i++)
                gwtVersions[i] = versions[i].toGWTVersion(_context);

            return gwtVersions;
        }
        catch (SQLException e)
        {
            throw UnexpectedException.wrap(e);
        }
    }

    public GWTStudyDefinition ensureDatasetPlaceholders(GWTStudyDefinition studyDefinition)
    {
        if (!getContainer().hasPermission(getUser(), AdminPermission.class))
            throw new UnauthorizedException("Only admins can create dataset definitions.");

        StudyImpl study = StudyManager.getInstance().getStudy(getContainer());
        if (null == study)
            throw new IllegalStateException("No study found in this folder.");

        int categoryId;
        ViewCategory category = ViewCategoryManager.getInstance().ensureViewCategory(getContainer(), getUser(), "Assays");
        categoryId = category.getRowId();

        try
        {
            for (GWTAssayDefinition assayDefinition : studyDefinition.getAssaySchedule().getAssays())
            {
                int dsId = StudyService.get().getDatasetId(getContainer(), assayDefinition.getName());
                if (dsId == -1)
                {
                    DataSetDefinition datasetDefinition = AssayPublishManager.getInstance().createAssayDataset(getUser(), study, assayDefinition.getName(),
                            null, null, false, DataSet.TYPE_PLACEHOLDER, categoryId, null);
                    if (datasetDefinition != null)
                    {
                        String domainURI = datasetDefinition.getTypeURI();
                        OntologyManager.ensureDomainDescriptor(domainURI, assayDefinition.getName(), getContainer());
                        datasetDefinition.provisionTable();
                    }
                }

            }
        }
        catch (SQLException e)
        {
            throw UnexpectedException.wrap(e);
        }

        return studyDefinition;
    }

    public GWTStudyDefinition createTimepoints(GWTStudyDefinition studyDefinition)
    {
        if (!getContainer().hasPermission(getUser(), AdminPermission.class))
            throw new UnauthorizedException("Only admins can create timepoints.");

        StudyImpl study = StudyManager.getInstance().getStudy(getContainer());
        if (null == study)
            throw new IllegalStateException("No study found in this folder.");

        if(study.getVisits(Visit.Order.DISPLAY).length > 0)
            throw new IllegalStateException("There are already timepoints in this study.");

        if (studyDefinition.getAssaySchedule().getTimepoints().size() == 0)
            return studyDefinition;

        try
        {
            //Make sure we're a date type study
            study = study.createMutable();
            study.setTimepointType(TimepointType.DATE);
            StudyManager.getInstance().updateStudy(getUser(), study);

            List<GWTTimepoint> timepoints = studyDefinition.getAssaySchedule().getTimepoints();
            Collections.sort(timepoints);
            if (timepoints.get(0).getDays() > 0)
                timepoints.add(0, new GWTTimepoint("Study Start", 0, GWTTimepoint.DAYS));

            //We try to create timepoints that make sense. A week is day-3 to day +3 unless that would overlap
            double previousDay = timepoints.get(0).getDays() - 1.0;
            for (int timepointIndex = 0; timepointIndex < timepoints.size(); timepointIndex++)
            {
                GWTTimepoint timepoint = timepoints.get(timepointIndex);
                double startDay = timepoints.get(timepointIndex).getDays();
                double endDay = startDay;
                double nextDay = timepointIndex + 1 == timepoints.size() ? Double.MAX_VALUE : timepoints.get(timepointIndex + 1).getDays();
                if (timepoint.getUnit().equals(GWTTimepoint.WEEKS))
                {
                    startDay = Math.max(previousDay + 1, startDay - 3);
                    endDay = Math.min(nextDay - 1, endDay + 3);
                }
                else if (timepoint.getUnit().equals(GWTTimepoint.MONTHS))
                {
                    startDay = Math.max(previousDay + 1, startDay - 15);
                    endDay = Math.min(nextDay - 1, endDay + 15);
                }
                VisitImpl visit = new VisitImpl(getContainer(), startDay, endDay, timepoint.toString(), Visit.Type.REQUIRED_BY_TERMINATION);
                StudyManager.getInstance().createVisit(study, getUser(), visit);
                previousDay = endDay;
            }
        }
        catch(SQLException e)
        {
            throw UnexpectedException.wrap(e);
        }

        return  studyDefinition;
    }
}
