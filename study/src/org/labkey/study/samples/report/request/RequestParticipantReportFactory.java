package org.labkey.study.samples.report.request;

import org.labkey.study.samples.report.SpecimenVisitReport;
import org.labkey.study.controllers.samples.SpecimenController;
import org.labkey.study.SampleManager;
import org.labkey.study.model.StudyManager;
import org.labkey.study.model.CohortImpl;
import org.labkey.study.model.VisitImpl;
import org.labkey.api.data.SimpleFilter;
import org.labkey.api.data.RuntimeSQLException;
import org.labkey.api.study.Study;
import org.labkey.api.study.Visit;
import org.labkey.api.study.StudyService;
import org.labkey.api.util.Pair;

import java.util.*;
import java.sql.SQLException;

/**
 * Copyright (c) 2008-2010 LabKey Corporation
 * <p/>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p/>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p/>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * <p/>
 * User: brittp
 * Created: Feb 5, 2008 2:03:52 PM
 */
public class RequestParticipantReportFactory extends BaseRequestReportFactory
{
    private String _participantId;

    public String getParticipantId()
    {
        return _participantId;
    }

    public void setParticipantId(String participantId)
    {
        _participantId = participantId;
    }

    public boolean allowsCohortFilter()
    {
        return false;
    }

    public boolean allowsAvailabilityFilter()
    {
        return false;
    }

    public boolean allowsParticipantAggregegates()
    {
        return false;
    }

    public List<Pair<String, String>> getAdditionalFormInputHtml()
    {
        List<Pair<String, String>> inputs = new ArrayList<Pair<String, String>>();
        inputs.addAll(super.getAdditionalFormInputHtml());
        inputs.add(getParticipantPicker("participantId", _participantId));
        return inputs;
    }

    protected List<? extends SpecimenVisitReport> createReports()
    {
        String[] participantIds;
        if (_participantId != null && _participantId.trim().length() > 0)
            participantIds = new String[] { _participantId };
        else
        {
            Study study = StudyManager.getInstance().getStudy(getContainer());
            participantIds = StudyManager.getInstance().getParticipantIds(study);
            if (participantIds == null)
                return Collections.<SpecimenVisitReport>emptyList();
        }

        List<SpecimenVisitReport> reports = new ArrayList<SpecimenVisitReport>();
        Map<Integer, VisitImpl[]> visitListCache = new HashMap<Integer, VisitImpl[]>(); // cohort rowId -> visit
        boolean showCohorts = StudyManager.getInstance().showCohorts(getContainer(), getUser());
        VisitImpl[] allVisits = null;
        Study study = StudyManager.getInstance().getStudy(getContainer());
        for (String participantId : participantIds)
        {
            SimpleFilter filter = new SimpleFilter(StudyService.get().getSubjectColumnName(getContainer()), participantId);
            addBaseFilters(filter);
            try
            {
                VisitImpl[] visits = null;
                if (showCohorts)
                {
                    CohortImpl cohort = StudyManager.getInstance().getCurrentCohortForParticipant(getContainer(), getUser(), participantId);
                    if (cohort != null)
                    {
                        visits = visitListCache.get(cohort.getRowId());
                        if (visits == null)
                        {
                            visits = SampleManager.getInstance().getVisitsWithSpecimens(getContainer(), getUser(), cohort);
                            visitListCache.put(cohort.getRowId(), visits);
                        }
                    }
                }

                if (visits == null)
                {
                    if (allVisits == null)
                        allVisits = StudyManager.getInstance().getVisits(study, Visit.Order.DISPLAY);
                    visits = allVisits;
                }
                reports.add(new RequestParticipantReport(participantId, visits, filter, this));
            }
            catch (SQLException e)
            {
                throw new RuntimeSQLException(e);
            }
        }
        return reports;
    }

    public String getLabel()
    {
        return "Requests by " + StudyService.get().getSubjectNounSingular(getContainer());
    }

    public Class<? extends SpecimenController.SpecimenVisitReportAction> getAction()
    {
        return SpecimenController.RequestParticipantReportAction.class;
    }
}
