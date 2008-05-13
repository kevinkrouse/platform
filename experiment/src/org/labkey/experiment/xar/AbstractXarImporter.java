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

package org.labkey.experiment.xar;

import org.apache.log4j.Logger;
import org.labkey.api.exp.*;
import org.labkey.api.exp.api.ExperimentService;
import org.labkey.api.exp.property.Domain;
import org.labkey.api.exp.property.DomainProperty;
import org.labkey.api.data.Container;
import org.labkey.api.security.User;
import org.labkey.experiment.api.property.DomainImpl;
import org.labkey.experiment.api.ExperimentServiceImpl;
import org.fhcrc.cpas.exp.xml.ExperimentArchiveType;
import org.fhcrc.cpas.exp.xml.DomainDescriptorType;
import org.fhcrc.cpas.exp.xml.PropertyDescriptorType;

import java.util.Map;
import java.util.HashMap;
import java.sql.SQLException;

/**
 * User: jeckels
 * Date: Jul 5, 2007
 */
public abstract class AbstractXarImporter
{
    protected final Logger _log;
    protected final XarSource _xarSource;
    protected final Container _container;
    protected ExperimentArchiveType _experimentArchive;
    protected final User _user;

    protected Map<String, Domain> _loadedDomains = new HashMap<String, Domain>();

    public AbstractXarImporter(XarSource source, Container targetContainer, Logger logger, User user)
    {
        _xarSource = source;
        _container = targetContainer;
        _log = logger;
        _user = user;
    }

    protected void checkDataCpasType(String declaredType)
    {
        if (declaredType != null && !"Data".equals(declaredType))
        {
            _log.warn("Unrecognized CpasType '" + declaredType + "' loaded for Data object.");
        }
    }

    protected void checkMaterialCpasType(String declaredType) throws SQLException, XarFormatException
    {
        if (declaredType != null && !"Material".equals(declaredType))
        {
            if (ExperimentService.get().getSampleSet(declaredType) != null)
            {
                return;
            }

            _log.warn("Unrecognized CpasType '" + declaredType + "' loaded for Material object.");
        }
    }

    protected void checkProtocolApplicationCpasType(String cpasType, Logger logger)
    {
        if (cpasType != null && !"ProtocolApplication".equals(cpasType) && !"ExperimentRun".equals(cpasType) && !"ExperimentRunOutput".equals(cpasType))
        {
            logger.warn("Unrecognized CpasType '" + cpasType + "' loaded for ProtocolApplication object.");
        }
    }
}
