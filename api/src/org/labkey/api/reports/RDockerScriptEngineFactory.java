/*
 * Copyright (c) 2012-2017 LabKey Corporation
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
package org.labkey.api.reports;

import org.labkey.api.rstudio.RStudioService;
import org.labkey.api.settings.AppProps;

import javax.script.ScriptEngine;

public class RDockerScriptEngineFactory extends ExternalScriptEngineFactory
{
    public RDockerScriptEngineFactory(ExternalScriptEngineDefinition def)
    {
        super(def);
    }

    public synchronized ScriptEngine getScriptEngine()
    {
        RStudioService rs = RStudioService.get();
        if (null != rs && rs.isConfigured() && AppProps.getInstance().isExperimentalFeatureEnabled(RStudioService.R_DOCKER_SANDBOX))
            return new RDockerScriptEngine(_def, rs, rs.getMount() + "/R_Sandbox");
        else return null;
    }
}
