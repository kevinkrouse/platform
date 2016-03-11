/*
 * Copyright (c) 2006-2015 LabKey Corporation
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

package org.labkey.api.settings;

import org.labkey.api.data.Container;
import org.labkey.api.util.ExceptionReportingLevel;
import org.labkey.api.util.UsageReportingLevel;

import java.net.URISyntaxException;

/**
 * A mutable version of {@link AppProps}.
 * User: jeckels
 * Date: Dec 6, 2006
 */
public class WriteableAppProps extends AppPropsImpl
{
    public WriteableAppProps(Container c)
    {
        super();
        makeWriteable(c);
    }

    /** Override to make public */
    @Override
    public void save()
    {
        super.save();
    }

    public void setAdminOnlyMessage(String adminOnlyMessage)
    {
        storeStringValue(ADMIN_ONLY_MESSAGE, adminOnlyMessage);
    }

    public void setRibbonMessageHtml(String messageHtml)
    {
        storeStringValue(RIBBON_MESSAGE, messageHtml);
    }

    public void setShowRibbonMessage(boolean show)
    {
        storeBooleanValue(SHOW_RIBBON_MESSAGE, show);
    }

    public void setSSLPort(int sslPort)
    {
        storeIntValue(SSL_PORT, sslPort);
    }

    public void setMemoryUsageDumpInterval(int memoryUsageDumpInterval)
    {
        storeIntValue(MEMORY_USAGE_DUMP_INTERVAL, memoryUsageDumpInterval);
    }

    public void setMaxBLOBSize(int maxBLOBSize)
    {
        storeIntValue(MAX_BLOB_SIZE, maxBLOBSize);
    }

    public void setSelfReportExceptions(boolean selfReportExceptions)
    {
        storeBooleanValue(SELF_REPORT_EXCEPTIONS, selfReportExceptions);
    }

    public void setExt3Required(boolean ext3Required)
    {
        storeBooleanValue(EXT3_REQUIRED, ext3Required);
    }

    public void setExt3APIRequired(boolean ext3APIRequired)
    {
        storeBooleanValue(EXT3API_REQUIRED, ext3APIRequired);
    }

    public void setBLASTServerBaseURL(String blastServerBaseURL)
    {
        storeStringValue(BLAST_SERVER_BASE_URL_PROP, blastServerBaseURL);
    }

    public void setExceptionReportingLevel(ExceptionReportingLevel level)
    {
        storeStringValue(EXCEPTION_REPORTING_LEVEL, level.toString());
    }

    public void setUsageReportingLevel(UsageReportingLevel level)
    {
        storeStringValue(USAGE_REPORTING_LEVEL, level.toString());
    }

    public void setDefaultDomain(String defaultDomain)
    {
        storeStringValue(DEFAULT_DOMAIN_PROP, defaultDomain);
    }

    public void setDefaultLsidAuthority(String defaultLsidAuthority)
    {
        if (defaultLsidAuthority != null && defaultLsidAuthority.contains(":"))
        {
            throw new IllegalArgumentException("Default LSID authority may not contain ':'");
        }
        storeStringValue(DEFAULT_LSID_AUTHORITY_PROP, defaultLsidAuthority);
    }

    public void setBaseServerUrl(String baseServerUrl) throws URISyntaxException
    {
        validateBaseServerUrl(baseServerUrl);

        storeStringValue(BASE_SERVER_URL_PROP, baseServerUrl);
    }

    public void setPipelineToolsDir(String toolsDir)
    {
        storeStringValue(PIPELINE_TOOLS_DIR_PROP, toolsDir);
    }

    public void setSSLRequired(boolean sslRequired)
    {
        storeBooleanValue(SSL_REQUIRED, sslRequired);
    }

    public void setUserRequestedAdminOnlyMode(boolean adminOnlyMode)
    {
        storeBooleanValue(USER_REQUESTED_ADMIN_ONLY_MODE, adminOnlyMode);
    }

    public void setNetworkDriveLetter(String letter)
    {
        storeStringValue(NETWORK_DRIVE_LETTER, letter);
    }

    public void setNetworkDrivePath(String path)
    {
        storeStringValue(NETWORK_DRIVE_PATH, path);
    }

    public void setNetworkDriveUser(String user)
    {
        storeStringValue(NETWORK_DRIVE_USER, user);
    }

    public void setNetworkDrivePassword(String password)
    {
        storeStringValue(NETWORK_DRIVE_PASSWORD, password);
    }

    public void setMailRecorderEnabled(boolean enabled)
    {
        storeBooleanValue(MAIL_RECORDER_ENABLED, enabled);        
    }

    public void setFileSystemRoot(String root)
    {
        storeStringValue(WEB_ROOT, root);
    }

    public void setAdministratorContactEmail(String email)
    {
        storeStringValue(ADMINISTRATOR_CONTACT_EMAIL, email);
    }

    private void incrementLookAndFeelRevision()
    {
        storeIntValue(LOOK_AND_FEEL_REVISION, getLookAndFeelRevision() + 1);
    }

    public static void incrementLookAndFeelRevisionAndSave()
    {
        WriteableAppProps app = AppProps.getWriteableInstance();
        app.incrementLookAndFeelRevision();
        app.save();
    }

    public void setExperimentalFeatureEnabled(String feature, boolean enabled)
    {
        storeBooleanValue(EXPERIMENTAL_FEATURE_PREFIX + feature, enabled);
    }

    public void setUseContainerRelativeURL(boolean b)
    {
        storeBooleanValue(USE_CONTAINER_RELATIVE_URL, b);
    }

    public void setShowSessionKeys(boolean b)
    {
        storeBooleanValue(SHOW_SESSION_KEYS, b);
    }
}
