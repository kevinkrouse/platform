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
package org.labkey.pipeline.mule;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.globus.axis.util.Util;
import org.globus.exec.client.GramJob;
import org.labkey.api.module.ModuleLoader;
import org.labkey.api.pipeline.*;
import org.labkey.api.settings.AppProps;
import org.labkey.api.util.NetworkDrive;
import org.labkey.api.util.HelpTopic;
import org.labkey.api.util.JobRunner;
import org.labkey.api.util.DateUtil;
import org.labkey.pipeline.mule.filters.TaskJmsSelectorFilter;
import org.labkey.pipeline.api.PipelineStatusFileImpl;
import org.labkey.pipeline.api.PipelineStatusManager;
import org.mule.umo.UMOEventContext;
import org.mule.umo.UMOException;
import org.mule.umo.UMODescriptor;
import org.mule.umo.endpoint.UMOEndpoint;
import org.mule.umo.lifecycle.Callable;
import org.mule.impl.RequestContext;

import javax.naming.*;
import java.io.*;
import java.security.Security;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateExpiredException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class PipelineJobRunnerGlobus implements Callable, ResumableDescriptor
{
    private static Logger _log = Logger.getLogger(PipelineJobRunnerGlobus.class);

    private static final String GLOBUS_LOCATION = "GLOBUS_LOCATION";

    static
    {
        Util.registerTransport();
        if (System.getProperty(GLOBUS_LOCATION) == null)
        {
            File webappDir = new File(ModuleLoader.getServletContext().getRealPath("/"));
            File webinfDir = new File(webappDir, "WEB-INF"); 
            System.setProperty(GLOBUS_LOCATION, webinfDir.getAbsolutePath());
        }

        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
        Security.addProvider(new BouncyCastleProvider());
    }

    public PipelineJobRunnerGlobus()
    {
        // Note: can't throw exception at config time, for missing globus
        //       client information, since it must be possible to run the web
        //       server without globus configuration.  The built-in Mule
        //       config runs this constructor with a JMS filter for task
        //       location "cluster".
    }

    public void resume(UMODescriptor descriptor)
    {
        for (UMOEndpoint endpoint : (List<UMOEndpoint>)descriptor.getInboundRouter().getEndpoints())
        {
            if (endpoint.getFilter() instanceof TaskJmsSelectorFilter)
            {
                TaskJmsSelectorFilter filter = (TaskJmsSelectorFilter) endpoint.getFilter();
                final Map<String, List<PipelineStatusFileImpl>> allLocations = new HashMap<String, List<PipelineStatusFileImpl>>();
                for (String location : filter.getLocations())
                {
                    // Grab the list of jobs to check synchronously, but don't block waiting to ping them all
                    allLocations.put(location, PipelineStatusManager.getStatusFilesForLocation(location, false));

                }
                JobRunner.getDefault().execute(new Runnable()
                {
                    public void run()
                    {
                        for (Map.Entry<String, List<PipelineStatusFileImpl>> entry : allLocations.entrySet())
                        {
                            String location = entry.getKey();
                            List<PipelineStatusFileImpl> filesToCheck = entry.getValue();

                            _log.info("Starting to check status for " + filesToCheck.size() + " jobs on Globus location '" + location + "'");
                            int count = 0;
                            for (PipelineStatusFileImpl sf : filesToCheck)
                            {
                                if (sf.getJobStore() != null && sf.isActive())
                                {
                                    PipelineJob job = null;
                                    try
                                    {
                                        job = PipelineJobService.get().getJobStore().fromXML(sf.getJobStore());

                                        GlobusJobWrapper wrapper = new GlobusJobWrapper(job, false, true);
                                        // Refresh to see what state Globus thinks the job is in. If the job is running or is finished,
                                        // the GlobusListener will be notified just like normal, so it can handle the updates or release
                                        // the associated resources
                                        wrapper.refreshStatus();
                                    }
                                    catch (Exception e)
                                    {
                                        if (job != null)
                                        {
                                            job.error("Failed to update status", e);
                                        }
                                    }
                                }
                                count++;
                                if (count % 10 == 0)
                                {
                                    _log.info("Checked status for " + count + " of " + filesToCheck.size() + " jobs on Globus location '" + location + "'");
                                }
                            }
                            _log.info("Finished checking status jobs on Globus location '" + location + "'");
                        }
                        _log.info("Finished checking status jobs for all Globus locations");
                    }
                });
            }
        }
    }

    public Object onCall(UMOEventContext eventContext) throws Exception
    {
        boolean submitted = false;
        String xmlJob = eventContext.getMessageAsString();
        PipelineJob job = PipelineJobService.get().getJobStore().fromXML(xmlJob);

        try
        {
            GlobusJobWrapper wrapper = new GlobusJobWrapper(job, true, true);
            GramJob gramJob = wrapper.getGramJob();
            PipelineJobService.GlobusClientProperties settings = wrapper.getSettings();

            String globusEndpoint = settings.getGlobusEndpoint();
            if (globusEndpoint == null || "".equals(globusEndpoint))
                throw new IllegalArgumentException("GlobusClientProperties must specify a server to run tasks on a cluster. Check configuration.");

            StringBuilder sb = new StringBuilder();
            sb.append("Submitting job to Globus location '");
            sb.append(settings.getLocation() == null ? "cluster" : settings.getLocation());
            sb.append("'");
            if (gramJob.getDescription().getQueue() != null)
            {
                sb.append(" with queue '");
                sb.append(gramJob.getDescription().getQueue());
                sb.append("'");
            }
            sb.append(": ");
            sb.append(gramJob.getDescription().getExecutable());
            for (String arg : gramJob.getDescription().getArgument())
            {
                sb.append(" ");
                sb.append(arg);
            }
            job.getLogger().info(sb.toString());

            PipeRoot pipeRoot = PipelineService.get().findPipelineRoot(job.getContainer());
            GlobusKeyPair keyPair = pipeRoot.getGlobusKeyPair();
            for (String warning : checkGlobusConfiguration(keyPair))
            {
                job.getLogger().warn(warning);
            }

            wrapper.submit();
            sb.append("Job submitted to Globus.");
            submitted = true;
        }
        finally
        {
            if (!submitted)
            {
                try
                {
                    updateStatus(job, PipelineJob.TaskStatus.error);
                }
                catch (IOException e)
                {
                    _log.error("Failed to update status after failing to submit job", e);
                }
                catch (UMOException e)
                {
                    _log.error("Failed to update status after failing to submit job", e);
                }
            }
        }
        return null;
    }

    public static List<String> checkGlobusConfiguration(GlobusKeyPair keyPair)
    {
        List<String> result = new ArrayList<String>();
        if (AppProps.getInstance().getBaseServerUrl().indexOf("//localhost") != -1)
        {
            result.add("You have not set your base server URL. Unless the Globus server is running on the same machine" +
                    " as LabKey Server, it will not be able to call back to give status updates. To fix this, go to " +
                    "Admin Console->Site Settings and enter a base server URL that your Globus server can use to " +
                    "issue HTTP/HTTPS requests to your LabKey Server.");
        }
        File homeDir = new File(System.getProperty("user.home"));
        File globusDir = new File(homeDir, ".globus");
        File certsDir = new File(globusDir, "certificates");
        FilenameFilter filter = new FilenameFilter()
        {
            public boolean accept(File dir, String name)
            {
                return name.endsWith(".0");
            }
        };
        if (!certsDir.exists() || certsDir.listFiles(filter) == null || certsDir.listFiles(filter).length == 0)
        {
            result.add("Your LabKey Server does not have the required Globus CA certificates in " + certsDir +
                    ". Please see " + new HelpTopic("configureEnterprisePipeline") +
                    " for instructions.");
        }
        if (keyPair != null)
        {
            try
            {
                for (X509Certificate x509Certificate : keyPair.getCertificates())
                {
                    try
                    {
                        x509Certificate.checkValidity();
                    }
                    catch (CertificateNotYetValidException e)
                    {
                        result.add("Certificate is not valid until " + DateUtil.formatDate(x509Certificate.getNotBefore()) + ": " + x509Certificate.getSubjectX500Principal().getName());
                    }
                    catch (CertificateExpiredException e)
                    {
                        result.add("Certificate expired " + DateUtil.formatDate(x509Certificate.getNotAfter()) + ": " + x509Certificate.getSubjectX500Principal().getName());
                    }

                }
            }
            catch (GeneralSecurityException e)
            {
                result.add("Problem getting key pair: " + e);
            }

        }

        try
        {
            InitialContext ctx = new InitialContext();
            Context envCtx = (Context) ctx.lookup("java:comp/env");
            StringBuilder message = new StringBuilder("You are missing the following JNDI object(s):");
            int originalLength = message.length();
            ensureJNDIConfig(envCtx, message, "services/NotificationConsumerService/home");
            ensureJNDIConfig(envCtx, message, "timer/ContainerTimer");
            ensureJNDIConfig(envCtx, message, "topic/ContainerTopicExpressionEngine");
            ensureJNDIConfig(envCtx, message, "query/eval/xpath");
            ensureJNDIConfig(envCtx, message, "query/ContainerQueryEngine");
            ensureJNDIConfig(envCtx, message, "topic/eval/simple");

            if (message.length() > originalLength)
            {
                message.append(". Please see ");
                message.append(new HelpTopic("configureEnterprisePipeline"));
                message.append(" for instructions.");
                result.add(message.toString());
            }
        }
        catch (NamingException e)
        {
            result.add("Unable to look up Globus objects in JNDI " + e);
            _log.error("Unable to look up Globus objects in JNDI", e);
        }

        return result;
    }

    private static void ensureJNDIConfig(Context ctx, StringBuilder errors, String name)
    {
        String[] components = name.split("/");
        try
        {
            for (int i = 0; i < components.length - 2; i++)
            {
                Object o = ctx.lookup(components[i]);
                if (!(o instanceof Context))
                {
                    errors.append(" ");
                    errors.append(name);
                    return;
                }
                ctx = (Context)o;
            }
            NamingEnumeration<NameClassPair> listing = ctx.list(components[components.length - 2]);
            while (listing.hasMoreElements())
            {
                NameClassPair classPair = listing.next();
                if (classPair.getName().equals(components[components.length - 1]))
                {
                    return;
                }
            }
        }
        catch (NamingException ignored)
        {
        }
        errors.append(" ");
        errors.append(name);
    }

    public static void updateStatus(PipelineJob job, PipelineJob.TaskStatus status) throws UMOException, IOException
    {
        assert status != PipelineJob.TaskStatus.waiting :
                "Reset cluster task status to 'waiting' is not allowed.";

        if (!status.isActive())
        {
            try
            {
                // This is a nasty hack. We want to delete the log file. One would think that Globus would be done
                // writing to the file before it gives us a callback to tell us that the job is complete. However,
                // in my testing about 50% of the time it's not quite done. We try to delete the file. Globus closes
                // the file, which ends up recreating it. Worse, it comes back with different file permissions, set
                // so that we can't read or write to it anymore, meaning that we can't delete it again or copy its
                // contents to the main job log. So, we wait a bit for it to be flushed and then try deleting it.
                // We'll have to wait and see if it's reliably done after ten seconds or not.
                job.getLogger().info("Waiting to get log files...");
                Thread.sleep(10000);
            }
            catch (InterruptedException ignored) {}

            appendAndDeleteLogFile(job, GlobusJobWrapper.OutputType.out);
            appendAndDeleteLogFile(job, GlobusJobWrapper.OutputType.err);

            // Clean up the serialized job file if Globus is done trying to run it
            File serializedFile = GlobusJobWrapper.getSerializedFile(job.getLogFile());
            if (NetworkDrive.exists(serializedFile))
            {
                job = PipelineJob.readFromFile(serializedFile);
                serializedFile.delete();
            }
        }

        job.setActiveTaskStatus(status);

        // Only re-queue the job if status is 'complete' (not 'running' or 'error').
        if (status == PipelineJob.TaskStatus.complete || status == PipelineJob.TaskStatus.error)
        {
            // And only, if this update didn't happen in the process of
            // handling an existing Mule request, in which case, Mule will
            // requeue if necessary.
            if (RequestContext.getEvent() == null)
                EPipelineQueueImpl.dispatchJob(job);
        }
    }

    private static void appendAndDeleteLogFile(PipelineJob job, GlobusJobWrapper.OutputType outputType)
    {
        File f = getOutputFile(job.getLogFile(), outputType);
        if (NetworkDrive.exists(f))
        {
            if (f.length() > 0)
            {
                job.getLogger().info("Reading log file " + f + ", which is now of size " + f.length());
                FileInputStream fIn = null;
                try
                {
                    fIn = new FileInputStream(f);
                    BufferedReader reader = new BufferedReader(new InputStreamReader(fIn));
                    String line;
                    StringBuilder sb = new StringBuilder();
                    while ((line = reader.readLine()) != null)
                    {
                        sb.append(line);
                        sb.append("\n");
                    }
                    job.getLogger().info("Content of std" + outputType + ":\n" + sb.toString());
                }
                catch (IOException e)
                {
                    job.getLogger().warn("Failed to append contents from log file " + f, e);
                }
                finally
                {
                    if (fIn != null) { try { fIn.close(); } catch (IOException ignored) {} }
                }
            }

            job.getLogger().info("Deleting log file " + f + ", which is now of size " + f.length());
            f.delete();
        }
    }

    public static File getOutputFile(File statusFile, GlobusJobWrapper.OutputType outputType)
    {
        if (statusFile == null)
        {
            return null;
        }

        String name = statusFile.getName();
        int index = name.indexOf('.');
        if (index != -1)
        {
            name = name.substring(0, index);
        }
        return new File(statusFile.getParentFile(), name + ".cluster." + outputType);
    }
}