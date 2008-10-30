/*
 * Copyright (c) 2005-2008 Fred Hutchinson Cancer Research Center
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
package org.labkey.api.module;

import junit.framework.TestCase;
import org.labkey.api.admin.AdminUrls;
import org.labkey.api.data.Container;
import org.labkey.api.data.DbSchema;
import org.labkey.api.data.FileSqlScriptProvider;
import org.labkey.api.data.SqlScriptRunner;
import org.labkey.api.data.SqlScriptRunner.SqlScript;
import org.labkey.api.data.SqlScriptRunner.SqlScriptProvider;
import org.labkey.api.security.User;
import org.labkey.api.settings.AppProps;
import org.labkey.api.util.ExceptionUtil;
import org.labkey.api.util.PageFlowUtil;
import org.labkey.api.view.*;
import org.labkey.common.util.Pair;
import org.springframework.web.servlet.mvc.Controller;

import javax.servlet.ServletContext;
import java.io.*;
import java.sql.SQLException;
import java.util.*;

/**
 * This handles modules that are implemented using Beehive controllers
 *
 * User: migra
 * Date: Jul 14, 2005
 * Time: 11:42:09 AM
 */
public abstract class DefaultModule implements Module
{
    public static final String CORE_MODULE_NAME = "Core";
    private static final Set<Class> INSTANTIATED_MODULES = new HashSet<Class>();
    private static final Object SCHEMA_UPDATE_LOCK = new Object();

    private String _name;
    private double _version;
    private boolean _shouldRunScripts;
    private final Map<String, Class> _pageFlowNameToClass = new LinkedHashMap<String, Class>();
    private final Map<Class, String> _pageFlowClassToName = new HashMap<Class, String>();
    private final WebPartFactory[] _webParts;

    private boolean _beforeSchemaUpdateComplete = false;
    private UpdateState _afterSchemaUpdateState = UpdateState.NotStarted;
    private enum UpdateState { NotStarted, InProgress, Complete }

    private ModuleMetaData _metaData;
    private boolean _loadFromSource;
    private String _sourcePath;

    private enum SchemaUpdateType
    {
        Before
        {
            List<SqlScript> getScripts(SqlScriptProvider provider) throws SqlScriptRunner.SqlScriptException
            {
                return provider.getDropScripts();
            }
        },

        After
        {
            List<SqlScript> getScripts(SqlScriptProvider provider) throws SqlScriptRunner.SqlScriptException
            {
                return provider.getCreateScripts();
            }
        };

        abstract List<SqlScript> getScripts(SqlScriptProvider provider) throws SqlScriptRunner.SqlScriptException;
    }

    protected DefaultModule(String name, double version, String resourcePath, boolean shouldRunScripts, WebPartFactory... webParts)
    {
        _name = name;
        _version = version;
        _shouldRunScripts = shouldRunScripts;
        _webParts = webParts;
    }

    protected DefaultModule()
    {
        _webParts = null;
    }

    final public void initialize()
    {
        synchronized (INSTANTIATED_MODULES)
        {
            if (INSTANTIATED_MODULES.contains(getClass()))
                throw new IllegalStateException("An instance of " + getClass() + " has already been created. Modules should be singletons");
            else
                INSTANTIATED_MODULES.add(getClass());
        }

        ModuleLoader.getInstance().registerResourcePrefix(getResourcePath(), this);
        ModuleLoader.getInstance().registerResourcePrefix(getResourcePath(), new ResourceFinder(this));
        for (WebPartFactory part : _webParts)
            part.setModule(this);

        init();
    }

    protected abstract void init();

    protected String getResourcePath()
    {
        return "/" + getClass().getPackage().getName().replaceAll("\\.", "/");
    }

    protected void addController(String primaryName, Class cl, String... aliases)
    {
        if (!ViewController.class.isAssignableFrom(cl) && !Controller.class.isAssignableFrom(cl))
            throw new IllegalArgumentException(cl.toString());

        // Map controller class to canonical name
        addPageFlowClass(cl, primaryName);

        // Map all names to controller class
        addPageFlowName(primaryName, cl);
        for (String alias : aliases)
            addPageFlowName(alias, cl);
    }


    // Map controller class to canonical name
    private void addPageFlowClass(Class controllerClass, String primaryName)
    {
        assert !_pageFlowNameToClass.values().contains(controllerClass) : "Controller class '" + controllerClass + "' is already registered";

        _pageFlowClassToName.put(controllerClass, primaryName);
    }


    // Map all names to controller class
    private void addPageFlowName(String pageFlowName, Class controllerClass)
    {
        assert null == _pageFlowNameToClass.get(pageFlowName) : "Page flow name '" + pageFlowName + "' is already registered";

        _pageFlowNameToClass.put(pageFlowName, controllerClass);
    }


    public String getName()
    {
        return _name;
    }


    public String getTabName(ViewContext context)
    {
        return getName();
    }


    public double getVersion()
    {
        return _version;
    }


    public String getFormattedVersion()
    {
        return ModuleContext.formatVersion(getVersion());
    }


    public boolean hasScripts()
    {
        return _shouldRunScripts;
    }


    public void bootstrap()
    {
        //By default do nothing...
    }

    public void beforeUpdate()
    {
        ModuleContext moduleContext = ModuleLoader.getInstance().getModuleContext(this);

        if (0.0 != moduleContext.getInstalledVersion())
            runScripts(SchemaUpdateType.Before);
    }

    public void beforeSchemaUpdate(ModuleContext moduleContext, ViewContext viewContext)
    {
    }

    /**
     * Upgrade this module to the latest version.
     *
     * If this module has scripts to run, redirect to the SqlScriptController.  The status page will eventually
     * redirect back to the moduleUpgrade action which will call this method again and cause afterSchemaUpdate()
     * to complete.
     *
     * This will get called multiple times before scripts are done running, e.g., if the admin user attempts to
     * hit the home page during upgrade.  We need to synchronize afterSchemaUpdate here.  SqlScriptRunner will
     * run and synchronize the actual scripts.
     */
    public ActionURL versionUpdate(final ModuleContext moduleContext, final ViewContext viewContext)
    {
        synchronized(SCHEMA_UPDATE_LOCK)
        {
            if (!_beforeSchemaUpdateComplete)
                beforeSchemaUpdate(moduleContext, viewContext);
            _beforeSchemaUpdateComplete = true;
        }

        if (_shouldRunScripts)
        {
            Map m = moduleContext.getProperties();
            Boolean scriptsRun = (Boolean) m.get(SqlScriptRunner.SCRIPTS_RUN_KEY);

            if (null == scriptsRun)
            {
                ActionURL returnURL = moduleContext.getContinueUpgradeURL(getVersion());
                return PageFlowUtil.urlProvider(SqlScriptRunner.SqlScriptUrls.class).getDefaultURL(returnURL, getName(), moduleContext.getInstalledVersion(), getVersion(), moduleContext.getExpress());
            }
        }

        synchronized(SCHEMA_UPDATE_LOCK)
        {
            if (UpdateState.Complete != _afterSchemaUpdateState)
            {
                if (UpdateState.NotStarted == _afterSchemaUpdateState)
                {
                    _afterSchemaUpdateState = UpdateState.InProgress;
                    Thread afterSchemaUpdateThread = new Thread()
                    {
                        public void run()
                        {
                            try
                            {
                                afterSchemaUpdate(moduleContext, viewContext);
                            }
                            catch (Exception e)
                            {
                                ExceptionUtil.logExceptionToMothership(viewContext.getRequest(), e);
                            }
                            finally
                            {
                                _afterSchemaUpdateState = UpdateState.Complete;
                            }
                        }
                    };
                    afterSchemaUpdateThread.start();
                }
                return PageFlowUtil.urlProvider(AdminUrls.class).getModuleStatusURL();
            }
        }

        return moduleContext.getUpgradeCompleteURL(getVersion());
    }

    public void afterUpdate()
    {
        runScripts(SchemaUpdateType.After);
    }

    public void afterSchemaUpdate(ModuleContext moduleContext, ViewContext viewContext)
    {
    }

    private void runScripts(SchemaUpdateType type)
    {
        try
        {
            if (hasScripts())
            {
                SqlScriptProvider provider = new FileSqlScriptProvider(this);
                List<SqlScript> scripts = type.getScripts(provider);

                if (!scripts.isEmpty())
                {
                    SqlScriptRunner.runScripts(null, scripts, provider, true);
                    SqlScriptRunner.waitForScriptsToFinish();
                    DbSchema.invalidateSchemas();
                }
            }
        }
        catch (Exception e)
        {
            throw new RuntimeException("Error running scripts in module " + getName(), e);
        }
    }


    /**
     * Start the module. Default implementation does nothing except setModuleState(Running).
     * Overrides must call super.startup(moduleContext) to set module state correctly. 
     */
    public void startup(ModuleContext moduleContext)
    {
        moduleContext.setModuleState(ModuleLoader.ModuleState.Running);
    }

    public void deleteContainerData(Container container)
    {
        //TODO: If module has standard table structure should be able to do this in base class using DbSchema
    }

    public WebPartFactory[] getModuleWebParts()
    {
        return _webParts;
    }


    public void destroy()
    {
    }


    public Collection<String> getSummary(Container c)
    {
        return Collections.emptyList();
    }


    public final Map<String, Class> getPageFlowNameToClass()
    {
        return _pageFlowNameToClass;
    }


    public final Map<Class, String> getPageFlowClassToName()
    {
        return _pageFlowClassToName;
    }

    public ActionURL getTabURL(Container c, User user)
    {
        return new ActionURL(getPageFlowNameToClass().keySet().iterator().next(), "begin", c == null ? null : c.getPath());
    }

    public TabDisplayMode getTabDisplayMode()
    {
        return Module.TabDisplayMode.DISPLAY_USER_PREFERENCE;
    }

    protected void addWebPart(String name, Container c, String location) throws SQLException
    {
        addWebPart(name, c, location, null);
    }

    protected void addWebPart(String name, Container c, String location, Map<String, String> properties)
            throws SQLException
    {
        boolean foundPart = false;
        for (Portal.WebPart part : Portal.getParts(c.getId()))
        {
            if (name.equals(part.getName()))
            {
                foundPart = true;
                break;
            }
        }
        if (!foundPart)
        {
            WebPartFactory desc = Portal.getPortalPart(name);
            if (desc != null)
            {
                Portal.addPart(c, desc, location, properties);
            }
        }
    }

    public Set<Class<? extends TestCase>> getJUnitTests()
    {
        return Collections.emptySet();
    }

    public Set<DbSchema> getSchemasToTest()
    {
        return Collections.emptySet();
    }

    public Set<String> getSchemaNames()
    {
        return Collections.emptySet();
    }

    public void setMetaData(ModuleMetaData metaData)
    {
        _metaData = metaData;
        _loadFromSource = false;
        _sourcePath = _metaData.getSourcePath();

        if (AppProps.getInstance().isDevMode() && _sourcePath != null)
        {
            File f = new File(_sourcePath);
            if (f.exists())
                _loadFromSource = true;
        }
    }

    public ModuleMetaData getMetaData()
    {
        return _metaData;
    }

    public String getSourcePath()
    {
        return _sourcePath;
    }

    public List<String> getAttributions()
    {
        return Collections.emptyList();
    }

    public InputStream getResourceStreamFromWebapp(ServletContext ctx, String path) throws FileNotFoundException
    {
        if (_loadFromSource)
        {
            File f = new File(_sourcePath, "/webapp" + path);
            return new FileInputStream(f);
        }
        else
            return ctx.getResourceAsStream(path);
    }


    // In dev mode, check the file timestamp against the previous timestamp.  If they match, return null, otherwise return the stream & new timestamp
    // In production mode, always load and return the stream
    public Pair<InputStream, Long> getResourceStreamIfChanged(String path, long tsPrevious) throws FileNotFoundException
    {
        if (_loadFromSource)
        {
            File f = new File(_sourcePath, "/src" + path);
            long ts = f.lastModified();
            if (tsPrevious == ts)
                return null;
            return new Pair<InputStream, Long>(new FileInputStream(f), ts);
        }
        else
            return new Pair<InputStream, Long>(this.getClass().getResourceAsStream(path), -1L);
    }

    public InputStream getResourceStream(String path) throws FileNotFoundException
    {
        if (_loadFromSource)
        {
            File f = new File(_sourcePath, "/src" + path);
            return new FileInputStream(f);
        }
        else
            return this.getClass().getResourceAsStream(path);
    }


    // Returns NULL if path does not exist.  Returns empty set if path exists but has no files.
    public Set<String> getManifest(String path, String filename)
    {
        Set<String> fileNames = null;

        if (_loadFromSource)
        {
            File dir = new File(_sourcePath, "/src" + path);

            if (dir.exists())
            {
                fileNames = new HashSet<String>();

                for (File file : dir.listFiles())
                    fileNames.add(file.getName());
            }
        }
        else
        {
            InputStream s = this.getClass().getResourceAsStream(path + "/" + filename);

            try
            {
                fileNames = new HashSet<String>(PageFlowUtil.getStreamContentsAsList(s));
            }
            catch (IOException e)
            {
                throw new RuntimeException(e);
            }
        }

        return fileNames;
    }


    @Override
    public String toString()
    {
        return getName() + " " + getVersion() + " " + super.toString();
    }


    // Called after every script runs.  Does nothing by default, but modules can override if they must execute code
    // after a specific script is executed.  For example, if some tranformation of data, that can only be performed
    // in code, must be done before subsequent scripts are run.  Overriding this method is a last resort; make every
    // effort to do the upgrade/transformation in a SQL script because the code you write and call MUST continue to
    // work against the old schema for the rest of time (it should be self-contained).  Also, future script
    // consolidations could easily break your code, since they may invalidate version checks.
    public void afterScriptRuns(SqlScript script)
    {
    }
}
