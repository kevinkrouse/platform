/*
 * Copyright (c) 2011 LabKey Corporation
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

package org.labkey.api.data;

import org.labkey.api.module.Module;
import org.labkey.api.module.ModuleContext;
import org.labkey.api.module.ModuleLoader;
import org.labkey.api.util.Filter;
import org.labkey.api.cache.BlockingCache;
import org.labkey.api.cache.CacheLoader;
import org.labkey.api.cache.CacheManager;
import org.labkey.api.settings.AppProps;

/*
* User: adam
* Date: Mar 20, 2011
* Time: 2:53:51 PM
*/

// Every scope has its own cache of DbSchemas... TODO: Switch to single cache for all scopes?
public class DbSchemaCache
{
    private final DbScope _scope;
    private final BlockingCache<String, DbSchema> _blockingCache = new DbSchemaBlockingCache();  // TODO: BlockingStringKeyCache?
    private final IncompleteSchemaFilter _incompleteFilter = new IncompleteSchemaFilter();

    public DbSchemaCache(DbScope scope)
    {
        _scope = scope;
    }

    DbSchema get(String schemaName)
    {
        return _blockingCache.get(schemaName);
    }

    void remove(String schemaName)
    {
        _blockingCache.remove(schemaName);
    }

    void removeIncomplete()
    {
        _blockingCache.removeUsingFilter(_incompleteFilter);
    }

    
    private class IncompleteSchemaFilter implements Filter<String>
    {
        @Override
        public boolean accept(String schemaName)
        {
            Module module = ModuleLoader.getInstance().getModuleForSchemaName(schemaName);

            // We only care about schemas associated with a module (not external schemas)
            if (null != module)
            {
                ModuleContext context = ModuleLoader.getInstance().getModuleContext(module);

                if (!context.isInstallComplete())
                    return true;
            }

            return false;
        }
    }


    private class DbSchemaLoader implements CacheLoader<String, DbSchema>
    {
        @Override
        public DbSchema load(String schemaName, Object argument)
        {
            try
            {
                return _scope.loadSchema(schemaName);
            }
            catch (Exception e)
            {
                throw new RuntimeException(e);  // Changed from "return null" to "throw runtimeexception" so admin is made aware of the cause of the problem
            }
        }
    }


    private class DbSchemaBlockingCache extends BlockingCache<String, DbSchema>
    {
        public DbSchemaBlockingCache()
        {
            // Add scope name?
            super(CacheManager.getStringKeyCache(10000, CacheManager.YEAR, "DbSchemas"), new DbSchemaLoader());
        }

        @Override
        protected boolean isValid(Wrapper<DbSchema> w, String key, Object argument, CacheLoader loader)
        {
            boolean isValid = super.isValid(w, key, argument, loader);

            if (isValid)
            {
                DbSchema schema = w.getValue();

                if (AppProps.getInstance().isDevMode() &&
                        // TODO: Remove isLabKeyScope() hack that works around DbSchema.isStale() assert
                        schema.getScope().isLabKeyScope() && schema.isStale())
                {
                    isValid = false;
                }
            }

            return isValid;
        }
    }
}
