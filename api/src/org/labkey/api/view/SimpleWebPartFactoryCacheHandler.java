/*
 * Copyright (c) 2013-2015 LabKey Corporation
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
package org.labkey.api.view;

import org.jetbrains.annotations.Nullable;
import org.labkey.api.files.FileSystemDirectoryListener;
import org.labkey.api.module.Module;
import org.labkey.api.module.ModuleResourceCacheHandler2;
import org.labkey.api.module.SimpleWebPartFactory;
import org.labkey.api.resource.Resource;

import java.nio.file.Path;
import java.util.Collection;
import java.util.Collections;
import java.util.stream.Collectors;

/**
 * Creates and caches the file-based web parts defined by modules. File changes result in dynamic reloading and re-initialization of webpart-related maps.
 * User: adam
 * Date: 12/29/13
 * Time: 12:38 PM
 */
public class SimpleWebPartFactoryCacheHandler implements ModuleResourceCacheHandler2<Collection<SimpleWebPartFactory>>
{
    @Override
    public Collection<SimpleWebPartFactory> load(@Nullable Resource dir, Module module)
    {
        if (null == dir)
            return Collections.emptyList();

        Collection<SimpleWebPartFactory> webPartFactories = dir.list().stream()
            .filter(resource -> resource.isFile() && SimpleWebPartFactory.isWebPartFile(resource.getName()))
            .map(resource -> new SimpleWebPartFactory(module, resource))
            .collect(Collectors.toList());

        return Collections.unmodifiableCollection(webPartFactories);
    }

    @Nullable
    @Override
    public FileSystemDirectoryListener createChainedDirectoryListener(final Module module)
    {
        return new FileSystemDirectoryListener()
        {
            @Override
            public void entryCreated(Path directory, Path entry)
            {
                update();
            }

            @Override
            public void entryDeleted(Path directory, Path entry)
            {
                update();
            }

            @Override
            public void entryModified(Path directory, Path entry)
            {
                update();
            }

            @Override
            public void overflow()
            {
                update();
            }

            private void update()
            {
                Portal.clearWebPartFactories(module);
                Portal.clearMaps();
            }
        };
    }
}
