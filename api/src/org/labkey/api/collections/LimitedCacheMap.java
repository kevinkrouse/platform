/*
 * Copyright (c) 2006-2010 LabKey Corporation
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

package org.labkey.api.collections;

import java.util.Map;

/**
 * User: adam
 * Date: May 19, 2006
 * Time: 6:11:59 AM
 */
public class LimitedCacheMap<K, V> extends CacheMap<K, V>
{
    private final int _maxSize;

    public LimitedCacheMap(int initialSize, int maxSize, String debugName)
    {
        super(initialSize, debugName);
        _maxSize = maxSize;
    }

    protected boolean removeOldestEntry(Map.Entry entry)
    {
        return (size() >= _maxSize);
    }

    @Override
    protected Long getLimit()
    {
        return new Long(_maxSize);
    }
}

