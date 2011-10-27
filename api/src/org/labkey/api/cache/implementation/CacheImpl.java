/*
 * Copyright (c) 2010 LabKey Corporation
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
package org.labkey.api.cache.implementation;

import org.apache.log4j.Logger;
import org.jetbrains.annotations.Nullable;
import org.labkey.api.cache.BasicCache;
import org.labkey.api.cache.CacheLoader;
import org.labkey.api.util.Filter;

/**
 *  Synchronized BasicCache implemented using TTLCacheMap
 */
class CacheImpl<K, V> implements BasicCache<K, V>
{
    private static final Logger _log = Logger.getLogger(CacheImpl.class);

    private final TTLCacheMap<K, Object> _cache;
    private static final Object _nullMarker = BasicCache.NULL_MARKER;

    public CacheImpl(int limit, long defaultTimeToLive)
    {
        _cache = new TTLCacheMap<K, Object>(limit, defaultTimeToLive, null);   // TODO: remove last param?
    }


    @Override
    public synchronized void put(K key, V value)
    {
        _logDebug("Cache.put(" + key + ")");
        _cache.put(key, value);
    }


    @Override
    public synchronized void put(K key, V value, long msToLive)
    {
        _logDebug("Cache.put(" + key + ")");
        _cache.put(key, value, msToLive);
    }


    @Override
    public synchronized V get(K key)
    {
        Object v = _cache.get(key);
        _logDebug("Cache.get(" + key + ") " + (null == v ? "not found" : "found"));
        return v==_nullMarker ? null : (V)v;
    }


    @Override
    public V get(K key, @Nullable Object arg, CacheLoader<K, V> loader)
    {
        Object v = _cache.get(key);
        _logDebug("Cache.get(" + key + ") " + (null == v ? "not found" : "found"));
        if (null == v)
        {
            v = loader.load(key, arg);
            _logDebug("Cache.put(" + key + ")");
            _cache.put(key, null==v ? _nullMarker : v);
        }
        return v==_nullMarker ? null : (V)v;
    }


    @Override
    public synchronized void remove(K key)
    {
        _logDebug("Cache.remove(" + key + ")");
        _cache.remove(key);
    }


    @Override
    public synchronized int removeUsingFilter(Filter<K> filter)
    {
        _logDebug("Cache.removeUsingFilter");
        return _cache.removeUsingFilter(filter);
    }


    @Override
    public synchronized void clear()
    {
        _cache.clear();
    }


    @Override
    public int getLimit()
    {
        return _cache.getLimit();
    }

    @Override
    public int size()
    {
        return _cache.size();
    }

    @Override
    public long getDefaultExpires()
    {
        return _cache.getDefaultExpires();
    }

    @Override
    public CacheType getCacheType()
    {
        return CacheType.DeterministicLRU;
    }

    @Override
    public void close()
    {
    }

    private void _logDebug(String msg)
    {
        _log.debug(msg);
    }
}
