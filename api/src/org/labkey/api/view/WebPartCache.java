package org.labkey.api.view;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.labkey.api.cache.BlockingStringKeyCache;
import org.labkey.api.cache.CacheLoader;
import org.labkey.api.cache.CacheManager;
import org.labkey.api.data.Container;
import org.labkey.api.data.SimpleFilter;
import org.labkey.api.data.Sort;
import org.labkey.api.data.Table;
import org.labkey.api.data.TableSelector;
import org.labkey.api.view.Portal.WebPart;

/**
 * User: adam
 * Date: 10/21/11
 * Time: 10:45 PM
 */
public class WebPartCache
{
    private static final BlockingStringKeyCache<WebPart[]> CACHE = CacheManager.getBlockingStringKeyCache(10000, CacheManager.DAY, "Webparts", null);

    private static String getCacheKey(@NotNull Container c, @Nullable String id)
    {
        String result = c.getId();
        if (null != id)
        {
            result += "/" + id.toLowerCase();
        }
        return result;
    }

    static WebPart[] get(final Container c, final String pageId)
    {
        String key = getCacheKey(c, pageId);
        return CACHE.get(key, null, new CacheLoader<String, WebPart[]>()
        {
            @Override
            public WebPart[] load(String key, Object argument)
            {
                SimpleFilter filter = new SimpleFilter("PageId", pageId);
                filter.addCondition("Container", c.getId());

                return new TableSelector(Portal.getTableInfoPortalWebParts(), Table.ALL_COLUMNS, filter, new Sort("Index")).getArray(WebPart.class);
            }
        });
    }

    static void remove(Container c, String pageId)
    {
        CACHE.remove(getCacheKey(c, pageId));
    }

    static void remove(Container c)
    {
        CACHE.removeUsingPrefix(getCacheKey(c, null));
    }
}
