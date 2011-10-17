package org.labkey.api.thumbnail;

import org.labkey.api.attachments.AttachmentFile;
import org.labkey.api.data.CacheableWriter;

import java.io.IOException;

/**
 * User: adam
 * Date: 10/8/11
 * Time: 7:17 AM
 */
public interface ThumbnailService
{
    public static final String THUMBNAIL_FILENAME = "Thumbnail";

    CacheableWriter getThumbnailWriter(StaticThumbnailProvider provider);
    void queueThumbnailRendering(DynamicThumbnailProvider provider);
    void deleteThumbnail(DynamicThumbnailProvider provider);
    void replaceThumbnail(DynamicThumbnailProvider provider, AttachmentFile thumbnailFile) throws IOException;
}
