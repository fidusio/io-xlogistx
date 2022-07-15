package io.xlogistx.common.image;

import java.io.ByteArrayInputStream;

public class ImageInfo {
    public final ByteArrayInputStream data;
    public final int height;
    public final int width;
    public final String format;
    public final long timestamp;
    public final String id;

    public ImageInfo(long timestamp, String id, ByteArrayInputStream data, int width, int height, String format)
    {
        this.timestamp = timestamp;
        this.id = id;
        this.data = data;
        this.height = height;
        this.width = width;
        this.format = format;

    }
}
