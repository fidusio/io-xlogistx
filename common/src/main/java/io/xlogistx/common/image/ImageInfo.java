package io.xlogistx.common.image;

import java.io.InputStream;

public class ImageInfo {
    public final InputStream data;
    public final int height;
    public final int width;
    public final String format;
    public final long timestamp;
    public final String id;
    public final int dataLength;

    public ImageInfo(long timestamp, String id, InputStream data, int dataLength,String format, int width, int height)
    {
        this.timestamp = timestamp;
        this.id = id;
        this.data = data;
        this.dataLength = dataLength;
        this.height = height;
        this.width = width;
        this.format = format;
    }






}
