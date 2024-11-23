package io.xlogistx.common.image;

import javax.imageio.ImageIO;
import javax.imageio.ImageReader;
import javax.imageio.stream.ImageInputStream;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.util.Iterator;

public class ImageUtil {

    private ImageUtil(){}

    public static String getImageFormat(String fileName)
            throws IOException
    {
        return getImageFormat(new File(fileName));
    }


    // Method to get image format from a File
    public static String getImageFormat(File file)
            throws IOException
    {
        try (ImageInputStream iis = ImageIO.createImageInputStream(file))
        {
            return getImageFormat(iis);
        }
    }

    // Method to get image format from a URL
    public static String getImageFormat(URL url)
            throws IOException
    {
        try (ImageInputStream iis = ImageIO.createImageInputStream(url.openStream()))
        {
            return getImageFormat(iis);
        }
    }

    // Helper method to extract format name from ImageInputStream
    public static String getImageFormat(ImageInputStream iis)
            throws IOException
    {
        Iterator<ImageReader> imageReaders = ImageIO.getImageReaders(iis);
        if (!imageReaders.hasNext())
            return null; // No reader found

        ImageReader reader = imageReaders.next();
        try
        {
            return reader.getFormatName();
        }
        finally
        {
            reader.dispose();
        }
    }



    public static void main(String ...args)
    {
        for (String filename : args)
        {

            URI uri = null;
            try
            {

                try
                {
                    uri = new URL(filename).toURI();
                }
                catch (IOException e){}

                System.out.println(filename + " format: " + (uri == null ? getImageFormat(filename) : getImageFormat(uri.toURL())));
            } catch (Exception e) {
                System.err.println(filename + " failed");
                e.printStackTrace();
            }
        }
    }
}
