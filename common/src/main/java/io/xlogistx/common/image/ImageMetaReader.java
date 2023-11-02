package io.xlogistx.common.image;

import com.drew.imaging.ImageMetadataReader;
import com.drew.imaging.ImageProcessingException;
import com.drew.metadata.Directory;
import com.drew.metadata.Metadata;
import com.drew.metadata.Tag;
import com.drew.metadata.exif.GpsDirectory;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.io.UByteArrayOutputStream;
import org.zoxweb.shared.util.ParamUtil;
import org.zoxweb.shared.util.SharedStringUtil;
import org.zoxweb.shared.util.SharedUtil;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

public class ImageMetaReader {



    public static void readInfo(String filename) throws ImageProcessingException, IOException {
        Metadata metadata = ImageMetadataReader.readMetadata(new File(filename));
        GpsDirectory  directory = metadata.getFirstDirectoryOfType(GpsDirectory.class);
        if (directory != null) {
            // Try to read the date and time when the picture was taken
            String dateTaken = directory.getString(GpsDirectory.TAG_DATE_STAMP);
            String timeTaken = directory.getString(GpsDirectory.TAG_TIME_STAMP);
            System.out.println("Date Taken: " + dateTaken);
            System.out.println("Time Taken: " + timeTaken);

            // Try to extract the GPS location


                // Try to read the date and time when the picture was taken from another directory
                // ... (Handle date and time as previously shown if needed)

                // Check for GPS data
                if (directory.containsTag(GpsDirectory.TAG_LATITUDE) && directory.containsTag(GpsDirectory.TAG_LONGITUDE)) {
                    // Note that you might also need to check TAG_LATITUDE_REF and TAG_LONGITUDE_REF to interpret the values correctly (N/S, E/W)
                    double latitude = directory.getGeoLocation().getLatitude();
                    double longitude = directory.getGeoLocation().getLongitude();

                    System.out.println("Latitude: " + latitude);
                    System.out.println("Longitude: " + longitude);
                } else {
                    System.out.println("No GPS coordinates found in the image.");
                }

        } else {
            System.out.println("No GPS Directory found in the image");
        }
    }


    public static void metaDataExtractor(String filename) throws IOException, ImageProcessingException {
        metaDataExtractor(new FileInputStream(filename));
    }

    public static void metaDataExtractor(InputStream is ) throws ImageProcessingException, IOException
    {
        try
        {
            Metadata metadata = ImageMetadataReader.readMetadata(is);

            // Iterate over all directories
            for (Directory directory : metadata.getDirectories())
            {
                for (Tag tag : directory.getTags())
                {
                    //System.out.println(tag);
                    System.out.println(SharedUtil.toCanonicalID(',', tag.getDirectoryName(), tag.getTagName(), tag.getDescription()));
                }

                // Print any errors encountered
                for (String error : directory.getErrors()) {
                    System.err.println("ERROR: " + error);
                }
            }
        }
        finally
        {
            IOUtil.close(is);
        }

    }


//    public static void printInfo(javaxt.io.Image image)
//    {
//
//        BufferedImage bi = image.getBufferedImage();
//
//        for (Map.Entry<Integer, Object> kv : image.getExifTags().entrySet()) {
//            System.out.println("k: " + kv.getKey() + ", " + kv.getValue());
//        }
//
//        for (Map.Entry<Integer, Object> kv : image.getGpsTags().entrySet()) {
//            System.out.println("k: " + kv.getKey() + ", " + kv.getValue());
//        }
//        if (image.getBufferedImage() != null)
//        System.out.println("width: " + image.getWidth()+ " height: " + image.getHeight());
//    }

    public static void main(String[] args) {
        try {
            boolean scrub = false;
            String overrideFormat = null;
            ParamUtil.ParamMap params = ParamUtil.parse("=", args);
            if (params.booleanValue("scrub"))
                scrub = true;

            overrideFormat = params.stringValue("format", true);



            for (String imageFileName : params.namelessValues()) {
//                javaxt.io.Image image = new javaxt.io.Image(imageFileName);

                metaDataExtractor(imageFileName);
                System.out.println("\n\n\n");
                readInfo(imageFileName);



//                ImageMetaReader meta = new ImageMetaReader();
//                meta.readAndDisplayMetadata(imageFileName);

                String format = SharedStringUtil.valueAfterRightToken(imageFileName, ".").toLowerCase();



//                printInfo(image);



                String nameWithoutFormat = SharedStringUtil.valueBeforeRightToken(imageFileName, ".");
//                System.out.println("GPS: " + image.getGPSDatum() + " " + Arrays.toString(image.getGPSCoordinate()));
//                System.out.println(format + " " + Arrays.toString(image.getInputFormats()));
                System.out.println(imageFileName + "  Just name " + nameWithoutFormat);
                System.out.println("Orig format: " + format + " override format: " + overrideFormat  + " " + scrub);


                UByteArrayOutputStream baos = new UByteArrayOutputStream();
                BufferedImage image = ImageIO.read(new File(imageFileName));

                ImageIO.write(image, format.toUpperCase(), baos);
                metaDataExtractor(baos.toByteArrayInputStream());



                if (overrideFormat != null)
                {
                    format = overrideFormat;
                }


                if (scrub && !nameWithoutFormat.endsWith("_scrubbed"))
                {
                    File outputFile = new File(nameWithoutFormat + "_scrubbed." + format);
                    baos = new UByteArrayOutputStream();
                    //image.saveAs(outputFile);
                    ImageIO.write(image, format.toUpperCase(), outputFile);
                    System.out.println("will override " + outputFile + " " + baos.size());

                }


            }
        }
        catch(Exception e)
        {
            e.printStackTrace();
        }
    }

//    void readAndDisplayMetadata(String fileName) {
//        try {
//
//            File file = new File( fileName );
//            ImageInputStream iis = ImageIO.createImageInputStream(file);
//            Iterator<ImageReader> readers = ImageIO.getImageReaders(iis);
//
//            javaxt.io.Image image = new javaxt.io.Image(fileName);
//            System.out.println(Arrays.toString(image.getGPSCoordinate()));
//
//
//            if (readers.hasNext()) {
//
//                try {
//
//
//                    // pick the first available ImageReader
//                    ImageReader reader = readers.next();
//
//                    // attach source to the reader
//                    reader.setInput(iis, true);
//
//
//                    // read metadata of first image
//                    IIOMetadata metadata = reader.getImageMetadata(0);
//
//
//                    String[] names = metadata.getMetadataFormatNames();
//                    int length = names.length;
//                    for (int i = 0; i < length; i++) {
//                        System.out.println("Format name: " + names[i]);
//                        displayMetadata(metadata.getAsTree(names[i]));
//                    }
//                    System.out.println(Arrays.toString(metadata.getExtraMetadataFormatNames()));
//                }
//                catch (Exception e)
//                {
//                    System.err.println("" + e );
//                }
//            }
//        }
//        catch (Exception e) {
//
//            e.printStackTrace();
//        }
//    }

    void displayMetadata(Node root) {
        displayMetadata(root, 0);
    }

    void indent(int level) {
        for (int i = 0; i < level; i++)
            System.out.print("    ");
    }

    void displayMetadata(Node node, int level) {
        // print open tag of element
        indent(level);
        System.out.print("<" + node.getNodeName());
        NamedNodeMap map = node.getAttributes();
        if (map != null) {

            // print attribute values
            int length = map.getLength();
            for (int i = 0; i < length; i++) {
                Node attr = map.item(i);
                System.out.print(" " + attr.getNodeName() +
                        "=\"" + attr.getNodeValue() + "\"");
            }
        }

        Node child = node.getFirstChild();
        if (child == null) {
            // no children, so close element and return
            System.out.println("/>");
            return;
        }

        // children, so close current tag
        System.out.println(">");
        while (child != null) {
            // print children recursively
            displayMetadata(child, level + 1);
            child = child.getNextSibling();
        }

        // print close tag of element
        indent(level);
        System.out.println("</" + node.getNodeName() + ">");
    }
}