package io.xlogistx.common.test;

import org.w3c.dom.*;
import org.zoxweb.shared.util.SharedStringUtil;

import java.io.*;

import java.util.*;
import javax.imageio.ImageIO;
import javax.imageio.ImageReader;
import javax.imageio.stream.*;
import javax.imageio.metadata.*;

public class ImageMetaReader {

    public static void main(String[] args) {
        try {
            ImageMetaReader meta = new ImageMetaReader();
            int length = args.length;
            for (int i = 0; i < length; i++) {
                meta.readAndDisplayMetadata(args[i]);
                javaxt.io.Image image = new javaxt.io.Image(args[i]);
                String format = SharedStringUtil.valueAfterRightToken(args[i], ".").toLowerCase();


                for (Map.Entry<Integer, Object> kv : image.getExifTags().entrySet()) {
                    System.out.println("k: " + kv.getKey() + ", " + kv.getValue());
                }

                for (Map.Entry<Integer, Object> kv : image.getGpsTags().entrySet()) {
                    System.out.println("k: " + kv.getKey() + ", " + kv.getValue());
                }

                System.out.println("GPS: " + image.getGPSDatum() + " " + Arrays.toString(image.getGPSCoordinate()));
                System.out.println(format + " " + Arrays.toString(image.getInputFormats()));

                ImageIO.write(image.getBufferedImage(), format, new File("d:\\temp\\toto."+format));


            }
        }
        catch(Exception e)
        {
            e.printStackTrace();
        }
    }

    void readAndDisplayMetadata(String fileName) {
        try {

            File file = new File( fileName );
            ImageInputStream iis = ImageIO.createImageInputStream(file);
            Iterator<ImageReader> readers = ImageIO.getImageReaders(iis);

            if (readers.hasNext()) {

                // pick the first available ImageReader
                ImageReader reader = readers.next();

                // attach source to the reader
                reader.setInput(iis, true);

                // read metadata of first image
                IIOMetadata metadata = reader.getImageMetadata(0);


                String[] names = metadata.getMetadataFormatNames();
                int length = names.length;
                for (int i = 0; i < length; i++) {
                    System.out.println( "Format name: " + names[ i ] );
                    displayMetadata(metadata.getAsTree(names[i]));
                }
                System.out.println(Arrays.toString(metadata.getExtraMetadataFormatNames()));
            }
        }
        catch (Exception e) {

            e.printStackTrace();
        }
    }

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