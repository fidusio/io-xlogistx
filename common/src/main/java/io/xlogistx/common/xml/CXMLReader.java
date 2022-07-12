package io.xlogistx.common.xml;



import org.w3c.dom.Document;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.File;

public class CXMLReader {

    public static void main(String ...args)
    {
        try
        {
            int index = 0;
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document document = builder.parse(new File(args[index++]));
            System.out.println(document.getElementsByTagName(""));

        }
        catch(Exception e)
        {
            e.printStackTrace();
        }
    }
}
