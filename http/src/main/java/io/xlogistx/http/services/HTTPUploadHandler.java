package io.xlogistx.http.services;

import io.xlogistx.common.data.PropertyHolder;
import io.xlogistx.common.http.HTTPProtocolHandler;
import io.xlogistx.common.http.HTTPSessionHandler;
import org.zoxweb.server.http.HTTPUtil;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.shared.annotation.EndPointProp;
import org.zoxweb.shared.annotation.ParamProp;
import org.zoxweb.shared.annotation.SecurityProp;
import org.zoxweb.shared.crypto.CryptoConst;
import org.zoxweb.shared.http.*;
import org.zoxweb.shared.util.*;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

public class HTTPUploadHandler
    extends PropertyHolder
    implements HTTPSessionHandler
{
    /**
     * @param hph
     * @throws IOException
     */
    @EndPointProp(methods = {HTTPMethod.POST, HTTPMethod.PUT}, name="upload-file", uris="/system-upload")
    @SecurityProp(authentications = {CryptoConst.AuthenticationType.ALL}, permissions = "upload:files")
    @Override
    public void handle(@ParamProp(name="raw-content", source= Const.ParamSource.RESOURCE, optional=true)HTTPProtocolHandler hph)
            throws IOException
    {
        HTTPMessageConfigInterface hmciRequest = hph.getRequest();
        //System.out.println(hph.getRawRequest());
        //System.out.println(hmciRequest.getParameters());

        InputStream is = null;


        NVGenericMap parameters = hmciRequest.getParameters();

        NamedValue<InputStream> fileData = parameters.getNV("file");
        String fileLocation = parameters.getValue("file-location");


//        long count = 0;
//
//        for (GetNameValue<?> gnv : hmciRequest.getParameters().values())
//        {
//            if (gnv instanceof NamedValue)
//            {
//                if(gnv.getValue() instanceof InputStream)
//                {
//                    is = (InputStream) gnv.getValue();
//                    if (is instanceof ByteArrayInputStream)
//                    {
//                        count = ((ByteArrayInputStream)is).available();
//                        System.out.println("Input stream length: " + count);
//                    }
//                }
//            }
//            else if (gnv instanceof NVGenericMap)
//            {
//                System.out.println(gnv);
//            }
//            else
//            {
//                if ("file-location".equalsIgnoreCase(gnv.getName()))
//                {
//                   fileLocation = (String) gnv.getValue();
//                }
//                System.out.println(gnv);
//            }
//        }
        if (SUS.isNotEmpty(fileLocation))
        {
            System.out.println(fileData);
            System.out.println(fileLocation);

            File file = new File(fileLocation);
            if (file.isDirectory())
            {
                file = new File(fileLocation, fileData.getProperties().getValue("filename"));
            }
            else if (file.getParentFile() == null || !file.getParentFile().isDirectory())
            {
                File baseFolder = ResourceManager.lookupResource("base-folder");
                if(baseFolder != null && baseFolder.isDirectory())
                {
                    file = new File(baseFolder, fileLocation);
                    System.out.println(baseFolder);
                    System.out.println(file);
                }
            }
            IOUtil.relayStreams(fileData.getValue(), new FileOutputStream(file), true);

        }






        HTTPMessageConfigInterface hmciResponse = hph.buildResponse(HTTPStatusCode.OK,
                HTTPHeader.SERVER.toHTTPHeader((String) ResourceManager.SINGLETON.lookup(ResourceManager.Resource.HTTP_SERVER)));
        hmciResponse.setContentType(HTTPMediaType.APPLICATION_JSON);


//        HTTPUtil.formatResponse(hmci, protocolHandler.getResponseStream());
//        protocolHandler.getResponseStream().writeTo(protocolHandler.getOutputStream());
        HTTPUtil.formatResponse(hmciResponse, hph.getResponseStream())
                .writeTo(hph.getOutputStream());

    }

    /**
     *
     */
    @Override
    protected void refreshProperties() {

    }
}
