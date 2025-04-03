package io.xlogistx.http.services;

import io.xlogistx.common.data.PropertyHolder;
import io.xlogistx.common.http.HTTPProtocolHandler;
import io.xlogistx.common.http.HTTPSessionHandler;
import org.zoxweb.server.http.HTTPUtil;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.logging.LogWrapper;
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


    public final static LogWrapper log = new LogWrapper(HTTPProtocolHandler.class).setEnabled(true);
    private File baseFolder;
    /**
     * @param hph
     * @throws IOException
     */
    @EndPointProp(methods = {HTTPMethod.POST, HTTPMethod.PUT}, name="upload-file", uris="/system-upload")
    @SecurityProp(authentications = {CryptoConst.AuthenticationType.ALL}, permissions = "system:upload:files")
    @Override
    public void handle(@ParamProp(name="raw-content", source= Const.ParamSource.RESOURCE, optional=true)HTTPProtocolHandler hph)
            throws IOException
    {



        if(getBaseFolder() == null)
            throw new HTTPCallException("Storage location not available!", HTTPStatusCode.NOT_FOUND);


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
        //if (SUS.isNotEmpty(fileLocation))





        File file;
        if (SUS.isNotEmpty(fileLocation)) {
            File fileDir = new File(getBaseFolder(), fileLocation);
            if (fileDir.isDirectory())
            {
                file = new File(fileDir, fileData.getProperties().getValue("filename"));
            }
            else
            {
                throw new HTTPCallException("file location " + fileLocation + " is not a folder", HTTPStatusCode.NOT_FOUND);
            }
        }
        else
            file = new File(getBaseFolder(), fileData.getProperties().getValue("filename"));



        if(log.isEnabled()) log.getLogger().info("File: " + file);


        if (file.isDirectory() && IOUtil.isFileInDirectory(getBaseFolder(), file))
        {
            file = new File(fileLocation, fileData.getProperties().getValue("filename"));
        }
        else if(!IOUtil.isFileInDirectory(getBaseFolder(), file))
        {
            throw new HTTPCallException("Invalid storage location ", HTTPStatusCode.FORBIDDEN);
        }

        if(log.isEnabled()) log.getLogger().info("File: " + file);

//            else if (file.getParentFile() == null || !file.getParentFile().isDirectory())
//            {
//                if(baseFolder != null && baseFolder.isDirectory())
//                {
//                    file = new File(baseFolder, fileLocation);
//                    System.out.println(baseFolder);
//                    System.out.println(file);
//                }
//            }
        IOUtil.relayStreams(fileData.getValue(), new FileOutputStream(file), true);




        HTTPMessageConfigInterface hmciResponse = hph.buildResponse(HTTPStatusCode.OK,
                HTTPHeader.SERVER.toHTTPHeader((String) ResourceManager.SINGLETON.lookup(ResourceManager.Resource.HTTP_SERVER)));
        hmciResponse.setContentType(HTTPMediaType.APPLICATION_JSON);

        HTTPUtil.formatResponse(hmciResponse, hph.getResponseStream())
                .writeTo(hph.getOutputStream());

    }

    /**
     *
     */
    @Override
    protected void refreshProperties() {
        System.out.println("base refresh");
        String baseFolderFilename = getProperties().getValue("base_folder");
        System.out.println("base: " + baseFolderFilename);
        SharedStringUtil.trimOrNull(baseFolderFilename);
        if(baseFolderFilename != null)
        {
            File folder = new File(baseFolderFilename);
            if (folder.exists() && folder.isDirectory() && folder.canRead())
                this.baseFolder = folder;
        }
    }

    public File getBaseFolder()
    {
        return baseFolder;
    }
}
