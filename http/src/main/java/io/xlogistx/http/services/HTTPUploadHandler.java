package io.xlogistx.http.services;

import io.xlogistx.common.data.PropertyHolder;
import io.xlogistx.common.http.HTTPProtocolHandler;
import io.xlogistx.common.http.HTTPRawHandler;
import org.zoxweb.server.http.HTTPUtil;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.util.DateUtil;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.shared.annotation.EndPointProp;
import org.zoxweb.shared.annotation.ParamProp;
import org.zoxweb.shared.annotation.SecurityProp;
import org.zoxweb.shared.crypto.CryptoConst;
import org.zoxweb.shared.crypto.HashResult;
import org.zoxweb.shared.http.*;
import org.zoxweb.shared.util.*;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Date;

public class HTTPUploadHandler
    extends PropertyHolder
    implements HTTPRawHandler
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



        if (getBaseFolder() == null)
            throw new HTTPCallException("Storage location not available!", HTTPStatusCode.NOT_FOUND);


        HTTPMessageConfigInterface hmciRequest = hph.getRequest();
        //System.out.println(hph.getRawRequest());
        //System.out.println(hmciRequest.getParameters());

        InputStream is = null;


        NVGenericMap parameters = hmciRequest.getParameters();

        NamedValue<InputStream> fileData = parameters.getNV("file");
        String fileLocation = parameters.getValue("file-location");


        File file = null;
        if (SUS.isNotEmpty(fileLocation))
        {
            File fileDir = new File(getBaseFolder(), fileLocation);

            if (fileDir.isDirectory())
                file = new File(fileDir, fileData.getProperties().getValue("filename"));
            else
                throw new HTTPCallException("file location " + fileLocation + " is not a folder", HTTPStatusCode.NOT_FOUND);

        }
        else
            file = new File(getBaseFolder(), fileData.getProperties().getValue("filename"));



        if (file.isDirectory() && IOUtil.isFileInDirectory(getBaseFolder(), file))
            file = new File(fileLocation, fileData.getProperties().getValue("filename"));
         else if (!IOUtil.isFileInDirectory(getBaseFolder(), file))
            throw new HTTPCallException("Invalid storage location ", HTTPStatusCode.FORBIDDEN);





        HashResult hr = IOUtil.relayStreams(CryptoConst.HASHType.SHA_256, fileData.getValue(), new FileOutputStream(file), true);



        HTTPMessageConfigInterface hmciResponse = hph.buildResponse(HTTPStatusCode.OK,
                HTTPHeader.SERVER.toHTTPHeader((String) ResourceManager.SINGLETON.lookup(ResourceManager.Resource.HTTP_SERVER)));
        hmciResponse.setContentType(HTTPMediaType.APPLICATION_JSON);
        NVGenericMap responseData = new NVGenericMap();
        responseData.build("filename", file.getName())
                .build(new NVLong("length", hr.dataLength))
                .build(new NVPair("timestamp", DateUtil.DEFAULT_GMT_MILLIS.format(new Date())))
                .build("hash_type", hr.hashType.getName())
                .build("hash", SharedStringUtil.bytesToHex(hr.hash.asBytes()));

        hmciResponse.setContent(GSONUtil.toJSONDefault(responseData, true));

        HTTPUtil.formatResponse(hmciResponse, hph.getResponseStream())
                .writeTo(hph.getOutputStream());

        if (log.isEnabled()) log.getLogger().info("Done receiving File: " + file);

        // ex
        hph.expire();


    }

    /**
     *
     */
    @Override
    protected void refreshProperties() {

        String baseFolderFilename = getProperties().getValue("base_folder");
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
