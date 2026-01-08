package io.xlogistx.http.services;

import io.xlogistx.common.data.PropertyContainer;
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
import org.zoxweb.shared.protocol.ProtoMarker;
import org.zoxweb.shared.protocol.ProtoSession;
import org.zoxweb.shared.util.*;

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Date;

public class HTTPUploadHandler
        extends PropertyContainer<NVGenericMap>
        implements HTTPRawHandler {


    public final static LogWrapper log = new LogWrapper(HTTPProtocolHandler.class).setEnabled(false);
    private File baseFolder;

    /**
     * @param hph
     * @throws IOException
     */
    @EndPointProp(methods = {HTTPMethod.POST, HTTPMethod.PUT}, name = "upload-file", uris = "/system-upload")
    @SecurityProp(authentications = {CryptoConst.AuthenticationType.ALL}, permissions = "system:upload:files")
    @Override
    public boolean handle(@ParamProp(name = "raw-content", source = Const.ParamSource.RESOURCE, optional = true) HTTPProtocolHandler hph)
            throws IOException {


        if (getBaseFolder() == null)
            throw new HTTPCallException("Storage location not available!", HTTPStatusCode.NOT_FOUND);


        HTTPMessageConfigInterface requestConfig = hph.getRequest(true);
        if (requestConfig.isTransferChunked()) {
            return chunkedHandle(hph);
        }
        //System.out.println(hph.getRawRequest());
        //System.out.println(hmciRequest.getParameters());

        NVGenericMap parameters = requestConfig.getParameters();

        NamedValue<InputStream> fileData = parameters.getNV("file");
        String fileLocation = parameters.getValue("file-location");


        File file;
        if (SUS.isNotEmpty(fileLocation)) {
            File fileDir = new File(getBaseFolder(), fileLocation);

            if (fileDir.isDirectory())
                file = new File(fileDir, fileData.getProperties().getValue("filename"));
            else
                throw new HTTPCallException("file location " + fileLocation + " is not a folder", HTTPStatusCode.NOT_FOUND);

        } else
            file = new File(getBaseFolder(), fileData.getProperties().getValue("filename"));


        if (file.isDirectory() && IOUtil.isFileInDirectory(getBaseFolder(), file))
            file = new File(fileLocation, fileData.getProperties().getValue("filename"));
        else if (!IOUtil.isFileInDirectory(getBaseFolder(), file))
            throw new HTTPCallException("Invalid storage location ", HTTPStatusCode.FORBIDDEN);


        MessageDigest md;
        try {
            md = MessageDigest.getInstance(CryptoConst.HashType.SHA_256.getName());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        long totalCopied = 0;
        try (FileOutputStream fos = new FileOutputStream(file)) {
            totalCopied += IOUtil.relayStreams(md, fileData.getValue(), fos);
        }


        HashResult hashResult = new HashResult(CryptoConst.HashType.SHA_256, md.digest(), totalCopied);


        HTTPMessageConfigInterface hmciResponse = hph.buildResponse(HTTPStatusCode.OK,
                HTTPHeader.SERVER.toHTTPHeader(((GetNamedVersion) ResourceManager.SINGLETON.lookup(ResourceManager.Resource.HTTP_SERVER)).getName()));
        hmciResponse.setContentType(HTTPMediaType.APPLICATION_JSON);
        NVGenericMap responseData = new NVGenericMap();
        responseData.build("filename", file.getName())
                .build(new NVPair("timestamp", DateUtil.DEFAULT_GMT_MILLIS.format(new Date())))
                .build(new NVLong("data-length", hashResult.dataLength))
                .build(hashResult.hashType.getName().toLowerCase(), SharedStringUtil.bytesToHex(hashResult.hash.asBytes()));

        hmciResponse.setContent(GSONUtil.toJSONDefault(responseData, true));

        HTTPUtil.formatResponse(hmciResponse, hph.getResponseStream())
                .writeTo(hph.getOutputStream());

        if (log.isEnabled()) log.getLogger().info("Done receiving File: " + file);

        // ex
        hph.expire();

        return true;
    }


    private boolean chunkedHandle(@ParamProp(name = "raw-content", source = Const.ParamSource.RESOURCE, optional = true) HTTPProtocolHandler hph)
            throws IOException {

        if (log.isEnabled()) log.getLogger().info("Chunked data");
        if (getBaseFolder() == null)
            throw new HTTPCallException("Storage location not available!", HTTPStatusCode.NOT_FOUND);


        HTTPMessageConfigInterface requestConfig = hph.getRequest(true);
        //System.out.println(hph.getRawRequest());
        //System.out.println(hmciRequest.getParameters());

        NVGenericMap parameters = requestConfig.getParameters();

        NamedValue<InputStream> fileData = parameters.getNV("file");
        OutputStream fos = null;
        if (log.isEnabled()) log.getLogger().info("fileData: " + (fileData != null ? fileData.getName() : "NULL"));

        if (fileData != null) {
            String fileLocation = parameters.getValue("file-location");
            fos = fileData.getProperties().getValue("fos");

            if (fos == null) {
                File file;
                if (SUS.isNotEmpty(fileLocation)) {
                    File fileDir = new File(getBaseFolder(), fileLocation);

                    if (fileDir.isDirectory())
                        file = new File(fileDir, fileData.getProperties().getValue("filename"));
                    else
                        throw new HTTPCallException("file location " + fileLocation + " is not a folder", HTTPStatusCode.NOT_FOUND);

                } else
                    file = new File(getBaseFolder(), fileData.getProperties().getValue("filename"));


                if (file.isDirectory() && IOUtil.isFileInDirectory(getBaseFolder(), file))
                    file = new File(fileLocation, fileData.getProperties().getValue("filename"));
                else if (!IOUtil.isFileInDirectory(getBaseFolder(), file))
                    throw new HTTPCallException("Invalid storage location ", HTTPStatusCode.FORBIDDEN);

                fos = new FileOutputStream(file);
                ProtoSession<?, ?> ps = hph.getConnectionSession();
                ps.getAutoCloseables().add(fos);
                fileData.getProperties().build(new NamedValue<>("fos", fos));

                fileData.getProperties().build(new NamedValue<>("file", file));
                fileData.getProperties().build(new NVLong("start-ts", System.currentTimeMillis()));

                GetNameValue<String> location = fileData.getProperties().getNV(HTTPHeader.LOCATION);
                if (location != null)
                    log.getLogger().info("We have location override " + location);


            }


            MessageDigest md = fileData.getProperties().getValue("md");
            if (md == null) {
                try {
                    md = MessageDigest.getInstance(CryptoConst.HashType.SHA_256.getName());
                    fileData.getProperties().build(new NamedValue<>("md", md));
                } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException(e);
                }
            }


            long totalCopied = fileData.getProperties().getValue("total-copied", (long) 0);
            int chunkSize = fileData.getValue().available();
            totalCopied += IOUtil.relayStreams(md, fileData.getValue(), fos);
            fileData.getProperties().build(new NVLong("total-copied", totalCopied));
            IOUtil.close(fileData.getValue());

            if (log.isEnabled())
                log.getLogger().info("Total copied so far " + totalCopied + " chunkSize: " + chunkSize + " " + fileData.getProperties().getNV(ProtoMarker.LAST_CHUNK) +
                        " Request data buffer size: " + hph.getRawRequest().getDataStream().size() + " request complete: " + hph.isRequestComplete());


            if ((boolean) fileData.getProperties().getValue(ProtoMarker.LAST_CHUNK)) {
                long delta = System.currentTimeMillis() - (long) fileData.getProperties().getValue("start-ts");


                log.getLogger().info("last remaining raw data: " + hph.getRawRequest().getDataStream().size());
                IOUtil.close(fos);


                HashResult hashResult = new HashResult(CryptoConst.HashType.SHA_256, md.digest(), totalCopied);


                HTTPMessageConfigInterface hmciResponse = hph.buildResponse(HTTPStatusCode.OK,
                        HTTPHeader.SERVER.toHTTPHeader(((GetNamedVersion) ResourceManager.SINGLETON.lookup(ResourceManager.Resource.HTTP_SERVER)).getName()));
                hmciResponse.setContentType(HTTPMediaType.APPLICATION_JSON);
                NVGenericMap responseData = new NVGenericMap();
                File file = fileData.getProperties().getValue("file");
                responseData.build("filename", file.getName())
                        .build(new NVPair("timestamp", DateUtil.DEFAULT_GMT_MILLIS.format(new Date())))
                        .build("duration", Const.TimeInMillis.toString(delta))
                        .build(new NVLong("data-length", hashResult.dataLength))
                        .build(hashResult.hashType.getName().toLowerCase(), SharedStringUtil.bytesToHex(hashResult.hash.asBytes()));

                hmciResponse.setContent(GSONUtil.toJSONDefault(responseData, true));

//                HTTPUtil.formatResponse(hmciResponse, hph.getResponseStream())
//                        .writeTo(hph.getOutputStream());

                if (log.isEnabled()) log.getLogger().info("Done receiving File: " + file);

                // ex
                hph.expire();
                return true;
            }
        }
        return false;

    }

    /**
     *
     */
    @Override
    protected void refreshProperties() {

        String baseFolderFilename = getProperties().getValue("base_folder");
        baseFolderFilename = SharedStringUtil.trimOrNull(baseFolderFilename);
        if (baseFolderFilename != null) {
            File folder = new File(baseFolderFilename);
            if (folder.exists() && folder.isDirectory() && folder.canRead())
                this.baseFolder = folder;
        }
    }

    public File getBaseFolder() {
        return baseFolder;
    }
}
