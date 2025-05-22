package io.xlogistx.http.services;

import io.xlogistx.common.data.PropertyHolder;
import io.xlogistx.common.http.HTTPProtocolHandler;
import io.xlogistx.common.http.HTTPRawHandler;
import org.zoxweb.server.http.HTTPUtil;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.shared.annotation.EndPointProp;
import org.zoxweb.shared.annotation.ParamProp;
import org.zoxweb.shared.http.*;
import org.zoxweb.shared.util.*;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

public class HTTPFileServiceHandler
        extends PropertyHolder
        implements HTTPRawHandler {
    public static final LogWrapper log = new LogWrapper(HTTPFileServiceHandler.class).setEnabled(false);

    private File baseFolder;

    @Override
    protected void refreshProperties() {
        setBaseFolder(getProperties().getValue("base_folder"));
    }

    @Override
    @EndPointProp(methods = {HTTPMethod.GET}, name = "files", uris = "/")
    public void handle(@ParamProp(name = "file-info", source = Const.ParamSource.RESOURCE, optional = true) HTTPProtocolHandler protocolHandler)
            throws IOException {
        String filename = protocolHandler.getRequest(true).getURI();

        if (SUS.isEmpty(filename) || filename.equals("/")) {
            String override = getProperties().getValue("default_file");
            if (override != null) {
                filename = override;
            }
        }
        HTTPMediaType mime = HTTPMediaType.lookupByExtension(filename);
        if (log.isEnabled()) {

            log.getLogger().info("file to load: " + filename);

            log.getLogger().info("mime: " + mime);
        }

        File file = new File(getBaseFolder(), filename);
        if (!file.exists() || !file.isFile() || !file.canRead()) {
            if (log.isEnabled())
                log.getLogger().info("File Not Found:" + file.getName());
            throw new HTTPCallException(file.getName() + " not found", HTTPStatusCode.NOT_FOUND);
        }


        FileInputStream fileIS = new FileInputStream(file);


        HTTPMessageConfigInterface hmci = protocolHandler.buildResponse(HTTPStatusCode.OK,
                HTTPHeader.SERVER.toHTTPHeader((String) ResourceManager.SINGLETON.lookup(ResourceManager.Resource.HTTP_SERVER)));

        if (mime != null)
            hmci.setContentType(mime.getValue());

        hmci.setContentLength((int) file.length());

//        HTTPUtil.formatResponse(hmci, protocolHandler.getResponseStream());
//        protocolHandler.getResponseStream().writeTo(protocolHandler.getOutputStream());
        HTTPUtil.formatResponse(hmci, protocolHandler.getResponseStream())
                .writeTo(protocolHandler.getOutputStream());

        IOUtil.relayStreams(fileIS, protocolHandler.getOutputStream(), true, false);
        if (log.isEnabled()) log.getLogger().info("filename: " + filename);

    }


    public HTTPFileServiceHandler setBaseFolder(String baseFolder) throws IllegalArgumentException {
        baseFolder = SharedStringUtil.trimOrNull(baseFolder);
        SUS.checkIfNulls("Null baseDir ", baseFolder);
        File folder = new File(baseFolder);
        if (!folder.exists() || !folder.isDirectory() || !folder.canRead())
            throw new IllegalArgumentException("Invalid folder: " + folder.getAbsolutePath());
        this.baseFolder = folder;
        ResourceManager.SINGLETON.register("base-folder", getBaseFolder());
        return this;
    }

    public File getBaseFolder() {
        return baseFolder;
    }
}
