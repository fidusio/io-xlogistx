package io.xlogistx.http.services;

import io.xlogistx.common.data.PropertyHolder;
import io.xlogistx.common.http.HTTPSessionHandler;
import io.xlogistx.common.http.HTTPSessionData;
import org.zoxweb.server.io.IOUtil;

import org.zoxweb.shared.annotation.EndPointProp;
import org.zoxweb.shared.annotation.ParamProp;
import org.zoxweb.shared.http.*;
import org.zoxweb.shared.util.Const;
import org.zoxweb.shared.util.ResourceManager;
import org.zoxweb.shared.util.SharedStringUtil;
import org.zoxweb.shared.util.SharedUtil;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

public class HTTPFileServiceHandler
    extends PropertyHolder
    implements HTTPSessionHandler
{


    private File baseFolder;

    @Override
    protected void refreshProperties() {
        setBaseFolder(getProperties().getValue("base_folder"));
    }

    @Override
    @EndPointProp(methods = {HTTPMethod.GET}, name="files", uris="/")
    public void handle(@ParamProp(name="filename", source=Const.ParamSource.RESOURCE, optional=true)HTTPSessionData sessionData)
            throws IOException
    {
        String filename = sessionData.protocolHandler.getRequest().getURI();

        if (SharedStringUtil.isEmpty(filename) || filename.equals("/"))
        {
            String override = getProperties().getValue("default_file");
            if(override != null)
            {
                filename = override;
            }
        }
        HTTPMimeType mime = HTTPMimeType.lookupByExtension(filename);
        if(log.isEnabled()) {

            log.getLogger().info("file to load: " + filename);

            log.getLogger().info("mime: " + mime);
        }

        File file = new File(getBaseFolder(), filename);
        if (!file.exists() || !file.isFile() || !file.canRead())
        {
            if(log.isEnabled())
                log.getLogger().info("File Not Found:" + file.getName());
            throw new HTTPCallException(file.getName() + " not found", HTTPStatusCode.NOT_FOUND);
        }
        if(mime != null)
            sessionData.protocolHandler.getResponse().setContentType(mime.getValue());
        sessionData.protocolHandler.getResponse().setContentLength((int)file.length());
        sessionData.protocolHandler.getResponse().setHTTPStatusCode(HTTPStatusCode.OK);
        sessionData.protocolHandler.getResponse().getHeaders().add(HTTPHeader.SERVER.getName(),
                (String)ResourceManager.SINGLETON.lookup(ResourceManager.Resource.HTTP_SERVER));

        FileInputStream fileIS = new FileInputStream(file);
        sessionData.writeResponse();
        IOUtil.relayStreams(fileIS, sessionData.os, true, false);
    }


    public HTTPFileServiceHandler setBaseFolder(String baseFolder) throws IllegalArgumentException
    {
        baseFolder = SharedStringUtil.trimOrNull(baseFolder);
        SharedUtil.checkIfNulls("Null baseDir ", baseFolder);
        File folder = new File(baseFolder);
        if (!folder.exists() || !folder.isDirectory() || !folder.canRead())
            throw new IllegalArgumentException("Invalid folder: " + folder.getAbsolutePath());
        this.baseFolder = folder;
        return this;
    }

    public File getBaseFolder(){return baseFolder;}
}
