package io.xlogistx.http.services;


import io.xlogistx.common.data.PropertyContainer;
import io.xlogistx.common.http.CachedPathMatcher;
import io.xlogistx.http.EndpointsUtil;
import org.zoxweb.server.http.HTTPUtil;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.shared.io.SharedIOUtil;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.server.util.JarTool;
import org.zoxweb.shared.annotation.EndPointProp;
import org.zoxweb.shared.annotation.ParamProp;
import org.zoxweb.shared.data.SimpleMessage;
import org.zoxweb.shared.http.*;
import org.zoxweb.shared.util.*;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipInputStream;

/**
 * This class load static public accessible files from the base-folder
 */
public class HTTPFileServiceHandler
        extends PropertyContainer<NVGenericMap> {
    public static final LogWrapper log = new LogWrapper(HTTPFileServiceHandler.class).setEnabled(true);

    private Path baseFolder;
    private final CachedPathMatcher cpm = new CachedPathMatcher();
    private String redirectURL = null;

    @Override
    protected void refreshProperties() {
        String htmlURI = getProperties().getValue("html_uri");
        if (log.isEnabled()) log.getLogger().info("htm_uri: " + htmlURI);
        FileSystem fileSystem = ResourceManager.lookupResource(ResourceManager.Resource.FILE_SYSTEM);
        if (log.isEnabled()) log.getLogger().info("We have a file system: " + fileSystem);

        if (htmlURI != null && fileSystem != null && fileSystem != FileSystems.getDefault()) {
            // need to copy the jar content to FileSystem
            if (log.isEnabled()) log.getLogger().info("html_uri: " + htmlURI);

            InputStream is = null;
            ZipInputStream zis = null;
            try {
                URI uri = new URI(htmlURI);
                is = uri.toURL().openStream();
                zis = JarTool.convertToZipIS(is);
                Path pathHtmlURI = fileSystem.getPath("/html_content");
                Files.createDirectory(pathHtmlURI);
                if (log.isEnabled()) log.getLogger().info("pathHtmlURI: " + pathHtmlURI);
                JarTool.zipISToOutputPath(zis, pathHtmlURI);
                log.getLogger().info(IOUtil.toStringFileSystem(fileSystem));
                baseFolder = pathHtmlURI;
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                SharedIOUtil.close(is, zis);
            }

        } else if (getProperties().getValue("base_folder") != null)
            setBaseFolder(getProperties().getValue("base_folder"));

        redirectURL = getProperties().getValue("redirect_url");

        if (log.isEnabled()) log.getLogger().info("baseFolder: " + baseFolder);

    }

    @EndPointProp(methods = {HTTPMethod.GET}, name = "files", uris = "/")
    public HTTPMessageConfigInterface loadFile(@ParamProp(name = "file-info", source = Const.ParamSource.RESOURCE, optional = true, uri = true) String filename)
            throws IOException {
        //String filename = protocolHandler.getRequest(true).getURI();

        if(log.isEnabled()) log.getLogger().info("filename: " + filename);

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

        if (filename.startsWith("/"))
            filename = filename.substring(1);


        Path filePath = cpm.findIn(getBaseFolder(), filename);

        if (filePath == null) {
            if (redirectURL != null) {
                log.getLogger().info("Redirect url: " + redirectURL);
                return EndpointsUtil.SINGLETON.redirect302(redirectURL);
            } else {
                //if (log.isEnabled())
                log.getLogger().info("File Not Found:" + filename);


                SimpleMessage sm = new SimpleMessage();
                sm.setError(filename + " not found");
                sm.setStatus(HTTPStatusCode.NOT_FOUND.CODE);
                HTTPMessageConfigInterface hmci = new HTTPMessageConfig();
                hmci.setContent(GSONUtil.toJSONDefault(sm));
                hmci = HTTPUtil.buildResponse(hmci, HTTPStatusCode.NOT_FOUND, HTTPConst.CommonHeader.CONTENT_TYPE_JSON_UTF8,
                        HTTPConst.CommonHeader.NO_CACHE_CONTROL,
                        HTTPConst.CommonHeader.EXPIRES_ZERO);

                return hmci;
            }
        }


        HTTPMessageConfigInterface response = new HTTPMessageConfig();
        response.setHTTPStatusCode(HTTPStatusCode.OK);
        response.getHeaders().build(HTTPHeader.SERVER.toHTTPHeader(((GetNamedVersion) ResourceManager.SINGLETON.lookup(ResourceManager.Resource.HTTP_SERVER)).getName()));
        if (mime != null)
            response.setContentType(mime.getValue());
        response.setContentAsIS(Files.newInputStream(filePath), true);

        return response;


    }

    public HTTPFileServiceHandler setBaseFolder(String baseFolder) throws IllegalArgumentException {
        baseFolder = SUS.trimOrNull(baseFolder);
        SUS.checkIfNulls("Null baseDir ", baseFolder);
        File folder = new File(baseFolder);
        if (!folder.exists() || !folder.isDirectory() || !folder.canRead())
            throw new IllegalArgumentException("Invalid folder: " + folder.getAbsolutePath());
        this.baseFolder = folder.toPath();
        ResourceManager.SINGLETON.register("base-folder", getBaseFolder());
        return this;
    }

    public Path getBaseFolder() {
        return baseFolder;
    }
}
