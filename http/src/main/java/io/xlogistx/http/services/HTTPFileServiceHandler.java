package io.xlogistx.http.services;


import io.xlogistx.common.data.PropertyContainer;
import io.xlogistx.common.http.CachedPathMatcher;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.util.JarTool;
import org.zoxweb.shared.annotation.EndPointProp;
import org.zoxweb.shared.annotation.ParamProp;
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
    public static final LogWrapper log = new LogWrapper(HTTPFileServiceHandler.class).setEnabled(false);

    private Path baseFolder;
    private final CachedPathMatcher cpm = new CachedPathMatcher();

    @Override
    protected void refreshProperties() {
        String htmlURI = getProperties().getValue("html_uri");
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
                IOUtil.close(is, zis);
            }
            if (log.isEnabled()) log.getLogger().info("baseFolder: " + baseFolder);

        } else
            setBaseFolder(getProperties().getValue("base_folder"));


    }

    @EndPointProp(methods = {HTTPMethod.GET}, name = "files", uris = "/")
    public HTTPMessageConfigInterface loadFile(@ParamProp(name = "file-info", source = Const.ParamSource.RESOURCE, optional = true, uri = true) String filename)
            throws IOException {
        //String filename = protocolHandler.getRequest(true).getURI();

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
            if (log.isEnabled())
                log.getLogger().info("File Not Found:" + filename);
            throw new HTTPCallException(filename + " not found", HTTPStatusCode.NOT_FOUND);
        }


        HTTPMessageConfigInterface response = new HTTPMessageConfig();
        response.setHTTPStatusCode(HTTPStatusCode.OK);
        response.getHeaders().build(HTTPHeader.SERVER.toHTTPHeader(((GetNamedVersion) ResourceManager.SINGLETON.lookup(ResourceManager.Resource.HTTP_SERVER)).getName()));
        if (mime != null)
            response.setContentType(mime.getValue());
        response.setContentAsIS(Files.newInputStream(filePath));

        return response;


    }

    public HTTPFileServiceHandler setBaseFolder(String baseFolder) throws IllegalArgumentException {
        baseFolder = SharedStringUtil.trimOrNull(baseFolder);
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
