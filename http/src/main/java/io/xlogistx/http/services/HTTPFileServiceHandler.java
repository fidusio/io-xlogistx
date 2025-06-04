package io.xlogistx.http.services;

import io.xlogistx.common.data.PropertyHolder;
import io.xlogistx.common.http.HTTPProtocolHandler;
import io.xlogistx.common.http.HTTPRawHandler;
import org.zoxweb.server.http.HTTPUtil;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.util.JarTool;
import org.zoxweb.shared.annotation.EndPointProp;
import org.zoxweb.shared.annotation.ParamProp;
import org.zoxweb.shared.http.*;
import org.zoxweb.shared.util.Const;
import org.zoxweb.shared.util.ResourceManager;
import org.zoxweb.shared.util.SUS;
import org.zoxweb.shared.util.SharedStringUtil;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipInputStream;

public class HTTPFileServiceHandler
        extends PropertyHolder
        implements HTTPRawHandler {
    public static final LogWrapper log = new LogWrapper(HTTPFileServiceHandler.class).setEnabled(false);

    private Path baseFolder;

    @Override
    protected void refreshProperties() {
        String htmlURI = getProperties().getValue("html_uri");
        FileSystem fileSystem = ResourceManager.lookupResource(ResourceManager.Resource.FILE_SYSTEM);
        if(log.isEnabled()) log.getLogger().info("We have a file system: " + fileSystem);

        if (htmlURI != null && fileSystem != null && fileSystem != FileSystems.getDefault()) {
            // need to copy the jar content to FileSystem
            if(log.isEnabled()) log.getLogger().info("htmt_uri: " + htmlURI);

            try {
                URI uri = new URI(htmlURI);
                InputStream is = uri.toURL().openStream();
                ZipInputStream zis = JarTool.convertToZipIS(is);
                Path pathHtmlURI = fileSystem.getPath("/html_content");
                Files.createDirectory(pathHtmlURI);
                if(log.isEnabled()) log.getLogger().info("pathHtmlURI: " + pathHtmlURI);
                JarTool.zipISToOutputPath(zis, pathHtmlURI);
                log.getLogger().info(IOUtil.toStringFileSystem(fileSystem));
                baseFolder = pathHtmlURI;
            } catch (Exception e) {
                e.printStackTrace();
            }
            if(log.isEnabled()) log.getLogger().info("baseFolder: " + baseFolder);

        } else
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

        if (filename.startsWith("/"))
            filename = filename.substring(1);

        Path filePath = getBaseFolder().resolve(filename);
        //File file = new File(getBaseFolder(), filename);
        if (!Files.exists(filePath) || !Files.isRegularFile(filePath) || !Files.isReadable(filePath)) {
            if (log.isEnabled())
                log.getLogger().info("File Not Found:" + filename);
            throw new HTTPCallException(filename + " not found", HTTPStatusCode.NOT_FOUND);
        }


        InputStream fileIS = Files.newInputStream(filePath);


        HTTPMessageConfigInterface hmci = protocolHandler.buildResponse(HTTPStatusCode.OK,
                HTTPHeader.SERVER.toHTTPHeader((String) ResourceManager.SINGLETON.lookup(ResourceManager.Resource.HTTP_SERVER)));

        if (mime != null)
            hmci.setContentType(mime.getValue());

        hmci.setContentLength((int) fileIS.available());

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
        this.baseFolder = folder.toPath();
        ResourceManager.SINGLETON.register("base-folder", getBaseFolder());
        return this;
    }

    public Path getBaseFolder() {
        return baseFolder;
    }
}
