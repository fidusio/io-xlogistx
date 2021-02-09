/*
 * Copyright (c) 2012-2020 ZoxWeb.com LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package io.xlogistx.http.services;

import com.sun.net.httpserver.HttpExchange;

import io.xlogistx.http.handler.BaseEndPointHandler;
import io.xlogistx.http.handler.HTTPHandlerUtil;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.io.UByteArrayOutputStream;
import org.zoxweb.shared.http.HTTPHeaderName;
import org.zoxweb.shared.http.HTTPMimeType;
import org.zoxweb.shared.http.HTTPStatusCode;
import org.zoxweb.shared.util.*;

import java.io.*;
import java.net.URI;
import java.util.HashSet;
import java.util.LinkedHashMap;



import java.util.logging.Logger;

/**
 * File handler for the built in http server that is shipped with java jre and jdk.
 * This class will automatically upload files to the http client if it exist on the file system.
 * The context is set during context initialization.
 * The baseDir is the main folder entry point, any file within the baseDir/filename or baseDir/
 */
@SuppressWarnings("restriction")
public class HTTPFileHandler extends BaseEndPointHandler {
    private final static Logger log = Logger.getLogger(HTTPFileHandler.class.getName());

    private boolean cacheEnabled = true;

    private KVMapStore<String, byte[]> dataCache = new KVMapStoreDefault<String, byte[]>(new LinkedHashMap<String, byte[]>(), new HashSet<String>(), DSR.BYTES);


    private File baseFolder;
    public HTTPFileHandler()
    {
    }

    public HTTPFileHandler(String baseFolder)
            throws IllegalArgumentException
    {
       setBaseFolder(baseFolder);
    }

    public void handle(HttpExchange he) throws IOException {
        long callCount = callCounter.incrementAndGet();
        String path = he.getHttpContext().getPath();
        URI uri = he.getRequestURI();
//        log.info("path: " + path);
//        log.info("URI: " +  uri.getPath());
//        log.info("Remote IP: " + he.getRemoteAddress());
//        log.info("Thread: " + Thread.currentThread());
        InputStream fileIS = null;
        //OutputStream responseOS = null;
        String filename = null;
        try {
            filename = uri.getPath().substring(path.length(), uri.getPath().length());
            if (SharedStringUtil.isEmpty(filename))
            {
                String override = getHTTPEndPoint().getProperties().getValue("default_file");
                if(override != null)
                {
                    filename = override;
                }
            }
            HTTPMimeType mime = HTTPMimeType.lookupByExtenstion(filename);
//            log.info(Thread.currentThread() + " filename: '" + filename + "' mime type:" + mime);


            byte[] content = lookupContent(filename);

            if(mime != null)
                he.getResponseHeaders()
                        .add(HTTPHeaderName.CONTENT_TYPE.getName(), mime.getValue());
//            File file = new File(baseFolder, filename);
//            if (!file.exists() || !file.isFile() || !file.canRead()) {
//                log.info("File Not Found:" + file.getName());
//                throw new FileNotFoundException(file.getName() + " not found");
//            }
//
//            he.sendResponseHeaders(HTTPStatusCode.OK.CODE, file.length());
//            fileIS = new FileInputStream(file);
//            responseOS = he.getResponseBody();
//            IOUtil.relayStreams(fileIS, responseOS, true, true);

            he.sendResponseHeaders(HTTPStatusCode.OK.CODE, content.length);
            he.getResponseBody().write(content);

            log.info(SharedUtil.toCanonicalID(':', callCount, Thread.currentThread(), " filename", filename," size",
                    content.length," mime",mime," SENT", " cache data size" , Const.SizeInBytes.toString(dataCache.dataSize())));
        }
        catch(FileNotFoundException e)
        {
          HTTPHandlerUtil.sendErrorMessage(he, HTTPStatusCode.NOT_FOUND, "Resource NOT FOUND");
        }
        catch(Exception e)
        {
            e.printStackTrace();
            log.info(SharedUtil.toCanonicalID(':', callCount, " ****ERROR*** ",Thread.currentThread(), filename));
            HTTPHandlerUtil.sendErrorMessage(he, HTTPStatusCode.BAD_REQUEST, "System error");
        }

        finally {
            he.close();
        }
    }

    @Override
    protected void init() {
        setBaseFolder(getHTTPEndPoint().getProperties().getValue("base_folder"));
    }
    
    public void setBaseFolder(String baseFolder) throws IllegalArgumentException {
        baseFolder = SharedStringUtil.trimOrNull(baseFolder);
        SharedUtil.checkIfNulls("Null baseDir ", baseFolder);
        File folder = new File(baseFolder);
        if (!folder.exists() || !folder.isDirectory() || !folder.canRead())
            throw new IllegalArgumentException("Invalid folder: " + folder.getAbsolutePath());
        this.baseFolder = folder;
    }

    public boolean isCacheEnabled()
    {
        return cacheEnabled;
    }

    public void setCacheEnabled(boolean enable)
    {
        this.cacheEnabled = enable;

    }


    private byte[] lookupContent(String filename) throws IOException
    {
        byte[] content = null;
        UByteArrayOutputStream contentOS = null;
        if (isCacheEnabled())
        {
            synchronized (this) {
                content = dataCache.get(filename);

                if (content == null)
                {
                    File file = new File(baseFolder, filename);
                    if (!file.exists() || !file.isFile() || !file.canRead())
                    {
                        log.info("File Not Found:" + file.getName());
                        throw new FileNotFoundException(file.getName() + " not found");
                    }
                    FileInputStream fileIS = new FileInputStream(file);
                    contentOS = new UByteArrayOutputStream();
                    IOUtil.relayStreams(fileIS, contentOS, true, true);
                    content = contentOS.toByteArray();
                    dataCache.put(filename, content);
                }
            }
        }
        else
        {
            File file = new File(baseFolder, filename);
            if (!file.exists() || !file.isFile() || !file.canRead())
            {
                log.info("File Not Found:" + file.getName());
                throw new FileNotFoundException(file.getName() + " not found");
            }
            FileInputStream fileIS = new FileInputStream(file);
            contentOS = new UByteArrayOutputStream();
            IOUtil.relayStreams(fileIS, contentOS, true, true);
            content = contentOS.toByteArray();
        }

        return  content;
    }
}