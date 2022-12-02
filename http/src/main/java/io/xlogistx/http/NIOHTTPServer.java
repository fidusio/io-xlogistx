package io.xlogistx.http;


import io.xlogistx.common.data.MethodHolder;
import io.xlogistx.common.http.EndPointScanner;
import io.xlogistx.common.http.EndPointsManager;
import io.xlogistx.common.http.HTTPServerMapper;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.logging.LoggerUtil;
import org.zoxweb.server.net.NIOSocket;
import org.zoxweb.server.security.CryptoUtil;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.shared.http.HTTPEndPoint;
import org.zoxweb.shared.http.HTTPServerConfig;
import org.zoxweb.shared.http.URIScheme;
import org.zoxweb.shared.net.ConnectionConfig;
import org.zoxweb.shared.net.InetSocketAddressDAO;
import org.zoxweb.shared.util.Const;
import org.zoxweb.shared.util.DaemonController;
import org.zoxweb.shared.util.NVGenericMap;
import org.zoxweb.shared.util.SharedUtil;

import javax.net.ssl.SSLContext;
import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.logging.Logger;

public class NIOHTTPServer
        implements DaemonController,
        HTTPServerMapper
{
    private final static Logger log = Logger.getLogger(NIOHTTPServer.class.getName());
    private final HTTPServerConfig config;
    private final NIOSocket nioSocket;
    private boolean isClosed = true;

    public NIOHTTPServer(HTTPServerConfig config, NIOSocket nioSocket)
    {
        SharedUtil.checkIfNulls("HTTPServerConfig null", config);
        this.config = config;
        this.nioSocket = nioSocket;
    }

    public NIOSocket getNIOSocket()
    {
        return nioSocket;
    }

    public HTTPServerConfig getConfig()
    {
        return config;
    }

    @Override
    public boolean isInstanceNative(Object beanInstance) {
        return false;
    }

    @Override
    public void mapHEP(EndPointsManager endPointsManager, HTTPEndPoint hep, MethodHolder mh, Object beanInstance) {

    }

    @Override
    public boolean isClosed() {
        return isClosed;
    }

    @Override
    public void close() throws IOException {

    }
    public void start() throws IOException, GeneralSecurityException {
        if (isClosed) {
            if (config != null) {
                isClosed = false;
            }

            ConnectionConfig[] ccs = config.getConnectionConfigs();

            //TaskUtil.setMinTaskProcessorThreadCount(config.getThreadPoolSize());
            //Executor executor = config.isThreadPoolJavaType() ? Executors.newCachedThreadPool() : TaskUtil.getDefaultTaskProcessor();

            log.info("Connection Configs: " + ccs);
            for(ConnectionConfig cc : ccs)
            {
                String[] schemes = cc.getSchemes();
                for (String scheme : schemes) {
                    URIScheme uriScheme = SharedUtil.lookupEnum(scheme, URIScheme.values());
                    if (uriScheme != null)
                    {
                        String serverId = null;
                        InetSocketAddressDAO serverAddress = null;
                        InetSocketAddress isa = null;
                        switch (uriScheme)
                        {
                            case HTTPS:
                                // we need to create an https server
                                log.info("we need to create an https server");
                                serverAddress = cc.getSocketConfig();
                                serverId = uriScheme.getName() + ":" + serverAddress.getPort();
                                isa = new InetSocketAddress(serverAddress.getPort());

                                NVGenericMap sslConfig = cc.getSSLConfig();
                                String ksPassword = sslConfig.getValue("keystore_password");
                                String aliasPassword = sslConfig.getValue("alias_password");
                                String trustStorePassword = sslConfig.getValue("truststore_password");
                                String trustStoreFilename = sslConfig.getValue("truststore_file");
                                String protocol = sslConfig.getValue("protocol");
                                SSLContext sslContext = CryptoUtil.initSSLContext(protocol, null, IOUtil.locateFile(sslConfig.getValue("keystore_file")),
                                        sslConfig.getValue("keystore_type"),
                                        ksPassword.toCharArray(),
                                        aliasPassword != null ?  aliasPassword.toCharArray() : null,
                                        trustStoreFilename != null ? IOUtil.locateFile(trustStoreFilename) : null,
                                        trustStorePassword != null ?  trustStorePassword.toCharArray() : null);
                                break;
                            case HTTP:
                                // we need to create an http server
                                serverAddress = cc.getSocketConfig();
                                serverId = uriScheme.getName() + ":" + serverAddress.getPort();
                                isa = new InetSocketAddress(serverAddress.getPort());

                                break;
                            case FTP:
                            case FILE:
                            case MAIL_TO:
                            case DATA:
                            case WSS:
                            case WS:
                                break;
                        }
                    }
                }
            }


            // create end point scanner
            EndPointScanner endPointScanner = new EndPointScanner(config);
            endPointScanner.scan(this);
            log.info("Start completed***********************");

        }

    }

    public static void main(String... args) {

        long startTS = System.currentTimeMillis();
        try {

            LoggerUtil.enableDefaultLogger("io.xlogistx");
            int index = 0;


            String filename = args[index++];
            log.info("config file:" + filename);
            File file = IOUtil.locateFile(filename);
            HTTPServerConfig hsc = null;


            if(file != null)
                hsc = GSONUtil.fromJSON(IOUtil.inputStreamToString(file), HTTPServerConfig.class);

            log.info("" + hsc);
            log.info("" + Arrays.toString(hsc.getConnectionConfigs()));
            TaskUtil.setTaskProcessorThreadCount(hsc.getThreadPoolSize());
            NIOSocket nioSocket = new NIOSocket(TaskUtil.getDefaultTaskProcessor());
            NIOHTTPServer niohttpServer = new NIOHTTPServer(hsc, nioSocket);
            niohttpServer.start();
            log.info("After start");

        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("Usage: NIOHTTPServer server-config.json");
            System.exit(-1);
        }
        startTS = System.currentTimeMillis() - startTS;

        log.info("Start up time:" + Const.TimeInMillis.toString(startTS));

    }


}