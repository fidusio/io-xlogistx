package io.xlogistx.http;


import io.xlogistx.common.http.*;
import org.zoxweb.server.http.HTTPUtil;
import org.zoxweb.server.http.proxy.NIOProxyProtocol;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.logging.LoggerUtil;
import org.zoxweb.server.net.NIOPlainSocketFactory;
import org.zoxweb.server.net.NIOSocket;
import org.zoxweb.server.net.PlainSessionCallback;
import org.zoxweb.server.net.ssl.SSLContextInfo;
import org.zoxweb.server.net.ssl.SSLNIOSocketFactory;
import org.zoxweb.server.net.ssl.SSLSessionCallback;
import org.zoxweb.server.security.CryptoUtil;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.server.util.ReflectionUtil;
import org.zoxweb.shared.data.SimpleMessage;
import org.zoxweb.shared.http.*;
import org.zoxweb.shared.net.ConnectionConfig;
import org.zoxweb.shared.net.InetSocketAddressDAO;
import org.zoxweb.shared.util.*;

import javax.net.ssl.SSLContext;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Map;
import java.util.logging.Logger;

import static org.zoxweb.server.net.ssl.SSLContextInfo.Param.CIPHERS;
import static org.zoxweb.server.net.ssl.SSLContextInfo.Param.PROTOCOLS;

public class NIOHTTPServer
        implements DaemonController
{

    public final String NAME = ResourceManager.SINGLETON.map(ResourceManager.Resource.HTTP_SERVER, "NIOHTTPServer")
            .lookup(ResourceManager.Resource.HTTP_SERVER);
    private final InstanceCreator<PlainSessionCallback> httpIC = HTTPSession::new;

    private final InstanceCreator<SSLSessionCallback> httpsIC = HTTPSSession::new;


    public class HTTPSession
        extends PlainSessionCallback
    {
        private final HTTPProtocolHandler hph = new HTTPProtocolHandler(false);

        @Override
        public void accept(ByteBuffer inBuffer)
        {

            try
            {
                incomingData(hph, inBuffer, get());
            }
            catch (Exception e)
            {
                e.printStackTrace();
                processException(hph, get(), e);
                IOUtil.close(get(), hph);
                // we should close
            }
        }

    }

    public class HTTPSSession
            extends SSLSessionCallback
    {
        private final HTTPProtocolHandler hph = new HTTPProtocolHandler(true);
        @Override
        public void accept(ByteBuffer inBuffer)
        {
            try
            {
                incomingData(hph, inBuffer, get());
            }
            catch (Exception e)
            {
                e.printStackTrace();
                processException(hph, get(), e);
                IOUtil.close(get(), hph);
                // we should close
            }
        }
    }

    private void processException(HTTPProtocolHandler hph, OutputStream os, Exception e)
    {
        if (e instanceof HTTPCallException)
        {
            HTTPStatusCode statusCode = ((HTTPCallException) e).getStatusCode();
            if(statusCode == null)
                statusCode = HTTPStatusCode.BAD_REQUEST;
            HTTPUtil.formatResponse(HTTPUtil.formatErrorResponse(e.getMessage(), statusCode), hph.getRawResponse());

        }
        else
        {
            HTTPUtil.formatResponse(HTTPUtil.formatErrorResponse("" +e, HTTPStatusCode.BAD_REQUEST), hph.getRawResponse());
        }
        try
        {
            hph.getRawResponse().writeTo(os);
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }


    private void incomingData(HTTPProtocolHandler hph, ByteBuffer inBuffer, OutputStream os)
            throws IOException, InvocationTargetException, IllegalAccessException
    {
        //UByteArrayOutputStream resp = null;
        HTTPMessageConfigInterface hmciResponse = null;
        if (hph.parseRequest(inBuffer)) {

            if(logger.isEnabled())
                logger.getLogger().info(hph.getRequest().getURI());
            URIMap.URIMapResult<EndPointMeta> epm = endPointsManager.lookupWithPath(hph.getRequest().getURI());
            if(logger.isEnabled()) logger.getLogger().info(""+epm.result.httpEndPoint);


            if (epm != null) {
                if(logger.isEnabled())
                    logger.getLogger().info("emp:" + epm + " " + epm.path + " " + epm.result);
                // validate if method supported
                if (!epm.result.httpEndPoint.isMethodSupported(hph.getRequest().getMethod()))
                {
                    throw new HTTPCallException(hph.getRequest().getMethod() + " not supported use " +
                            Arrays.toString(epm.result.httpEndPoint.getMethods()),
                            HTTPStatusCode.METHOD_NOT_ALLOWED);
                }

                // check if instance of HTTPSessionHandler
                if (epm.result.methodHolder.getInstance() instanceof HTTPSessionHandler)
                {
                    HTTPSessionData sessionData = new HTTPSessionData(hph, os);

                    ((HTTPSessionHandler) epm.result.methodHolder.getInstance()).handle(sessionData);
                }
                else
                {

                    if (logger.isEnabled()) {
                        logger.getLogger().info("" + epm.result.methodHolder.getInstance());
                        logger.getLogger().info("" + hph.getRequest());
                        logger.getLogger().info("" + epm.path);
                    }

                    Map<String, Object> parameters = EndPointsManager.buildParameters(epm, hph.getRequest());




                    Object result = ReflectionUtil.invokeMethod(epm.result.methodHolder.getInstance(),
                            epm.result.methodHolder.getMethodAnnotations(),
                            parameters);

                    if (result != null) {

//                        if (result instanceof File) {
//
//                        }
//                        else if (result instanceof HTTPResult)
//                        {
//
//                        }
//                        else
                        {
                            hmciResponse = HTTPUtil.formatResponse(GSONUtil.toJSONDefault(result), HTTPStatusCode.OK);
                        }
                    }
                    else
                    {
                        hmciResponse = HTTPUtil.formatResponse(HTTPStatusCode.OK);
                    }
                }


            }
            else
            {
                SimpleMessage sm = new SimpleMessage();
                sm.setError(hph.getRequest().getURI() + " not found");
                hmciResponse = HTTPUtil.formatResponse(sm, HTTPStatusCode.NOT_FOUND);
            }

            // we have a response
            if (hmciResponse != null)
            {
                hmciResponse.getHeaders().add(HTTPHeader.SERVER.getName(), NAME);
                hmciResponse.getHeaders().add(HTTPConst.Headers.CONNECTION_CLOSE);

                HTTPUtil.formatResponse(hmciResponse, hph.getRawResponse()).writeTo(os);
            }

            IOUtil.close(os, hph);

        }
        else
        {
            if(logger.isEnabled())
                logger.getLogger().info("Message not complete yet");
        }
    }








    public final static LogWrapper logger = new LogWrapper(Logger.getLogger(NIOHTTPServer.class.getName())).setEnabled(false);
    private final HTTPServerConfig config;
    private NIOSocket nioSocket;
    private boolean isClosed = true;
    private EndPointsManager endPointsManager = null;


    public NIOHTTPServer(HTTPServerConfig config)
    {
        this(config,null);
    }
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
    public boolean isClosed() {
        return nioSocket.isClosed();
    }

    @Override
    public void close() throws IOException {
        nioSocket.close();
    }
    public void start() throws IOException, GeneralSecurityException {
        String msg = "";
        if (isClosed) {
            if (config != null) {
                isClosed = false;
            }

            endPointsManager = EndPointsManager.scan(getConfig());
            if(logger.isEnabled()) logger.getLogger().info("mapping completed***********************");
            if(getNIOSocket() == null)
            {
                if(getConfig().getThreadPoolSize() > 0)
                    TaskUtil.setTaskProcessorThreadCount(getConfig().getThreadPoolSize());
                nioSocket = new NIOSocket(TaskUtil.getDefaultTaskProcessor());
            }
            ConnectionConfig[] ccs = getConfig().getConnectionConfigs();


            if(logger.isEnabled()) logger.getLogger().info("Connection Configs: " + Arrays.toString(ccs));
            for(ConnectionConfig cc : ccs)
            {
                String[] schemes = cc.getSchemes();
                for (String scheme : schemes) {
                    URIScheme uriScheme = SharedUtil.lookupEnum(scheme, URIScheme.values());
                    if (uriScheme != null)
                    {
                        InetSocketAddressDAO serverAddress;
                        switch (uriScheme)
                        {
                            case HTTPS:
                                // we need to create a https server
                                logger.getLogger().info("we need to create an https server");
                                serverAddress = cc.getSocketConfig();

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
                                NVStringList protocols =((NVStringList)sslConfig.get(PROTOCOLS));
                                NVStringList ciphers =((NVStringList)sslConfig.get(CIPHERS));
                                getNIOSocket().addSeverSocket(serverAddress.getPort(),
                                        serverAddress.getBacklog(),
                                        new SSLNIOSocketFactory(new SSLContextInfo(sslContext,
                                                protocols != null && protocols.getValues().length > 0 ? protocols.getValues() : null,
                                                ciphers != null && ciphers.getValues().length > 0 ? ciphers.getValues() : null),
                                                httpsIC));
                                msg += " HTTPS @ port: " + serverAddress.getPort();
                                break;
                            case HTTP:
                                // we need to create a http server
                                logger.getLogger().info("we need to create an http server");
                                serverAddress = cc.getSocketConfig();
                                getNIOSocket().addSeverSocket(serverAddress.getPort(), serverAddress.getBacklog(), new NIOPlainSocketFactory(httpIC));
                                msg += " HTTP @ port: " + serverAddress.getPort();
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
        }
        if(!SharedStringUtil.isEmpty(msg))
            logger.getLogger().info("Services started"+msg);

        ResourceManager.SINGLETON.map("nio-http-server", this);


    }

    public static void main(String... args) {

        long startTS = System.currentTimeMillis();
        boolean noExec = false;
        try {

            LoggerUtil.enableDefaultLogger("io.xlogistx");

            ParamUtil.ParamMap parsedParam = ParamUtil.parse("=", args);
            System.out.println(parsedParam);
//            logger.setEnabled(true);
            String filename = parsedParam.stringValue("0");
            noExec = "noExec".equalsIgnoreCase(parsedParam.stringValue("1", null));
            int proxyPort = parsedParam.intValue("proxy", -1);
            if (logger.isEnabled()) logger.getLogger().info("config file:" + filename);
            File file = IOUtil.locateFile(filename);
            HTTPServerConfig hsc = null;


            if(file != null)
                hsc = GSONUtil.fromJSON(IOUtil.inputStreamToString(file), HTTPServerConfig.class);

            if(hsc == null)
                throw new IllegalArgumentException("No configuration file was defined");

            if (logger.isEnabled()) logger.getLogger().info("" + hsc);
            if (logger.isEnabled()) logger.getLogger().info("" + Arrays.toString(hsc.getConnectionConfigs()));
            if(hsc.getThreadPoolSize() > 0)
                TaskUtil.setTaskProcessorThreadCount(hsc.getThreadPoolSize());
            NIOSocket nioSocket = new NIOSocket(!noExec ? TaskUtil.getDefaultTaskProcessor() : null);
            NIOHTTPServer niohttpServer = new NIOHTTPServer(hsc, nioSocket);
            niohttpServer.start();

            if (proxyPort > 0)
            {
                // set up the proxy
                nioSocket.addSeverSocket(proxyPort, 256, new NIOProxyProtocol.NIOProxyProtocolFactory());
                logger.getLogger().info("HTTP proxy started @" + proxyPort);
            }
            logger.getLogger().info("After start");

        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("Usage: NIOHTTPServer server-config.json [noExec] [proxy=portValue]");
            System.exit(-1);
        }
        startTS = System.currentTimeMillis() - startTS;

        logger.getLogger().info("Start up time " + Const.TimeInMillis.toString(startTS) + " Use executor : " +!noExec);



    }


}