
package io.xlogistx.http;


import io.xlogistx.common.http.*;
import io.xlogistx.http.websocket.WSHandler;
import io.xlogistx.shiro.ShiroInvoker;
import io.xlogistx.shiro.ShiroSession;
import io.xlogistx.shiro.ShiroUtil;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;
import org.zoxweb.server.http.HTTPUtil;
import org.zoxweb.server.http.proxy.NIOProxyProtocol;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.net.BaseSessionCallback;
import org.zoxweb.server.net.NIOSocket;
import org.zoxweb.server.net.NIOSocketHandlerFactory;
import org.zoxweb.server.net.PlainSessionCallback;
import org.zoxweb.server.net.ssl.SSLContextInfo;
import org.zoxweb.server.net.ssl.SSLNIOSocketHandlerFactory;
import org.zoxweb.server.net.ssl.SSLSessionCallback;
import org.zoxweb.server.security.SecUtil;
import org.zoxweb.server.task.TaskSchedulerProcessor;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.shared.annotation.SecurityProp;
import org.zoxweb.shared.crypto.CryptoConst;
import org.zoxweb.shared.data.SimpleMessage;
import org.zoxweb.shared.http.*;
import org.zoxweb.shared.net.ConnectionConfig;
import org.zoxweb.shared.net.IPAddress;
import org.zoxweb.shared.protocol.ProtoSession;
import org.zoxweb.shared.security.model.SecurityModel;
import org.zoxweb.shared.util.*;

import javax.net.ssl.SSLContext;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.function.Function;

import static org.zoxweb.server.net.ssl.SSLContextInfo.Param.CIPHERS;
import static org.zoxweb.server.net.ssl.SSLContextInfo.Param.PROTOCOLS;
import static org.zoxweb.shared.util.InstanceFactory.InstanceCreator;


public class NIOHTTPServer
        implements DaemonController {
    public static final String VERSION = "1.1.9";

    public final static LogWrapper logger = new LogWrapper(NIOHTTPServer.class).setEnabled(false);
    private final HTTPServerConfig config;
    private NIOSocket nioSocket;
    private boolean isClosed = true;
    private volatile boolean securityManagerEnabled = false;
    private EndPointsManager endPointsManager = null;
    private final List<Function<HTTPProtocolHandler, Const.FunctionStatus>> filters = new ArrayList<>();
    public final String NAME = ResourceManager.SINGLETON.register(ResourceManager.Resource.HTTP_SERVER, "NOUFN")
            .lookupResource(ResourceManager.Resource.HTTP_SERVER);
    private volatile KAConfig kaConfig = null;
    private final InstanceFactory.InstanceCreator<PlainSessionCallback> httpIC = HTTPSession::new;

    private final InstanceCreator<SSLSessionCallback> httpsIC = HTTPsSession::new;


    public class HTTPSession
            extends PlainSessionCallback {
        protected final HTTPProtocolHandler hph = new HTTPProtocolHandler(URIScheme.HTTP, kaConfig);

        @Override
        public void accept(ByteBuffer inBuffer) {

            try {
                if (hph.parseRequest(inBuffer)) {
                    if (logger.isEnabled())
                        logger.getLogger().info("\n" + hph.getRawRequest().getDataStream().toString());

                    incomingData(this, getEndPointsManager(), hph.setOutputStream(get()));
                    if (hph.isExpired())
                        IOUtil.close(this);

                    if (logger.isEnabled())
                        logger.getLogger().info(SharedUtil.toCanonicalID(':', "http", getRemoteAddress().getHostAddress(), hph.getRequest(true) != null ? hph.getRequest(true).getURI() : ""));
                } else {
                    if (logger.isEnabled()) logger.getLogger().info("Message Not Complete");
                }
            } catch (Exception e) {
                if (logger.isEnabled()) e.printStackTrace();
                processException(hph, get(), e);
                IOUtil.close(this);
                // we should close
            }

        }

        /**
         * Closes this stream and releases any system resources associated
         * with it. If the stream is already closed then invoking this
         * method has no effect.
         *
         * <p> As noted in {@link AutoCloseable#close()}, cases where the
         * close may fail require careful attention. It is strongly advised
         * to relinquish the underlying resources and to internally
         * <em>mark</em> the {@code Closeable} as closed, prior to throwing
         * the {@code IOException}.
         *
         * @throws IOException if an I/O error occurs
         */
        @Override
        public void close() throws IOException {
            IOUtil.close(hph, protocolHandler);


        }

        @Override
        public boolean isClosed() {
            return hph.isClosed();
        }
    }

    public class HTTPsSession
            extends SSLSessionCallback {
        protected final HTTPProtocolHandler hph = new HTTPProtocolHandler(URIScheme.HTTPS, kaConfig);

        @Override
        public void accept(ByteBuffer inBuffer) {
            try {
                if (hph.parseRequest(inBuffer)) {
                    if (logger.isEnabled())
                        logger.getLogger().info("\n" + hph.getRawRequest().getDataStream().toString());
                    // we are processing a request

                    incomingData(this, getEndPointsManager(), hph.setOutputStream(get()));
                    // processing finished
                    if (hph.isExpired())
                        IOUtil.close(this);

                    if (logger.isEnabled())
                        logger.getLogger().info(SharedUtil.toCanonicalID(':', "http", getRemoteAddress().getHostAddress(), hph.getRequest(true) != null ? hph.getRequest(true).getURI() : ""));
                } else {
                    if (logger.isEnabled()) logger.getLogger().info("Message Not Complete");
                }
            } catch (Exception e) {
                if (logger.isEnabled()) e.printStackTrace();
                processException(hph, get(), e);
                IOUtil.close(this);
                // we should close
            }


        }

        public void exception(Exception e) {
            if (logger.isEnabled()) logger.getLogger().info("" + e);
        }

        /**
         * Closes this stream and releases any system resources associated
         * with it. If the stream is already closed then invoking this
         * method has no effect.
         *
         * <p> As noted in {@link AutoCloseable#close()}, cases where the
         * close may fail require careful attention. It is strongly advised
         * to relinquish the underlying resources and to internally
         * <em>mark</em> the {@code Closeable} as closed, prior to throwing
         * the {@code IOException}.
         *
         * @throws IOException if an I/O error occurs
         */
        @Override
        public void close() throws IOException {
            IOUtil.close(hph, protocolHandler);
        }

        @Override
        public boolean isClosed() {
            return hph.isClosed();
        }
    }

    private void processException(HTTPProtocolHandler hph, OutputStream os, Exception e) {
        if (!hph.isClosed() && hph.isHTTPProtocol()) {
            try {


                if (e instanceof HTTPCallException) {

                    HTTPUtil.formatErrorResponse((HTTPCallException) e, hph.getResponseStream(),
                            HTTPHeader.CACHE_CONTROL.toHTTPHeader(HTTPConst.HTTPValue.NO_STORE),
                            HTTPConst.CommonHeader.EXPIRES_ZERO);
                } else if (e instanceof AuthenticationException) {
                    HTTPUtil.formatResponse(HTTPUtil.buildErrorResponse(e.getMessage() != null ? e.getMessage() : e.toString(), HTTPStatusCode.UNAUTHORIZED), hph.getResponseStream(),
                            HTTPHeader.CACHE_CONTROL.toHTTPHeader(HTTPConst.HTTPValue.NO_STORE),
                            HTTPConst.CommonHeader.EXPIRES_ZERO);
                } else {
                    HTTPUtil.formatResponse(HTTPUtil.buildErrorResponse("" + e, HTTPStatusCode.BAD_REQUEST), hph.getResponseStream(),
                            HTTPHeader.CACHE_CONTROL.toHTTPHeader(HTTPConst.HTTPValue.NO_STORE),
                            HTTPConst.CommonHeader.EXPIRES_ZERO);
                }
                try {
                    //logger.getLogger().info(hph.getResponseStream().toString());
                    hph.getResponseStream(true).writeTo(os);
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        } else {
            if (logger.isEnabled()) logger.getLogger().info("Channel closed can't process exception " + e);
        }

    }

    private static void securityCheck(URIMap.URIMapResult<EndPointMeta> epm, HTTPProtocolHandler hph) throws IOException {


        CryptoConst.AuthenticationType[] resourceAuthTypes = epm.result.httpEndPoint.authenticationTypes();
        if (logger.isEnabled())
            logger.getLogger().info("Authentication supported: " + Arrays.toString(resourceAuthTypes));

        // for performance check
        // if the resource authentication is required
        // if the resource permission  is PERM_RESOURCE_ANY
        if (ShiroUtil.isAuthenticationRequired(resourceAuthTypes) &&
                !SharedUtil.contains(SecurityModel.PERM_RESOURCE_ANY, epm.result.httpEndPoint.permissions())) {
            HTTPAuthorization httpAuthorization = hph.getRequest(true).getAuthorization();
            if (logger.isEnabled())
                logger.getLogger().info("Authorization header: " + httpAuthorization);

            if (httpAuthorization == null) {
                HTTPMessageConfigInterface hmci = HTTPMessageConfig.createAndInit(null, hph.getRequest(true).getURI(), hph.getRequest(true).getMethod());
                hmci.setHTTPStatusCode(HTTPStatusCode.UNAUTHORIZED);
                hmci.getHeaders().build(HTTPConst.toHTTPHeader(HTTPHeader.CONTENT_TYPE, HTTPMediaType.APPLICATION_JSON, HTTPConst.CHARSET_UTF_8));

                // if basic authentication is supported
                if (SharedUtil.contains(CryptoConst.AuthenticationType.BASIC, resourceAuthTypes) ||
                        SharedUtil.contains(CryptoConst.AuthenticationType.ALL, resourceAuthTypes))
                    hmci.getHeaders().build(HTTPConst.CommonHeader.WWW_AUTHENTICATE);


                if (logger.isEnabled())
                    logger.getLogger().info("Error response: " + hmci + "\n" + HTTPConst.CommonHeader.WWW_AUTHENTICATE);
                throw new HTTPCallException("authentication missing", hmci);

            } else {
                if (httpAuthorization instanceof HTTPAuthorizationBasic &&
                        (SharedUtil.lookupEnum(CryptoConst.AuthenticationType.BASIC.getName(), resourceAuthTypes) != null ||
                                SharedUtil.lookupEnum(CryptoConst.AuthenticationType.ALL.getName(), resourceAuthTypes) != null)) {

                    // need to check session HERE
                    ProtoSession<?, Subject> protoSession = hph.getConnectionSession();
                    if (protoSession != null) {
                        if (protoSession.getSubjectID().isAuthenticated()) {
                            // we need to swap subject here
                            //ThreadContext.bind(protoSession.getSubjectID());
                            protoSession.attach();
                        }
                    }

                    if (!ShiroUtil.subject().isAuthenticated()) {
                        SecurityUtils.getSubject().login(ShiroUtil.httpAuthorizationToAuthToken(httpAuthorization));
                        if (logger.isEnabled())
                            logger.getLogger().info("subject : " + SecurityUtils.getSubject().getPrincipal() + " login: " + SecurityUtils.getSubject().isAuthenticated());
                    }

                    if (!ShiroUtil.isAuthorizedCheckPoint(epm.result.httpEndPoint)) {
//                        HTTPMessageConfigInterface hmci = HTTPMessageConfig.createAndInit(null, hph.getRequest().getURI(), hph.getRequest().getMethod());
//                        hmci.setHTTPStatusCode(HTTPStatusCode.UNAUTHORIZED);
//                        hmci.getHeaders().build(HTTPConst.toHTTPHeader(HTTPHeader.CONTENT_TYPE, HTTPMediaType.APPLICATION_JSON, HTTPConst.CHARSET_UTF_8));
                        throw new HTTPCallException("Role Or Permission, Authorization Access Denied", HTTPStatusCode.UNAUTHORIZED);
                    }

                    if (hph.getRequest(true).isTransferChunked() && protoSession == null) {

//                        Subject currentSubject = ShiroUtil.subject();
//                        protoSession = new ShiroSession(currentSubject, null, hph::isRequestComplete);
                        hph.setConnectionSession(new ShiroSession<>(ShiroUtil.subject(), null, hph::isRequestComplete));
                        logger.getLogger().info("TRANSFER-CHUNKED subject : " + SecurityUtils.getSubject().getPrincipal() + " login: " + SecurityUtils.getSubject().isAuthenticated());
                    }

                    // need to add session here
                } else {
                    if (logger.isEnabled()) logger.getLogger().info("*********** NO LOGIN **********");
                }
            }
        }

    }

    private static void incomingData(BaseSessionCallback<?> session, EndPointsManager endPointsManager, HTTPProtocolHandler hph)
            throws IOException, InvocationTargetException, IllegalAccessException {


        switch (hph.getProtocol()) {
            case HTTPS:
            case HTTP:
                // HTTP protocol processing
            {

                try {

                    if (logger.isEnabled()) {
                        logger.getLogger().info(hph.getRequest(true).getURI());
                        logger.getLogger().info("HTTP status code: " + hph.getRequest(true).getHTTPStatusCode());
                        logger.getLogger().info("" + hph.getRequest(true).getHeaders());
                    }

                    URIMap.URIMapResult<EndPointMeta> epm = endPointsManager.lookupWithPath(hph
                            .getRequest(true)
                            .getURI());
                    if (logger.isEnabled()) logger.getLogger().info("" + epm.result.httpEndPoint);

                    if (epm != null) {
                        if (logger.isEnabled())
                            logger.getLogger().info("emp:" + epm + " " + epm.path + " " + epm.result);
                        // validate if method supported
                        HTTPMethod toCheck = hph.getRequest(true).getMethod();
                        if (!epm.result.httpEndPoint.isHTTPMethodSupported(toCheck)) {
                            throw new HTTPCallException(toCheck + " not supported use " +
                                    Arrays.toString(epm.result.httpEndPoint.getHTTPMethods()),
                                    HTTPStatusCode.METHOD_NOT_ALLOWED);
                        }


                        // +++ Security check +++++++++++++++++++++
                        securityCheck(epm, hph);
                        //_________________________________________

                        // check if instance of HTTPSessionHandler
                        if (epm.result.methodContainer.instance instanceof HTTPRawHandler) {
                            ((HTTPRawHandler) epm.result.methodContainer.instance).handle(hph);
                        } else if (hph.isRequestComplete()) {
                            if (logger.isEnabled()) {
                                logger.getLogger().info("" + epm.result.methodContainer.instance);
                                logger.getLogger().info("" + hph.getRequest());
                                logger.getLogger().info(epm.path);
                            }

//                            Map<String, Object> parameters = endPointsManager.buildParameters(epm, hph.getRequest());
                            Object result = epm.result.methodContainer.invoke(endPointsManager.buildParameters(epm, hph.getRequest()));
//                                    ReflectionUtil.invokeMethod(epm.result.methodHolder.instance,
//                                    epm.result.methodHolder.methodAnnotations,
//                                    parameters);

                            HTTPMessageConfigInterface hmci = hph.buildResponse(epm.result.httpEndPoint.getOutputContentType(), result, HTTPStatusCode.OK,
                                    HTTPConst.CommonHeader.X_CONTENT_TYPE_OPTIONS_NO_SNIFF,
                                    HTTPConst.CommonHeader.NO_CACHE_CONTROL,
                                    HTTPConst.CommonHeader.EXPIRES_ZERO);

                            HTTPUtil.writeHTTPResponse(hph.getResponseStream(), hmci, hph.getOutputStream());
                        }
                    } else {
                        // error status uri map not found
                        SimpleMessage sm = new SimpleMessage();
                        sm.setError(hph.getRequest(true).getURI() + " not found");
                        sm.setStatus(HTTPStatusCode.NOT_FOUND.CODE);


                        HTTPMessageConfigInterface hmci = hph.buildResponse(HTTPConst.CommonHeader.CONTENT_TYPE_JSON_UTF8.getValue(), sm, HTTPStatusCode.NOT_FOUND,
                                HTTPConst.CommonHeader.NO_CACHE_CONTROL,
                                HTTPConst.CommonHeader.EXPIRES_ZERO);

                        HTTPUtil.writeHTTPResponse(hph.getResponseStream(), hmci, hph.getOutputStream());
                    }


//                        if (!hph.reset() && hph.isHTTPProtocol())
//                            IOUtil.close(hph);
//                        if (hph.getRequest().isTransferChunked())
//                            if (hph.isRequestComplete())
//                                hph.reset();
//                        else
//                            hph.reset();

                    if (hph.isRequestComplete() && hph.getConnectionSession() == null) {
                        hph.reset();
                        if (logger.isEnabled()) logger.getLogger().info("hph reset invoked");
                    }
                } finally {
                    // very important check DO NOT REMOVE since the protocol can switch from HTTP get to
                    // websocket
                    if (hph.isHTTPProtocol()) {

                        ProtoSession<?, ?> protoSession = hph.getConnectionSession();
                        if (protoSession != null) {


                            if (protoSession.canClose()) {
                                protoSession.close();
                                hph.reset();
                            }
                            ThreadContext.unbindSubject();

                        } else {
                            ShiroUtil.subject().logout();
                        }

                    }
                }
            }
            break;
            case WSS:
            case WS:
                ((HTTPRawHandler) hph.getEndPointBean()).handle(hph);
                // web socket processing here
                break;
        }

    }


    public NIOHTTPServer(HTTPServerConfig config) {
        this(config, null);
    }

    public NIOHTTPServer(HTTPServerConfig config, NIOSocket nioSocket) {
        SUS.checkIfNulls("HTTPServerConfig null", config);
        this.config = config;
        this.nioSocket = nioSocket;
    }

    public NIOSocket getNIOSocket() {
        return nioSocket;
    }

    public HTTPServerConfig getConfig() {
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

        TaskUtil.registerMainThread();
        String msg = "";
        NVGenericMap keepAliveConfig = null;
        if (isClosed) {
            if (config != null) {
                isClosed = false;
            }


            String shiroConfig = config.getProperties().lookupValue("shiro.config");
            // shiro registration
            if (shiroConfig != null) {
                try {
                    SecurityUtils.setSecurityManager(ShiroUtil.loadSecurityManager(shiroConfig));

//                    IniRealm iniRealm = ShiroUtil.getRealm(IniRealm.class);
//                    if (iniRealm != null) {
//                        // TODO must be replaced
//                        iniRealm.setCredentialsMatcher(new PasswordCredentialsMatcher());
//                        logger.getLogger().info("Credential matcher set for realm:" + iniRealm);
//                    }
                    logger.getLogger().info("shiro security manager loaded " + SecurityUtils.getSecurityManager());
                    securityManagerEnabled = true;
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }

            // keep alive configuration
            keepAliveConfig = config.getProperties().lookup("keep-alive");
            logger.getLogger().info("Keep-Alive Config: " + keepAliveConfig);
            if (keepAliveConfig != null) {
                GetNameValue<?> time_out = keepAliveConfig.lookup("time_out");
                if (time_out.getValue() instanceof String) {
                    long timeoutInMillis = Const.TimeInMillis.toMillis((String) time_out.getValue());
                    keepAliveConfig.add(new NVLong("time_out", timeoutInMillis));
                }
                int max = keepAliveConfig.getValue("maximum");
                long timeout = keepAliveConfig.getValue("time_out");
                kaConfig = new KAConfig(max, timeout);
                logger.getLogger().info("KAConfig: " + kaConfig);
            }

//            String startupBeanName = config.getProperties().lookupValue("on-startup.bean");
//            String shutdownBeanName = config.getProperties().lookupValue("on-shutdown.bean");
//            logger.getLogger().info("startup bean: " + startupBeanName + " shutdown bean: " + shutdownBeanName);

            // scan endpoints
            endPointsManager = EndPointsManager.scan(getConfig(), (a) -> new WSHandler((String) a[0], (SecurityProp) a[1], (WSCache) a[2], a[3]), ShiroInvoker.SINGLETON);

            if(endPointsManager.getOnShutdown() != null)
            {
                ResourceManager.SINGLETON.register("on-shutdown", endPointsManager.getOnShutdown());
            }

            if(endPointsManager.getOnStartup() != null)
            {
                ResourceManager.SINGLETON.register("on-startup", endPointsManager.getOnStartup());
            }

            if (logger.isEnabled()) logger.getLogger().info("mapping completed***********************");

            EndpointsUtil.SINGLETON.startup();

            // NISocket
            if (getNIOSocket() == null) {
                if (getConfig().getThreadPoolSize() > 0)
                    TaskUtil.setTaskProcessorThreadCount(getConfig().getThreadPoolSize());
                nioSocket = new NIOSocket(TaskUtil.defaultTaskProcessor(), TaskUtil.defaultTaskScheduler());
            }
            ConnectionConfig[] ccs = getConfig().getConnectionConfigs();


            if (logger.isEnabled()) logger.getLogger().info("Connection Configs: " + Arrays.toString(ccs));
            // connection configuration
            for (ConnectionConfig cc : ccs) {
                String[] schemes = cc.getSchemes();
                for (String scheme : schemes) {
                    URIScheme uriScheme = SharedUtil.lookupEnum(scheme, URIScheme.values());
                    if (uriScheme != null) {
                        IPAddress serverAddress;
                        switch (uriScheme) {
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
                                SSLContext sslContext = SecUtil.SINGLETON.initSSLContext(protocol, null, IOUtil.locateFile(sslConfig.getValue("keystore_file")),
                                        sslConfig.getValue("keystore_type"),
                                        ksPassword.toCharArray(),
                                        aliasPassword != null ? aliasPassword.toCharArray() : null,
                                        trustStoreFilename != null ? IOUtil.locateFile(trustStoreFilename) : null,
                                        trustStorePassword != null ? trustStorePassword.toCharArray() : null);
                                NVStringList protocols = ((NVStringList) sslConfig.get(PROTOCOLS));
                                NVStringList ciphers = ((NVStringList) sslConfig.get(CIPHERS));
                                SSLNIOSocketHandlerFactory sslnioSocketHandlerFactory = new SSLNIOSocketHandlerFactory(new SSLContextInfo(sslContext,
                                        protocols != null && protocols.getValues().length > 0 ? protocols.getValues() : null,
                                        ciphers != null && ciphers.getValues().length > 0 ? ciphers.getValues() : null),
                                        httpsIC);
                                if (sslConfig.get("simple_state_machine") != null) {
                                    NVBoolean ssm = (NVBoolean) sslConfig.get("simple_state_machine");
                                    sslnioSocketHandlerFactory.getProperties().add(ssm);
                                    logger.getLogger().info("" + ssm);
                                    NVGenericMap sysInfo = ResourceManager.lookupResource(ResourceManager.Resource.SYSTEM_INFO);
                                    if (ssm.getValue()) {
                                        sysInfo.add("ssl_state_machine_type", "CustomSSLStateMachine");
                                    } else {
                                        sysInfo.add("ssl_state_machine_type", "SSLStateMachine");
                                    }
                                }
                                getNIOSocket().addServerSocket(serverAddress,
                                        serverAddress.getBacklog(),
                                        sslnioSocketHandlerFactory);
                                msg += " HTTPS @" + serverAddress;
                                break;
                            case HTTP:
                                // we need to create a http server
                                logger.getLogger().info("we need to create an http server");
                                serverAddress = cc.getSocketConfig();
                                getNIOSocket().addServerSocket(serverAddress, serverAddress.getBacklog(), new NIOSocketHandlerFactory(httpIC));
                                msg += " HTTP @" + serverAddress;
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


        if (!SUS.isEmpty(msg))
            logger.getLogger().info("Services started" + msg);


        ResourceManager.SINGLETON.register("nio-http-server", this);
        if (keepAliveConfig != null)
            ResourceManager.SINGLETON.register("keep-alive-config", keepAliveConfig);


    }

    public EndPointsManager getEndPointsManager() {
        return endPointsManager;
    }

    public static void main(String... args) {

        long startTS = System.currentTimeMillis();
        Const.ExecPool execPool = Const.ExecPool.DEFAULT;
        TaskSchedulerProcessor tsp = null;
        try {


            ParamUtil.ParamMap parsedParam = ParamUtil.parse("=", args);
            System.out.println(parsedParam);
//            logger.setEnabled(true);
            String filename = parsedParam.stringValue("0");
            execPool = parsedParam.parameterExists("exec") ? parsedParam.enumValue("exec", Const.ExecPool.values()) : Const.ExecPool.DEFAULT;//"noExec".equalsIgnoreCase(parsedParam.stringValue("1", null));
            int proxyPort = parsedParam.intValue("proxy", -1);
            if (logger.isEnabled()) logger.getLogger().info("config file:" + filename);
            File file = IOUtil.locateFile(filename);
            HTTPServerConfig hsc = null;


            if (file != null)
                hsc = GSONUtil.fromJSON(IOUtil.inputStreamToString(file), HTTPServerConfig.class);

            if (hsc == null)
                throw new IllegalArgumentException("No configuration file was defined");

            if (logger.isEnabled()) logger.getLogger().info("" + hsc);
            if (logger.isEnabled()) logger.getLogger().info("" + Arrays.toString(hsc.getConnectionConfigs()));
            if (hsc.getThreadPoolSize() > 0)
                TaskUtil.setTaskProcessorThreadCount(hsc.getThreadPoolSize());

            Executor exec = null;
            if (execPool != null) {
                switch (execPool) {

                    case DEFAULT:
                        exec = TaskUtil.defaultTaskProcessor();

                        break;
                    case JAVA:
                        exec = Executors.newFixedThreadPool(64);

                        break;
                }
            }

            NIOSocket nioSocket = new NIOSocket(exec, TaskUtil.defaultTaskScheduler());
            NIOHTTPServer niohttpServer = new NIOHTTPServer(hsc, nioSocket);
            niohttpServer.start();

            if (proxyPort > 0) {
                // set up the proxy
                nioSocket.addServerSocket(proxyPort, 256, new NIOProxyProtocol.NIOProxyProtocolFactory());
                logger.getLogger().info("HTTP proxy started @" + proxyPort);
            }
            logger.getLogger().info("After start");

        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("Usage: NIOHTTPServer server-config.json [exec=[no_exec, default, java]] [proxy=portValue]");
            System.exit(-1);
        }
        startTS = System.currentTimeMillis() - startTS;

        logger.getLogger().info("Start up time " + Const.TimeInMillis.toString(startTS) + " Use executor : " + execPool);


    }


}