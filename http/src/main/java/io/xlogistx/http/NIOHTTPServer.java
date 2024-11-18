
package io.xlogistx.http;


import io.xlogistx.common.http.*;
import io.xlogistx.shiro.ShiroUtil;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.zoxweb.server.http.HTTPUtil;
import org.zoxweb.server.http.proxy.NIOProxyProtocol;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.logging.LoggerUtil;
import org.zoxweb.server.net.NIOSocket;
import org.zoxweb.server.net.NIOSocketHandlerFactory;
import org.zoxweb.server.net.PlainSessionCallback;
import org.zoxweb.server.net.ssl.SSLContextInfo;
import org.zoxweb.server.net.ssl.SSLNIOSocketHandlerFactory;
import org.zoxweb.server.net.ssl.SSLSessionCallback;
import org.zoxweb.server.security.CryptoUtil;
import org.zoxweb.server.task.TaskSchedulerProcessor;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.server.util.ReflectionUtil;
import org.zoxweb.shared.crypto.CryptoConst;
import org.zoxweb.shared.data.SimpleMessage;
import org.zoxweb.shared.http.*;
import org.zoxweb.shared.net.ConnectionConfig;
import org.zoxweb.shared.net.IPAddress;
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
import java.util.Map;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.function.Function;
import java.util.logging.Logger;

import static org.zoxweb.server.net.ssl.SSLContextInfo.Param.CIPHERS;
import static org.zoxweb.server.net.ssl.SSLContextInfo.Param.PROTOCOLS;

public class NIOHTTPServer
        implements DaemonController
{


    public final static LogWrapper logger = new LogWrapper(Logger.getLogger(NIOHTTPServer.class.getName())).setEnabled(false);
    private final HTTPServerConfig config;
    private NIOSocket nioSocket;
    private boolean isClosed = true;
    private volatile boolean securityManagerEnabled = false;
    private EndPointsManager endPointsManager = null;
    private final List<Function<HTTPProtocolHandler, Const.FunctionStatus>> filters = new ArrayList<>();
    public final String NAME = ResourceManager.SINGLETON.register(ResourceManager.Resource.HTTP_SERVER, "NOUFN")
            .lookupResource(ResourceManager.Resource.HTTP_SERVER);
    private final InstanceCreator<PlainSessionCallback> httpIC = HTTPSession::new;

    private final InstanceCreator<SSLSessionCallback> httpsIC = HTTPsSession::new;





    public class HTTPSession
        extends PlainSessionCallback
    {
        private final HTTPProtocolHandler hph = new HTTPProtocolHandler(false);

        @Override
        public void accept(ByteBuffer inBuffer)
        {

            try
            {
                if(hph.parseRequest(inBuffer))
                {
                    if (logger.isEnabled())
                        logger.getLogger().info("\n" + hph.getRawRequest().getDataStream().toString());
                    hph.isBusy.set(true);
                    incomingData(hph.setOutputStream(get()));
                    hph.isBusy.set(false);
                    if (logger.isEnabled()) logger.getLogger().info(SharedUtil.toCanonicalID(':', "http", getRemoteAddress().getHostAddress(), hph.getRequest() != null ? hph.getRequest().getURI() : ""));
                }
                else
                {
                    if (logger.isEnabled()) logger.getLogger().info("Message Not Complete");
                }
            }
            catch (Exception e)
            {
                if(logger.isEnabled()) e.printStackTrace();
                processException(hph, get(), e);
                IOUtil.close(hph);

                // we should close
            }
        }

    }

    public class HTTPsSession
            extends SSLSessionCallback
    {
        private final HTTPProtocolHandler hph = new HTTPProtocolHandler(true);
        @Override
        public void accept(ByteBuffer inBuffer)
        {
            try
            {
                if(hph.parseRequest(inBuffer))
                {
                    if (logger.isEnabled())
                        logger.getLogger().info("\n" + hph.getRawRequest().getDataStream().toString());
                    // we are processing a request
                    hph.isBusy.set(true);
                    incomingData(hph.setOutputStream(get()));
                    // processing finished
                    hph.isBusy.set(false);
                    if (logger.isEnabled()) logger.getLogger().info(SharedUtil.toCanonicalID(':', "http", getRemoteAddress().getHostAddress(), hph.getRequest() != null ? hph.getRequest().getURI() : ""));
                }
                else
                {
                    if (logger.isEnabled()) logger.getLogger().info("Message Not Complete");
                }
            }
            catch (Exception e)
            {
                if(logger.isEnabled()) e.printStackTrace();
                processException(hph, get(), e);
                IOUtil.close(hph);

                // we should close
            }

        }

        public void exception(Exception e)
        {
            if(logger.isEnabled()) logger.getLogger().info("" + e);
        }
    }

    private void processException(HTTPProtocolHandler hph, OutputStream os, Exception e)
    {
        e.printStackTrace();
        if(!hph.isClosed())
        {
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
                hph.getResponseStream().writeTo(os);
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }
        else
        {
            if(logger.isEnabled()) logger.getLogger().info("Channel closed can't process exception " + e);
        }
    }

   private  void securityCheck(URIMap.URIMapResult<EndPointMeta> epm,  HTTPProtocolHandler hph) throws IOException
    {
        //if(securiyManagerEnabled)
        {
            CryptoConst.AuthenticationType[] resourceAuthTypes = epm.result.httpEndPoint.authenticationTypes();


            // for performance check
            // if the resource authentication is required
            // if the resource permission  is PERM_RESOURCE_ANY
            if (ShiroUtil.isAuthenticationRequired(resourceAuthTypes) &&
                    !SharedUtil.contains(SecurityModel.PERM_RESOURCE_ANY, epm.result.httpEndPoint.permissions())) {
                HTTPAuthorization httpAuthorization = hph.getRequest().getAuthorization();
                if (logger.isEnabled())
                    logger.getLogger().info("Authorization header: " + httpAuthorization);

                if (httpAuthorization == null) {
                    HTTPMessageConfigInterface hmci = HTTPMessageConfig.createAndInit(null, hph.getRequest().getURI(), hph.getRequest().getMethod());
                    hmci.setHTTPStatusCode(HTTPStatusCode.UNAUTHORIZED);
                    hmci.getHeaders().build(HTTPConst.toHTTPHeader(HTTPHeader.CONTENT_TYPE, HTTPMediaType.APPLICATION_JSON, HTTPConst.CHARSET_UTF_8));

                    // if basic authentication is supported
                    if (SharedUtil.contains(CryptoConst.AuthenticationType.BASIC, resourceAuthTypes) ||
                            SharedUtil.contains(CryptoConst.AuthenticationType.ALL, resourceAuthTypes))
                        hmci.getHeaders().build(HTTPConst.CommonHeader.WWW_AUTHENTICATE);

                    throw new HTTPCallException("authentication missing", hmci);

                }
                else
                {
                    if (httpAuthorization instanceof HTTPAuthorizationBasic &&
                            (SharedUtil.lookupEnum(CryptoConst.AuthenticationType.BASIC.getName(), resourceAuthTypes) != null ||
                                    SharedUtil.lookupEnum(CryptoConst.AuthenticationType.ALL.getName(), resourceAuthTypes) != null)) {

                        SecurityUtils.getSubject().login(ShiroUtil.httpAuthorizationToAuthToken(httpAuthorization));
                        if (logger.isEnabled())
                            logger.getLogger().info("subject : " + SecurityUtils.getSubject().getPrincipal() + " login: " + SecurityUtils.getSubject().isAuthenticated());

                        if (!ShiroUtil.isAuthorizedCheckPoint(epm.result.httpEndPoint)) {
//                        HTTPMessageConfigInterface hmci = HTTPMessageConfig.createAndInit(null, hph.getRequest().getURI(), hph.getRequest().getMethod());
//                        hmci.setHTTPStatusCode(HTTPStatusCode.UNAUTHORIZED);
//                        hmci.getHeaders().build(HTTPConst.toHTTPHeader(HTTPHeader.CONTENT_TYPE, HTTPMediaType.APPLICATION_JSON, HTTPConst.CHARSET_UTF_8));
                            throw new HTTPCallException("Role Or Permission, Authorization Access Denied", HTTPStatusCode.UNAUTHORIZED);
                        }
                    } else {
                        if (logger.isEnabled()) logger.getLogger().info("*********** NO LOGIN **********");
                    }
                }
            }
        }
    }

    private void incomingData(HTTPProtocolHandler hph)
            throws IOException, InvocationTargetException, IllegalAccessException
    {


        try
        {


            //HTTPMessageConfigInterface hmciResponse = null;


                if (logger.isEnabled()) {
                    logger.getLogger().info(hph.getRequest().getURI());
                    logger.getLogger().info("HTTP status code: " + hph.getRequest().getHTTPStatusCode());
                    logger.getLogger().info("" + hph.getRequest().getHeaders());
                }
                URIMap.URIMapResult<EndPointMeta> epm = getEndPointsManager().lookupWithPath(hph.getRequest().getURI());
                if (logger.isEnabled()) logger.getLogger().info("" + epm.result.httpEndPoint);


                if (epm != null)
                {
                    if (logger.isEnabled())
                        logger.getLogger().info("emp:" + epm + " " + epm.path + " " + epm.result);
                    // validate if method supported
                    if (!epm.result.httpEndPoint.isMethodSupported(hph.getRequest().getMethod())) {
                        throw new HTTPCallException(hph.getRequest().getMethod() + " not supported use " +
                                Arrays.toString(epm.result.httpEndPoint.getMethods()),
                                HTTPStatusCode.METHOD_NOT_ALLOWED);
                    }


                    // security check
                    securityCheck(epm, hph);
                    // check if instance of HTTPSessionHandler
                    if (epm.result.methodHolder.getInstance() instanceof HTTPSessionHandler)
                    {
                        ((HTTPSessionHandler) epm.result.methodHolder.getInstance()).handle(hph);
                    }
                    else
                    {
                        if (logger.isEnabled()) {
                            logger.getLogger().info("" + epm.result.methodHolder.getInstance());
                            logger.getLogger().info("" + hph.getRequest());
                            logger.getLogger().info(epm.path);
                        }

                        Map<String, Object> parameters = getEndPointsManager().buildParameters(epm, hph.getRequest());
                        Object result = ReflectionUtil.invokeMethod(epm.result.methodHolder.getInstance(),
                                epm.result.methodHolder.getMethodAnnotations(),
                                parameters);

                        HTTPMessageConfigInterface hmci = hph.buildResponse(epm.result.httpEndPoint.getOutputContentType(), result, HTTPStatusCode.OK,
                                        HTTPConst.CommonHeader.X_CONTENT_TYPE_OPTIONS_NO_SNIFF,
                                        HTTPConst.CommonHeader.NO_CACHE_CONTROL,
                                        HTTPConst.CommonHeader.EXPIRES_ZERO);

                        HTTPUtil.formatResponse(hmci, hph.getResponseStream())
                                .writeTo(hph.getOutputStream());
                        // message complete and sent to client
                    }
                }
                else
                {
                    // error status uri map not found
                    SimpleMessage sm = new SimpleMessage();
                    sm.setError(hph.getRequest().getURI() + " not found");
                    sm.setStatus(HTTPStatusCode.NOT_FOUND.CODE);


                    HTTPMessageConfigInterface hmci = hph.buildResponse(HTTPConst.CommonHeader.CONTENT_TYPE_JSON_UTF8.getValue(),sm, HTTPStatusCode.NOT_FOUND,
                            HTTPConst.CommonHeader.NO_CACHE_CONTROL,
                            HTTPConst.CommonHeader.EXPIRES_ZERO);
                    HTTPUtil.formatResponse(hmci, hph.getResponseStream())
                            .writeTo(hph.getOutputStream());
                }

                // we have a response
//                if (hmciResponse != null) {
//                    hmciResponse.getHeaders().build(HTTPHeader.SERVER.getName(), NAME).
//                    build(HTTPConst.CommonHeader.CONNECTION_CLOSE).
//                    build(HTTPConst.CommonHeader.X_CONTENT_TYPE_OPTIONS_NO_SNIFF);
//
//                    HTTPProtocolHandler.preResponse(hph, hmciResponse);
//
//                    HTTPUtil.formatResponse(hmciResponse, hph.getRawResponse()).writeTo(hph.getOutputStream());
//                }

                if(!hph.reset())
                    IOUtil.close(hph);
                //hph.postResponse(hph);

//                if (hph.getKeepAlive() != null && !hph.getKeepAlive().isExpired())
//                {
//                    System.out.println(hph.getKeepAlive().hashCode() + " " + hph.getKeepAlive().getUsageCounter() + " " + hph.getOutputStream());
//                    ///System.out.println(hmciResponse.getHeaders().lookup(HTTPHeader.KEEP_ALIVE));
//                    hph.reset();
//                }
//                else
//                    IOUtil.close(hph);
        }
        finally
        {
            SecurityUtils.getSubject().logout();
        }
    }













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
        // very crucial step must be executed first
        TaskUtil.registerMainThread();
        String msg = "";
        NVGenericMap keepAliveConfig = null;
        if (isClosed) {
            if (config != null) {
                isClosed = false;
            }


            String shiroConfig = config.getProperties().lookupValue("shiro.config");
            // shiro registration
            if(shiroConfig != null)
            {
                try
                {
                    SecurityUtils.setSecurityManager(ShiroUtil.loadSecurityManager(shiroConfig));

//                    IniRealm iniRealm = ShiroUtil.getRealm(IniRealm.class);
//                    if (iniRealm != null) {
//                        // TODO must be replaced
//                        iniRealm.setCredentialsMatcher(new PasswordCredentialsMatcher());
//                        logger.getLogger().info("Credential matcher set for realm:" + iniRealm);
//                    }
                    logger.getLogger().info("shiro security manager loaded " + SecurityUtils.getSecurityManager());
                    securityManagerEnabled = true;
                }
                catch(Exception e)
                {
                    e.printStackTrace();
                }
            }

            keepAliveConfig = config.getProperties().lookup("keep-alive");
            logger.getLogger().info("Keep-Alive Config: " + keepAliveConfig);
            if(keepAliveConfig != null)
            {
                GetNameValue<?> timeout = keepAliveConfig.lookup("time_out");
                if (timeout.getValue() instanceof String)
                {
                    long timeoutInMillis = Const.TimeInMillis.toMillis((String)timeout.getValue());
                    keepAliveConfig.add(new NVLong("time_out", timeoutInMillis));
                }
            }


            endPointsManager = EndPointsManager.scan(getConfig());
            if(logger.isEnabled()) logger.getLogger().info("mapping completed***********************");
            if(getNIOSocket() == null)
            {
                if(getConfig().getThreadPoolSize() > 0)
                    TaskUtil.setTaskProcessorThreadCount(getConfig().getThreadPoolSize());
                nioSocket = new NIOSocket(TaskUtil.defaultTaskProcessor(), TaskUtil.defaultTaskScheduler());
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
                        IPAddress serverAddress;
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
                                SSLNIOSocketHandlerFactory sslnioSocketHandlerFactory = new SSLNIOSocketHandlerFactory(new SSLContextInfo(sslContext,
                                        protocols != null && protocols.getValues().length > 0 ? protocols.getValues() : null,
                                        ciphers != null && ciphers.getValues().length > 0 ? ciphers.getValues() : null),
                                        httpsIC);
                                if (sslConfig.get("simple_state_machine") != null)
                                {
                                    NVBoolean ssm = (NVBoolean) sslConfig.get("simple_state_machine");
                                    sslnioSocketHandlerFactory.getProperties().add(ssm);
                                    logger.getLogger().info("" + ssm);
                                    NVGenericMap sysInfo = ResourceManager.lookupResource(ResourceManager.Resource.SYSTEM_INFO);
                                    if(ssm.getValue())
                                    {
                                        sysInfo.add("ssl_state_machine_type", "CustomSSLStateMachine");
                                    }
                                    else
                                    {
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



        if(!SUS.isEmpty(msg))
            logger.getLogger().info("Services started"+msg);




        ResourceManager.SINGLETON.register("nio-http-server", this);
        if(keepAliveConfig != null)
            ResourceManager.SINGLETON.register("keep-alive-config", keepAliveConfig);


    }

    public EndPointsManager getEndPointsManager()
    {
        return endPointsManager;
    }

    public static void main(String... args) {

        long startTS = System.currentTimeMillis();
        Const.ExecPool execPool = Const.ExecPool.DEFAULT;
        TaskSchedulerProcessor tsp = null;
        try {

            LoggerUtil.enableDefaultLogger("io.xlogistx");

            ParamUtil.ParamMap parsedParam = ParamUtil.parse("=", args);
            System.out.println(parsedParam);
//            logger.setEnabled(true);
            String filename = parsedParam.stringValue("0");
            execPool = parsedParam.parameterExists("exec") ? parsedParam.enumValue("exec", Const.ExecPool.values()) : Const.ExecPool.DEFAULT;//"noExec".equalsIgnoreCase(parsedParam.stringValue("1", null));
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

            Executor exec = null;
            if(execPool != null)
            {
                switch (execPool)
                {

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

            if (proxyPort > 0)
            {
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