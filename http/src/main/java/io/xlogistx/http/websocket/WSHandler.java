package io.xlogistx.http.websocket;

import io.xlogistx.common.http.HTTPProtocolHandler;
import io.xlogistx.common.http.HTTPRawHandler;
import io.xlogistx.common.http.WSCache;
import io.xlogistx.shiro.ShiroInvoker;
import io.xlogistx.shiro.ShiroSession;
import io.xlogistx.shiro.ShiroUtil;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.util.ThreadContext;
import org.zoxweb.server.http.HTTPHeaderParser;
import org.zoxweb.server.http.HTTPUtil;
import org.zoxweb.server.io.ByteBufferUtil;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.security.HashUtil;
import org.zoxweb.shared.annotation.EndPointProp;
import org.zoxweb.shared.annotation.ParamProp;
import org.zoxweb.shared.annotation.SecurityProp;
import org.zoxweb.shared.http.*;
import org.zoxweb.shared.util.*;

import javax.websocket.Session;
import java.io.IOException;
import java.lang.reflect.Method;
import java.security.NoSuchAlgorithmException;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class WSHandler
        implements HTTPRawHandler {

    public static final LogWrapper log = new LogWrapper(WSHandler.class).setEnabled(false);

    private final String uri;
    private final Object bean;
    private final SecurityProp securityProp;
    private final WSCache methodCache;

    private final Set<Session> sessionSet = ConcurrentHashMap.newKeySet();

    //private static final  WSCache.WSMethodType[] BINARY_TYPES = { WSCache.WSMethodType.BINARY_BYTES_ARRAY,  WSCache.WSMethodType.BINARY_BYTES,  WSCache.WSMethodType.BINARY_BYTE_BUFFER};


    public WSHandler(String uri, SecurityProp securityProp, WSCache wsCache, Object bean) {
        this.uri = uri;
        this.securityProp = securityProp;
        this.bean = bean;
        this.methodCache = wsCache;
        if (log.isEnabled()) log.getLogger().info("URI: " + uri + " secProp: " + securityProp + " bean: " + bean);
    }

    public String getPath() {
        return uri;
    }

    public Object getBean() {
        return bean;
    }


    /**
     * @param hph
     * @throws IOException
     */
    @EndPointProp(methods = {HTTPMethod.GET}, name = "all-websocket", uris = "/web-socket-overridde")
    @Override
    public boolean handle(@ParamProp(name = "WSProtocol", source = Const.ParamSource.RESOURCE) HTTPProtocolHandler hph)
            throws IOException {
        if (log.isEnabled()) log.getLogger().info("Protocol " + hph.getProtocol());
        if (hph.isHTTPProtocol()) {
            NVGenericMap headers = hph.getRequest().getHeaders();
            if (log.isEnabled()) log.getLogger().info(hph.getRequest().getHeaders().toString());
            HTTPAuthorization authorization = hph.getRequest().getAuthorization();
            if (log.isEnabled()) log.getLogger().info("" + authorization);
            if (log.isEnabled()) log.getLogger().info("" + headers.getValue(HTTPHeader.CONNECTION));
            //System.out.println("" + headers.getValue(HTTPHeader.SEC_WEBSOCKET_ACCEPT));
            if (log.isEnabled()) log.getLogger().info("" + headers.getValue(HTTPHeader.SEC_WEBSOCKET_VERSION));
            if (log.isEnabled())
                log.getLogger().info("WEB-SOCKET-Protocol: " + headers.getValue(HTTPHeader.SEC_WEBSOCKET_PROTOCOL));
            if (log.isEnabled()) log.getLogger().info("" + headers.getValue(HTTPHeader.SEC_WEBSOCKET_KEY));
            if (log.isEnabled()) log.getLogger().info("" + headers.getValue(HTTPHeader.UPGRADE));
            HTTPMessageConfigInterface resp = new HTTPMessageConfig();

            resp.setHTTPStatusCode(HTTPStatusCode.SWITCHING_PROTOCOLS);


            try {
               GetNameValue<String> supportedProtocol = parseHeaderRequestProtocol(hph.getRequest().getHeaders());

                resp.getHeaders().build(headers.get(HTTPHeader.UPGRADE)).
                        build(HTTPHeader.CONNECTION.toHTTPHeader("upgrade")).
                        // caused disconnection with chrome and edge
                        //build(HTTPHeader.SEC_WEBSOCKET_PROTOCOL.toHTTPHeader("chat")).
                                build(HTTPHeader.SEC_WEBSOCKET_ACCEPT.toHTTPHeader(HashUtil.hashAsBase64("sha-1", headers.getValue(HTTPHeader.SEC_WEBSOCKET_KEY) + HTTPWSProto.WEB_SOCKET_UUID)));
                if(supportedProtocol != null) resp.getHeaders().build(supportedProtocol);
            } catch (NoSuchAlgorithmException e) {
                throw new IOException(e);
            }


            if (log.isEnabled()) log.getLogger().info("Resp: " + resp);


            HTTPUtil.formatResponse(resp, hph.getResponseStream())
                    .writeTo(hph.getOutputStream());


            hph.switchProtocol(hph.getProtocol() == URIScheme.HTTPS ? URIScheme.WSS : URIScheme.WS);
            if (log.isEnabled()) log.getLogger().info("Protocol switched: " + hph.getProtocol());

            if (log.isEnabled()) log.getLogger().info("Request Size() " + hph.getRawRequest().getDataStream().size());
            if (log.isEnabled())
                log.getLogger().info("Request Size() " + hph.getRawRequest().getDataStream().toString());

            hph.reset();
            if (log.isEnabled()) log.getLogger().info("Request Size() " + hph.getRawRequest().getDataStream().size());
            hph.setEndPointBean(this);


            WSSession webSocketSession = null;
            // create the websocket session
            if (hph.getConnectionSession() == null) {
                webSocketSession = new WSSession(hph, ShiroUtil.subject(), sessionSet);
                hph.setConnectionSession(webSocketSession.getShiroSession());
            }
            // call OnOpen
            Method toInvoke = methodCache.lookup(WSCache.WSMethodType.OPEN, false);
            if (toInvoke != null) {
                try {
                    ShiroInvoker.SINGLETON.invoke(false, false, getBean(), toInvoke, new Object[]{webSocketSession});
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }

            if (webSocketSession != null)
                webSocketSession.getShiroSession().detach();
            else
                ThreadContext.unbindSubject();

        } else if (hph.isWSProtocol()) {

            ShiroSession<?> currentSession = hph.getConnectionSession();
            try {

                currentSession.attach();
                if (log.isEnabled())
                    log.getLogger().info("We need to start processing " + hph.getProtocol() + " " + SecurityUtils.getSubject());
                processWSMessage(hph);
            } finally {
                currentSession.detach();
            }
        }

        return false;
    }


    private static GetNameValue<String> parseHeaderRequestProtocol(NVGenericMap headers)
    {
        GetNameValue<String> hProtocol = headers.getNV(HTTPHeader.SEC_WEBSOCKET_PROTOCOL);
        if(hProtocol != null){
            GetNameValue<?> webSocketProtocol = HTTPHeaderParser.parseHeader(hProtocol);
            if(log.isEnabled()) log.getLogger().info("" + webSocketProtocol);
            // we need to check protocols TBD MN-2025-12-30
        }

        return null;
    }

    private void processWSMessage(HTTPProtocolHandler hph)
            throws IOException {
        HTTPWSFrame frame;
        ShiroSession<WSSession> shiroSession = hph.getConnectionSession();
        WSSession webSocketSession = shiroSession.getAssociatedSession();
        while (webSocketSession.isOpen() && (frame = HTTPWSFrame.parse(hph.getRawRequest().getDataStream(), hph.getMarkerIndex())) != null) {
            if (log.isEnabled())
                log.getLogger().info("We have a web socket frame " + SUS.toCanonicalID(',', frame.opCode(), frame.isFin(), frame.isMasked(), frame.status(), frame.dataLength()));

            HTTPWSProto.OpCode opCode = frame.opCode();
            if (opCode != null) {


                Method toInvoke = null;
                Object[] parameters = null;
                switch (opCode) {
                    case TEXT:
                        toInvoke = methodCache.lookup(opCode, !frame.isFin());

                        if (toInvoke != null) {
                            parameters = new Object[]{frame.data().asString(), frame.isFin(), webSocketSession};
                        }
                        break;
                    case BINARY:
                        // find the appropriate method
                        toInvoke = methodCache.lookup(opCode, !frame.isFin());

                        if (toInvoke != null) {
                            parameters = new Object[]{frame.data(), frame.isFin(), webSocketSession};
                        }
                        break;
                    case CLOSE:
                        toInvoke = methodCache.lookup(opCode, false);
                        if (toInvoke != null) {
                            parameters = new Object[]{webSocketSession};


                            if (log.isEnabled()) log.getLogger().info(opCode + " " + frame.isFin() + " " + toInvoke);
                            try {
                                ShiroInvoker.SINGLETON.invoke(false, false,getBean(), toInvoke, parameters);
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        }
                        IOUtil.close(hph);
                        return;
                    case PING:
                        // we received a ping message

                        webSocketSession.getBasicRemote().sendPong(frame.data() != null ? ByteBufferUtil.wrap(frame.data()) : null);
                        break;
                    case PONG:
                        toInvoke = methodCache.lookup(WSCache.WSMethodType.PONG, false);
                        if (toInvoke != null) {
                            parameters = new Object[]{new WSPongMessage(frame.data()), webSocketSession};
                        }
                        break;
                }

                // invoke method
                if (toInvoke != null) {
                    if (log.isEnabled())
                        log.getLogger().info(opCode + " " + frame.isFin() + " " + toInvoke);
                    try {
                        ShiroInvoker.SINGLETON.invoke(false,false, getBean(), toInvoke, parameters);
                    } catch (Exception e) {
                        e.printStackTrace();
                        log.getLogger().info(webSocketSession.isOpen() + " " + frame.id() + " " + e);
                        Method onErrorMethod = methodCache.lookup(WSCache.WSMethodType.ERROR, false);
                        if (onErrorMethod != null) {
                            try {
                                // Error Processing OnError
                                onErrorMethod.invoke(bean, e, webSocketSession);
                            } catch (Exception ex) {
                                ex.printStackTrace();
                            }
                        }

                    }
                }
            }

            if (!hph.isClosed()) {
                if (hph.getRawRequest().getDataStream().size() != frame.frameSize())
                    hph.getRawRequest().getDataStream().shiftLeft(hph.getMarkerIndex() + frame.frameSize(), 0);
                else
                    hph.getRawRequest().getDataStream().reset();

                hph.setMarkerIndex(0);
                hph.getResponseStream(true).reset();
            }
        }

    }


}
