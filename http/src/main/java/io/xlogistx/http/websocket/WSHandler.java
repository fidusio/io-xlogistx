package io.xlogistx.http.websocket;

import io.xlogistx.common.http.HTTPProtocolHandler;
import io.xlogistx.common.http.HTTPSessionHandler;
import io.xlogistx.common.http.WSMethodType;
import io.xlogistx.shiro.ShiroUtil;
import io.xlogistx.shiro.SubjectSwap;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.zoxweb.server.http.HTTPUtil;
import org.zoxweb.server.io.ByteBufferUtil;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.security.HashUtil;
import org.zoxweb.shared.annotation.EndPointProp;
import org.zoxweb.shared.annotation.ParamProp;
import org.zoxweb.shared.annotation.SecurityProp;
import org.zoxweb.shared.http.*;
import org.zoxweb.shared.protocol.HTTPWSFrame;
import org.zoxweb.shared.protocol.HTTPWSProto;
import org.zoxweb.shared.util.Const;
import org.zoxweb.shared.util.NVGenericMap;
import org.zoxweb.shared.util.SUS;

import javax.websocket.PongMessage;
import javax.websocket.Session;
import java.io.IOException;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class WSHandler
        implements HTTPSessionHandler<Subject>
{

    public static final LogWrapper log = new LogWrapper(WSHandler.class).setEnabled(false);

    private final String uri;
    private final Object bean;
    private final SecurityProp securityProp;
    private final Map<WSMethodType, Method> methodMaps;

    private final Set<Session> sessionSet = ConcurrentHashMap.newKeySet();

    private static final WSMethodType[] BINARY_TYPES = {WSMethodType.BINARY_BYTES_ARRAY, WSMethodType.BINARY_BYTES, WSMethodType.BINARY_BYTE_BUFFER};



    public WSHandler(String uri, SecurityProp securityProp,  Map<WSMethodType, Method> methodMaps, Object bean)
    {
        this.uri = uri;
        this.securityProp = securityProp;
        this.bean = bean;
        this.methodMaps = methodMaps;
        if (log.isEnabled()) log.getLogger().info("URI: " + uri + " secProp: " + securityProp + " bean: " + bean);
    }

    public String getPath()
    {
        return uri;
    }

    public Object getBean()
    {
        return bean;
    }



    /**
     * @param hph
     * @throws IOException
     */
    @EndPointProp(methods = {HTTPMethod.GET}, name="all-websocket", uris="/web-socket-overridden")
    @Override
    public void handle(@ParamProp(name="WSProtocol", source= Const.ParamSource.RESOURCE) HTTPProtocolHandler<Subject> hph)
            throws IOException
    {
        if (log.isEnabled()) log.getLogger().info("Protocol " + hph.getProtocol());
        if(hph.isHTTPProtocol())
        {
            NVGenericMap headers = hph.getRequest().getHeaders();
            if (log.isEnabled()) log.getLogger().info(hph.getRequest().getHeaders().toString());
            HTTPAuthorization authorization = hph.getRequest().getAuthorization();
            if (log.isEnabled()) log.getLogger().info(""+ authorization);
            if (log.isEnabled()) log.getLogger().info("" + headers.getValue(HTTPHeader.CONNECTION));
            //System.out.println("" + headers.getValue(HTTPHeader.SEC_WEBSOCKET_ACCEPT));
            if (log.isEnabled()) log.getLogger().info("" + headers.getValue(HTTPHeader.SEC_WEBSOCKET_VERSION));
            if (log.isEnabled()) log.getLogger().info("WEB-SOCKET-Protocol: " + headers.getValue(HTTPHeader.SEC_WEBSOCKET_PROTOCOL));
            if (log.isEnabled()) log.getLogger().info("" + headers.getValue(HTTPHeader.SEC_WEBSOCKET_KEY));
            if (log.isEnabled()) log.getLogger().info("" + headers.getValue(HTTPHeader.UPGRADE));
            HTTPMessageConfigInterface resp = null;
            try {
                 resp = new HTTPMessageConfig();
                 resp.setHTTPStatusCode(HTTPStatusCode.SWITCHING_PROTOCOLS);

                 // Minimum negotiation
                 resp.getHeaders().build(headers.get(HTTPHeader.UPGRADE)).
                        build(HTTPHeader.CONNECTION.toHTTPHeader("upgrade")).
                         // caused disconnection with chrome and edge
                         //build(HTTPHeader.SEC_WEBSOCKET_PROTOCOL.toHTTPHeader("chat")).
                        build(HTTPHeader.SEC_WEBSOCKET_ACCEPT.toHTTPHeader(HashUtil.hashAsBase64("sha-1", headers.getValue(HTTPHeader.SEC_WEBSOCKET_KEY) + HTTPWSProto.WEB_SOCKET_UUID)));

            } catch (Exception e) {
               e.printStackTrace();
            }

            if (log.isEnabled()) log.getLogger().info("Resp: " + resp);

            if (resp !=  null)
            {
                HTTPUtil.formatResponse(resp, hph.getResponseStream())
                        .writeTo(hph.getOutputStream());


                hph.switchProtocol( hph.getProtocol() == URIScheme.HTTPS ? URIScheme.WSS : URIScheme.WS);
                if (log.isEnabled()) log.getLogger().info("Protocol switched: " + hph.getProtocol());

                if (log.isEnabled()) log.getLogger().info("Request Size() " + hph.getRawRequest().getDataStream().size());
                if (log.isEnabled()) log.getLogger().info("Request Size() " + hph.getRawRequest().getDataStream().toString());

                hph.reset();
                if (log.isEnabled()) log.getLogger().info("Request Size() " + hph.getRawRequest().getDataStream().size());
                hph.setEndPointBean(this);

                // create the websocket session
                if(hph.getExtraSession() == null)
                {
                    hph.setExtraSession(new WSSession(hph, sessionSet));
                }


            }

        }
        else if (hph.isWSProtocol())
        {
            SubjectSwap ss = null;
            try
            {
                ss = new SubjectSwap(hph.getSubject());
                if (log.isEnabled()) log.getLogger().info("We need to start processing " + hph.getProtocol() + " " + SecurityUtils.getSubject());
                processWSMessage(hph);
            }
            finally
            {
                IOUtil.close(ss);
            }
        }
    }




    private void processWSMessage(HTTPProtocolHandler<Subject> hph)
            throws IOException
    {
        HTTPWSFrame frame;
        Session session = hph.getExtraSession();
        while((frame = HTTPWSFrame.parse(hph.getRawRequest().getDataStream(), hph.getLastWSIndex())) != null)
        {

            if (log.isEnabled())
                log.getLogger().info("We have a web socket frame " + SUS.toCanonicalID(',', frame.opCode(), frame.isFin(), frame.isMasked(), frame.status(), frame.dataLength()));


            if (frame.isFin())
            {
                HTTPWSProto.OpCode opCode = frame.opCode();
                if (opCode == null)
                {
                    log.getLogger().info(""+ frame.rawOpCode());
                }

                if (!hph.pendingWSFrames.isEmpty())
                {
                    log.getLogger().info("WE HAVE PENDING FRAMES\n" + hph.pendingWSFrames);

                }

                Method toInvoke = null;
                switch (opCode)
                {
                    case TEXT:
                        toInvoke = methodMaps.get(WSMethodType.TEXT);
                        if(toInvoke != null)
                        {
                            try
                            {
                                ShiroUtil.invokeMethod(false, getBean(), toInvoke, frame.data().asString(), frame.isFin(), hph.getExtraSession());
                            }
                            catch (Exception e)
                            {
                                e.printStackTrace();
                            }
                        }

                        break;
                    case BINARY:

                        for(WSMethodType binaryMatch : BINARY_TYPES)
                        {
                            // find the appropriate method
                            toInvoke = methodMaps.get(binaryMatch);

                            if (toInvoke != null)
                            {
                                Object mainParameter = null;
                                // covert first parameters
                                switch (binaryMatch)
                                {

                                    case BINARY_BYTES:
                                        mainParameter = frame.data().asBytes();
                                        break;
                                    case BINARY_BYTE_BUFFER:
                                        mainParameter = ByteBufferUtil.toByteBuffer(frame.data());
                                        break;
                                    case BINARY_BYTES_ARRAY:
                                        mainParameter = frame.data();
                                        break;
                                }
                                // invoke method
                                try
                                {
                                    ShiroUtil.invokeMethod(false, getBean(), toInvoke, mainParameter, frame.isFin(), hph.getExtraSession());
                                }
                                catch (Exception e)
                                {
                                    e.printStackTrace();
                                }
                                // break the loop
                                break;
                            }
                        }

                        break;
                    case CLOSE:
                        toInvoke = methodMaps.get(WSMethodType.CLOSE);
                        if(toInvoke != null)
                        {
                            try
                            {
                                // MN WARMING!!! DO NOT CHANGE new Object[]{...} error was generated by sending one object instead object[]
                                // SPENT 2 hours 27-3-2025 after midnight
                                ShiroUtil.invokeMethod(false, getBean(), toInvoke, new Object[]{hph.getExtraSession()});
                            }
                            catch (Exception e)
                            {
                                e.printStackTrace();

                                log.getLogger().info(toInvoke + " " + getBean());
                            }
                        }
                        hph.close();
                        return;
                    case PING:
                        // we received a ping message
                        session.getBasicRemote().sendPong(frame.data() != null ? ByteBuffer.wrap(frame.data().asBytes()) : null);
                        break;
                    case PONG:
                        toInvoke = methodMaps.get(WSMethodType.PONG);
                        if(toInvoke != null)
                        {
                            try
                            {
                                ByteBuffer pongData = ByteBufferUtil.toByteBuffer(frame.data());
                                PongMessage message = ()->pongData;
                                ShiroUtil.invokeMethod(false, getBean(), toInvoke, message, hph.getExtraSession());
                            }
                            catch (Exception e)
                            {
                                e.printStackTrace();
                            }
                        }

                        if (log.isEnabled())
                            log.getLogger().info("Data: " + frame.opCode() + " " + (frame.data() != null ? frame.data().asString() : ""));
                        break;
                }
                if(hph.getRawRequest().getDataStream().size() != frame.frameSize())
                    hph.getRawRequest().getDataStream().shiftLeft(hph.getLastWSIndex() + frame.frameSize(), 0);
                else
                    hph.getRawRequest().getDataStream().reset();
                hph.setLastWSIndex(0);
                hph.getResponseStream(true).reset();

            }
            else
            {
                log.getLogger().info("********  Frame isFin " + frame.isFin() + " " + frame + " " +frame.rawOpCode() + "  " +frame.data().asString());

                hph.pendingWSFrames.add(frame);
                hph.setLastWSIndex(hph.getRawRequest().getDataStream().size());

                // we have to shift the buffer and extract the data
                // and update hph.setLastWSIndex
                // don't reset the request buffer
            }

        }
    }




}
