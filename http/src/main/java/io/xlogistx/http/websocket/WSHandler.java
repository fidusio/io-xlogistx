package io.xlogistx.http.websocket;

import io.xlogistx.common.http.HTTPProtocolHandler;
import io.xlogistx.common.http.HTTPSessionHandler;
import org.apache.shiro.subject.Subject;
import org.zoxweb.server.http.HTTPUtil;
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

import java.io.IOException;

public class WSHandler
        implements HTTPSessionHandler<Subject>
{
    public static final LogWrapper log = new LogWrapper(WSHandler.class).setEnabled(true);

    private final String uri;
    private final Object bean;
    private final SecurityProp securityProp;

    public WSHandler(String uri, SecurityProp securityProp, Object bean)
    {
        this.uri = uri;
        this.securityProp = securityProp;
        this.bean = bean;
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
            System.out.println(""+ authorization);
            System.out.println("" + headers.getValue(HTTPHeader.CONNECTION));
            //System.out.println("" + headers.getValue(HTTPHeader.SEC_WEBSOCKET_ACCEPT));
            System.out.println("" + headers.getValue(HTTPHeader.SEC_WEBSOCKET_VERSION));
            System.out.println("WEB-SOCKET-Protocol: " + headers.getValue(HTTPHeader.SEC_WEBSOCKET_PROTOCOL));
            System.out.println("" + headers.getValue(HTTPHeader.SEC_WEBSOCKET_KEY));
            System.out.println("" + headers.getValue(HTTPHeader.UPGRADE));
            HTTPMessageConfigInterface resp = null;
            try {
                 resp = new HTTPMessageConfig();
                 resp.setHTTPStatusCode(HTTPStatusCode.SWITCHING_PROTOCOLS);
                 resp.getHeaders().build(headers.get(HTTPHeader.UPGRADE)).
                        build(HTTPHeader.CONNECTION.toHTTPHeader("upgrade")).
                        build(HTTPHeader.SEC_WEBSOCKET_PROTOCOL.toHTTPHeader("chat")).
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

                System.out.println("Request Size() " + hph.getRawRequest().getDataStream().size());
                hph.reset();
                System.out.println("Request Size() " + hph.getRawRequest().getDataStream().size());
                hph.setEndPointBean(this);
            }

        }
        else if (hph.isWSProtocol())
        {
            if (log.isEnabled()) log.getLogger().info("We need to start processing " + hph.getProtocol());



            HTTPWSFrame frame = new HTTPWSFrame(hph.getRawRequest().getDataStream(), hph.getLastWSIndex());
            if(frame.frameSize() != -1)
            {
                if (log.isEnabled()) log.getLogger().info("We have a web socket frame " + SUS.toCanonicalID(',', frame.opCode(), frame.isFin(), frame.isMasked(), frame.status(), frame.dataLength()));



                if (frame.isFin())
                {
                    switch (frame.opCode())
                    {
                        case TEXT:
                            String text =  frame.data().asString();
                            if (log.isEnabled()) log.getLogger().info("Data: " + text);


                            if (text.equalsIgnoreCase("ping"))
                            {
                                HTTPWSProto.formatFrame(hph.getResponseStream(true), true, HTTPWSProto.OpCode.PING, null, text)
                                    .writeTo(hph.getOutputStream());

                            }
                            else
                                HTTPWSProto.formatFrame(hph.getResponseStream(true), true, HTTPWSProto.OpCode.TEXT, null, "Reply-" + text)
                                    .writeTo(hph.getOutputStream());

                            break;
                        case BINARY:
                            break;
                        case CLOSE:
                            hph.close();
                            break;
                        case PING:
                            HTTPWSProto.formatFrame(hph.getResponseStream(true),
                                            true,
                                            HTTPWSProto.OpCode.PONG,
                                            null, // masking key always null since this is a server
                                            frame.data() != null ? frame.data().asBytes() : null)
                                    .writeTo(hph.getOutputStream());
                            break;
                        case PONG:
                            if (log.isEnabled()) log.getLogger().info("Data: " + frame.opCode() + " " + (frame.data() != null ? frame.data().asString() : ""));
                            break;
                    }


                    hph.reset();
                }
                else
                {
                    // we have to shift the buffer and extract the data
                    // and update hph.setLastWSIndex
                    // don't reset the request buffer
                }




            }


        }
    }
}
