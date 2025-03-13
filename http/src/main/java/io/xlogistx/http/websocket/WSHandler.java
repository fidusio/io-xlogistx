package io.xlogistx.http.websocket;

import io.xlogistx.common.http.HTTPProtocolHandler;
import io.xlogistx.common.http.HTTPSessionHandler;
import io.xlogistx.shiro.SubjectSwap;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.zoxweb.server.http.HTTPUtil;
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

import java.io.IOException;

public class WSHandler
        implements HTTPSessionHandler<Subject>
{
    public static final LogWrapper log = new LogWrapper(WSHandler.class).setEnabled(false);

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

                if (log.isEnabled()) log.getLogger().info("Request Size() " + hph.getRawRequest().getDataStream().size());
                hph.reset();
                if (log.isEnabled()) log.getLogger().info("Request Size() " + hph.getRawRequest().getDataStream().size());
                hph.setEndPointBean(this);

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
            finally {
                IOUtil.close(ss);
            }
        }
    }




    private void processWSMessage(HTTPProtocolHandler<Subject> hph)
            throws IOException
    {
        HTTPWSFrame frame;
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

//                            if (frame.frameSize() < hph.getRawRequest().getDataStream().size())
//                            {
//                                log.getLogger().info("we have data to extract");
//
//                            }

                if (!hph.pendingWSFrames.isEmpty())
                {
                    log.getLogger().info("WE HAVE PENDING FRAMES\n" + hph.pendingWSFrames);
                    System.exit(0);
                }
                ///hph.getRawRequest().getDataStream().shiftLeft(frame.data().offset, hph.getLastWSIndex());

                switch (opCode) {
                    case TEXT:
                        String text = frame.data().asString();
                        if (log.isEnabled()) log.getLogger().info("Data: " + text);


                        if (text.equalsIgnoreCase("ping")) {
                            HTTPWSProto.formatFrame(hph.getResponseStream(true), true, HTTPWSProto.OpCode.PING, null, text)
                                    .writeTo(hph.getOutputStream());

                        } else
                            HTTPWSProto.formatFrame(hph.getResponseStream(true), true, HTTPWSProto.OpCode.TEXT, null, "Reply-" + text)
                                    .writeTo(hph.getOutputStream());

                        break;
                    case BINARY:
                        break;
                    case CLOSE:
                        hph.close();
                        return;
                    case PING:
                        HTTPWSProto.formatFrame(hph.getResponseStream(true),
                                        true,
                                        HTTPWSProto.OpCode.PONG,
                                        null, // masking key always null since this is a server
                                        frame.data() != null ? frame.data().asBytes() : null)
                                .writeTo(hph.getOutputStream());
                        break;
                    case PONG:
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

            } else
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
