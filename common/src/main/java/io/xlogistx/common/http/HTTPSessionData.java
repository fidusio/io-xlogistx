package io.xlogistx.common.http;

import org.zoxweb.server.http.HTTPUtil;

import java.io.IOException;
import java.io.OutputStream;

public class HTTPSessionData
{
    public final HTTPProtocolHandler protocolHandler;
    public final OutputStream os;
    public HTTPSessionData(HTTPProtocolHandler protocolHandler, OutputStream os)
    {
        this.os = os;
        this.protocolHandler = protocolHandler;
    }

    public void writeResponse()
        throws IOException
    {
        HTTPUtil.formatResponse(protocolHandler.getResponse(), protocolHandler.getRawResponse());
        protocolHandler.getRawResponse().writeTo(os);
    }

}
