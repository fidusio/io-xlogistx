package io.xlogistx.common.http;

import org.zoxweb.server.http.HTTPUtil;

import java.io.IOException;

public class HTTPSessionData
{
    public final HTTPProtocolHandler protocolHandler;
    public HTTPSessionData(HTTPProtocolHandler protocolHandler)
    {
        this.protocolHandler = protocolHandler;
    }

    public void writeResponse()
        throws IOException
    {
        HTTPUtil.formatResponse(protocolHandler.getResponse(), protocolHandler.getRawResponse());
        protocolHandler.getRawResponse().writeTo(protocolHandler.getOutputStream());
    }

}
