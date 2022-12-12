package io.xlogistx.common.http;


import org.zoxweb.server.http.HTTPRawMessage;
import org.zoxweb.server.io.ByteBufferUtil;
import org.zoxweb.server.io.UByteArrayOutputStream;
import org.zoxweb.shared.http.HTTPMessageConfig;
import org.zoxweb.shared.http.HTTPMessageConfigInterface;

import java.io.IOException;
import java.nio.ByteBuffer;

public class HTTPProtocolHandler

{


    private final UByteArrayOutputStream rawResponse = new UByteArrayOutputStream(256);
    private final HTTPMessageConfigInterface response = new HTTPMessageConfig();
    private final HTTPRawMessage rawRequest = new HTTPRawMessage(new UByteArrayOutputStream(256));
    //private final AtomicBoolean closed = new AtomicBoolean();

    public boolean parseRequest(ByteBuffer inBuffer) throws IOException
    {
        ByteBufferUtil.write(inBuffer, rawRequest.getInternalBAOS(), true);

        rawRequest.parse(true);
        return rawRequest.isMessageComplete();// ? rawRequest.getHTTPMessageConfig() : null;
    }

    public boolean isRequestComplete()
    {
        return rawRequest.isMessageComplete();
    }

    public HTTPMessageConfigInterface getRequest()
    {
        return rawRequest.isMessageComplete() ? rawRequest.getHTTPMessageConfig() : null;
    }

    public UByteArrayOutputStream getRawRequest()
    {
        return rawRequest.isMessageComplete() ? rawRequest.getInternalBAOS() : null;
    }

    public UByteArrayOutputStream getRawResponse()
    {
        return rawRequest.isMessageComplete() ? rawResponse : null;
    }


    public HTTPMessageConfigInterface getResponse(){return response;}

}
