package io.xlogistx.http.handler;

import org.zoxweb.server.http.HTTPRawMessage;
import org.zoxweb.server.io.ByteBufferUtil;
import org.zoxweb.server.io.UByteArrayOutputStream;
import org.zoxweb.shared.http.HTTPMessageConfigInterface;

import java.io.IOException;
import java.nio.ByteBuffer;

public class HTTPProtocolHandler {


    private volatile UByteArrayOutputStream responseUBAOS = new UByteArrayOutputStream(256);
    private volatile HTTPRawMessage rawRequest = new HTTPRawMessage(new UByteArrayOutputStream(256));

    public boolean parseRequest(ByteBuffer inBuffer) throws IOException
    {
        ByteBufferUtil.write(inBuffer, rawRequest.getUBAOS(), true);

        rawRequest.parse(true);
        return rawRequest.isMessageComplete();// ? rawRequest.getHTTPMessageConfig() : null;
    }

    public boolean isRequestComplete()
    {
        return rawRequest.isMessageComplete();
    }

    public HTTPMessageConfigInterface getHTTPMessage()
    {
        return rawRequest.isMessageComplete() ? rawRequest.getHTTPMessageConfig() : null;
    }

    public UByteArrayOutputStream getRawRequest()
    {
        return rawRequest.isMessageComplete() ? rawRequest.getUBAOS() : null;
    }

    public UByteArrayOutputStream getRawResponse()
    {
        return rawRequest.isMessageComplete() ? responseUBAOS : null;
    }

}
