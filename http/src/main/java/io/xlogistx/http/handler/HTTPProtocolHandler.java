package io.xlogistx.http.handler;

import org.zoxweb.server.http.HTTPRawMessage;
import org.zoxweb.server.io.ByteBufferUtil;
import org.zoxweb.server.io.UByteArrayOutputStream;
import org.zoxweb.shared.http.HTTPMessageConfigInterface;

import java.io.IOException;
import java.nio.ByteBuffer;

public class HTTPProtocolHandler {


    private final UByteArrayOutputStream responseUBAOS = new UByteArrayOutputStream(256);
    private final HTTPRawMessage hrm = new HTTPRawMessage();

    public HTTPMessageConfigInterface parseRequest(ByteBuffer inBuffer) throws IOException
    {
        ByteBufferUtil.write(inBuffer, hrm.getUBAOS(), true);

        hrm.parse(true);
        return getHTTPMessage();
    }


    public HTTPMessageConfigInterface getHTTPMessage()
    {
        return hrm.isMessageComplete() ? hrm.getHTTPMessageConfig() : null;
    }

    public UByteArrayOutputStream getRawRequest()
    {
        return hrm.isMessageComplete() ? hrm.getUBAOS() : null;
    }

    public UByteArrayOutputStream getRawResponse()
    {
        return hrm.isMessageComplete() ? responseUBAOS : null;
    }

}
