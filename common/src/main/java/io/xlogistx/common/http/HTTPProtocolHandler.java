package io.xlogistx.common.http;


import org.zoxweb.server.http.HTTPRawMessage;
import org.zoxweb.server.io.ByteBufferUtil;
import org.zoxweb.server.io.UByteArrayOutputStream;
import org.zoxweb.shared.http.HTTPMessageConfig;
import org.zoxweb.shared.http.HTTPMessageConfigInterface;
import org.zoxweb.shared.util.IsClosed;

import java.io.Closeable;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.concurrent.atomic.AtomicBoolean;

public class HTTPProtocolHandler
    implements Closeable, IsClosed
{


    private final UByteArrayOutputStream rawResponse = ByteBufferUtil.allocateUBAOS(256);//new UByteArrayOutputStream(256);
    private HTTPMessageConfigInterface response = new HTTPMessageConfig();
    private HTTPRawMessage rawRequest = new HTTPRawMessage(ByteBufferUtil.allocateUBAOS(256));
    private final AtomicBoolean closed = new AtomicBoolean();
    public  final boolean https;

    public HTTPProtocolHandler(boolean https)
    {
        this.https = https;
    }




    public boolean parseRequest(ByteBuffer inBuffer) throws IOException
    {
        ByteBufferUtil.write(inBuffer, rawRequest.getDataStream(), true);

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
        return rawRequest.isMessageComplete() ? rawRequest.getDataStream() : null;
    }

    public UByteArrayOutputStream getRawResponse()
    {
        return rawRequest.isMessageComplete() ? rawResponse : null;
    }


    public HTTPMessageConfigInterface getResponse(){return response;}

    @Override
    public void close() throws IOException
    {
        if(!closed.getAndSet(true))
            ByteBufferUtil.cache(rawResponse, rawRequest.getDataStream());
    }

    public void reset()
    {
        response = new HTTPMessageConfig();
        rawRequest.reset();
        rawResponse.reset();
    }

    public boolean isClosed()
    {
        return closed.get();
    }
}
