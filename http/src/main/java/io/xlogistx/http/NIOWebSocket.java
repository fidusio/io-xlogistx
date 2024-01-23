package io.xlogistx.http;

import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.net.PlainSessionCallback;
import org.zoxweb.server.net.ssl.SSLSessionCallback;

import java.nio.ByteBuffer;
import java.util.logging.Logger;

public class NIOWebSocket
{
    public final static LogWrapper logger = new LogWrapper(Logger.getLogger(NIOWebSocket.class.getName())).setEnabled(false);

    public class WWSWebSocket
        extends SSLSessionCallback
    {

        @Override
        public void accept(ByteBuffer byteBuffer)
        {

        }
    }

    public class WWWebSocket
        extends PlainSessionCallback
    {

        @Override
        public void accept(ByteBuffer byteBuffer)
        {

        }
    }
}
