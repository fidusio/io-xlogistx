package io.xlogistx.common.net;


import org.zoxweb.server.net.SessionCallback;

import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.ByteChannel;
import java.util.logging.Logger;

public abstract class PlainSessionCallback extends SessionCallback<ByteChannel, ByteBuffer, OutputStream>
{
    private ChannelOutputStream cos = null;
    protected  static final transient Logger log = Logger.getLogger(PlainSessionCallback.class.getName());
    public synchronized void setConfig(ByteChannel bc)
    {
        if(cos == null)
            cos = new ChannelOutputStream(bc, 512);
    }


    @Override
    public void exception(Exception e) {
        // exception handling

        log.info( e + "");
    }
    final public OutputStream get()
    {
        return cos;
    }
}
