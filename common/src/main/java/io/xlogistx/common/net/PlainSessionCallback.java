package io.xlogistx.common.net;

import org.zoxweb.server.net.BaseSessionCallback;

import java.io.OutputStream;
import java.nio.channels.ByteChannel;

public abstract class PlainSessionCallback extends BaseSessionCallback<ByteChannel>
{
    private ChannelOutputStream cos = null;
    public synchronized void setConfig(ByteChannel bc)
    {
        if(cos == null)
            cos = new ChannelOutputStream(bc, 512);
    }



    final public OutputStream get()
    {
        return cos;
    }
}
