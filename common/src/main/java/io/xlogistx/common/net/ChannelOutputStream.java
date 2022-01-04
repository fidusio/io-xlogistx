package io.xlogistx.common.net;

import org.zoxweb.server.io.ByteBufferUtil;
import org.zoxweb.server.io.IOUtil;

import java.io.IOException;

import java.nio.ByteBuffer;
import java.nio.channels.ByteChannel;


public class ChannelOutputStream extends BaseChannelOutputStream {

    public ChannelOutputStream(ByteChannel config, int outAppBufferSize)
    {
        super(config, outAppBufferSize);
    }



    /**
     *
     * @param bb buffer sent over the wire
     * @return the number of byte sent
     * @throws IOException in case of error
     */
    protected int write(ByteBuffer bb) throws IOException
    {
        return ByteBufferUtil.smartWrite(null, outChannel, bb);
    }

    public void close()
    {
        IOUtil.close(outChannel);
        ByteBufferUtil.cache(outAppData);
    }

}
