package io.xlogistx.common.net;

import org.zoxweb.server.io.ByteBufferUtil;
import org.zoxweb.server.io.IOUtil;

import java.io.IOException;

import java.nio.ByteBuffer;
import java.nio.channels.ByteChannel;


public class ChannelOutputStream
        extends BaseChannelOutputStream
{

    public ChannelOutputStream(ByteChannel byteChannel, int outAppBufferSize)
    {
        super(byteChannel, outAppBufferSize);
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
        if(!isClosed.getAndSet(true))
        {
            IOUtil.close(outChannel);
            ByteBufferUtil.cache(outAppData);
            //ByteBufferUtil.cache(oneByteBuffer);
        }
    }

}
