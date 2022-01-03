package io.xlogistx.common.net;

import org.zoxweb.server.io.ByteBufferUtil;
import org.zoxweb.server.io.IOUtil;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.ByteChannel;
import java.util.logging.Logger;


public class ChannelOutputStream extends OutputStream {

    protected static final transient Logger log = Logger.getLogger(ChannelOutputStream.class.getName());
    public static boolean debug = false;

    protected final ByteChannel outChannel;
    protected final ByteBuffer outAppData;
    public ChannelOutputStream(ByteChannel config, int outAppBufferSize)
    {
        this.outChannel = config;
        if(outAppBufferSize > 0) {
            outAppData = ByteBufferUtil.allocateByteBuffer(ByteBufferUtil.BufferType.DIRECT, outAppBufferSize);

        }
        else
            throw new IllegalArgumentException("Invalid buffer size");
    }

    @Override
    public synchronized void write(int b) throws IOException
    {
       throw new IOException("Not supported method");
    }


    public synchronized void write(byte b[], int off, int len) throws IOException
    {
        if (off > b.length || len > (b.length - off) || off < 0 || len < 0)
            throw new IndexOutOfBoundsException();
        // len == 0 condition implicitly handled by loop bounds
       for(; off < len;)
       {
           int tempLen = len - off;
           if(tempLen > (outAppData.capacity() - outAppData.position()))
               tempLen = outAppData.capacity() - outAppData.position();


           outAppData.put(b, off, tempLen);
           write(outAppData);
           off += tempLen;
       }
    }




    /**
     *
     * @param bb unencrypted to be encrypted and sent over the wire
     * @return the number of ecnrypted data sent
     * @throws IOException
     */
    public synchronized int write(ByteBuffer bb) throws IOException
    {
        return ByteBufferUtil.smartWrite(null, outChannel, bb);
    }

    public void close() throws IOException
    {
        IOUtil.close(outChannel);
        ByteBufferUtil.cache(outAppData);
    }

}
