package io.xlogistx.common.net;

import org.zoxweb.server.io.ByteBufferUtil;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.ByteChannel;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Logger;

public abstract class BaseChannelOutputStream extends OutputStream {
    protected static final transient Logger log = Logger.getLogger(BaseChannelOutputStream.class.getName());
    public static boolean debug = false;

    protected final ByteChannel outChannel;
    protected final ByteBuffer outAppData;
    protected final AtomicBoolean isClosed = new AtomicBoolean(false);
    public BaseChannelOutputStream(ByteChannel outByteChannel, int outAppBufferSize)
    {
        this.outChannel = outByteChannel;
        if(outAppBufferSize > 0)
        {
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


    public synchronized void write(byte[] b, int off, int len) throws IOException
    {
        if (off > b.length || len > (b.length - off) || off < 0 || len < 0)
            throw new IndexOutOfBoundsException();
        // len == 0 condition implicitly handled by loop bounds
        while(off < len)
        {
            int tempLen = len - off;
            if(tempLen > (outAppData.capacity() - outAppData.position()))
                tempLen = outAppData.capacity() - outAppData.position();


            outAppData.put(b, off, tempLen);
            write(outAppData);
            off += tempLen;
        }
    }

    protected abstract int write(ByteBuffer byteBuffer) throws IOException;
}
