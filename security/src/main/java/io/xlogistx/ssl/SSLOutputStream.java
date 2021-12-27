package io.xlogistx.ssl;

import org.zoxweb.server.io.ByteBufferUtil;

import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;


import java.util.logging.Logger;

import static javax.net.ssl.SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;

public class SSLOutputStream extends OutputStream {
    private static final transient Logger log = Logger.getLogger(SSLOutputStream.class.getName());
    public static boolean debug = false;

    private final SSLSessionConfig config;
    protected SSLOutputStream(SSLSessionConfig config, boolean createBuffer)
    {
        this.config = config;
        if(createBuffer && config.outAppData == null)
            config.outAppData = ByteBufferUtil.allocateByteBuffer(ByteBufferUtil.BufferType.DIRECT, 2048);
    }

    @Override
    public synchronized void write(int b) throws IOException
    {
       throw new IOException("Not supported method");
    }


    public void write(byte b[], int off, int len) throws IOException {
        if (off > b.length || len > (b.length - off) || off < 0 || len < 0)
            throw new IndexOutOfBoundsException();

        // len == 0 condition implicitly handled by loop bounds
       for(int i = off; i < len;)
       {
           int tempLen = len;
           if(len - i > config.outAppData.capacity() - config.outAppData.position())
               tempLen = config.outAppData.capacity() - config.outAppData.position();
           config.outAppData.put(b, off, tempLen);
           i+= write(config.outAppData);
       }
    }




    /**
     *
     * @param bb unencrypted to be encrypted and sent over the wire the wire
     * @return
     * @throws IOException
     */
    public int write(ByteBuffer bb) throws IOException
    {
        int written = -1;
        if (config.getHandshakeStatus() == NOT_HANDSHAKING)
        {
            try {


                //config.outSSLNetData.clear();
//                if (config.outSSLNetData.limit() != config.outSSLNetData.capacity()) {
//                    config.outSSLNetData.compact();
//                }
                SSLEngineResult result = config.smartWrap(bb, config.outSSLNetData); // at handshake stage, data in appOut won't be

                if(debug) log.info("AFTER-NEED_WRAP-PROCESSING: " + result);

                switch (result.getStatus()) {
                    case BUFFER_UNDERFLOW:
                    case BUFFER_OVERFLOW:
                        throw new IOException(result.getStatus() + " invalid state context");
                    case OK:
                       written = ByteBufferUtil.smartWrite(config.ioLock, config.sslChannel, config.outSSLNetData);
                        break;
                    case CLOSED:
                       throw new IOException("Closed");
                }

            } catch (IOException e) {


                close();
                throw e;
                //publish(SSLStateMachine.SessionState.CLOSE, callback);
            }
        }
        else
        {
            throw new SSLException("handshaking state can't send data yet");
        }

        return written;
    }

    public void close() throws IOException
    {
        config.close();
    }

}
