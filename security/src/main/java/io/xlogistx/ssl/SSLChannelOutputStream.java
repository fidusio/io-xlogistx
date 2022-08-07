package io.xlogistx.ssl;

import io.xlogistx.common.net.BaseChannelOutputStream;
import org.zoxweb.server.io.ByteBufferUtil;

import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import java.io.IOException;
import java.nio.ByteBuffer;



import static javax.net.ssl.SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;

public class SSLChannelOutputStream extends BaseChannelOutputStream {
    private final SSLSessionConfig config;

    protected SSLChannelOutputStream(SSLSessionConfig config, int outAppBufferSize)
    {
        super(config.sslChannel, outAppBufferSize);
        this.config = config;
    }


    /**
     *
     * @param bb unencrypted to be encrypted and sent over the wire
     * @return the number of encrypted data sent
     * @throws IOException in case of error
     */
    protected int write(ByteBuffer bb) throws IOException
    {
        int written = -1;
        if (config.getHandshakeStatus() == NOT_HANDSHAKING)
        {
            SSLEngineResult result = config.smartWrap(bb, config.outSSLNetData); // at handshake stage, data in appOut won't be
            if(debug)
                log.info("AFTER-NEED_WRAP-PROCESSING: " + result);

            switch (result.getStatus())
            {
                case BUFFER_UNDERFLOW:
                case BUFFER_OVERFLOW:
                    throw new IOException(result.getStatus() + " invalid state context");
                case OK:
                   written = ByteBufferUtil.smartWrite(config.ioLock, outChannel, config.outSSLNetData);
                    break;
                case CLOSED:
                   throw new IOException("Closed");
            }
        }
        else
        {
            throw new SSLException("handshaking state can't send data yet");
        }

        return written;
    }

    public void close()
    {
        if(!isClosed.getAndSet(true))
        {
            config.close();
            ByteBufferUtil.cache(outAppData);
            //ByteBufferUtil.cache(oneByteBuffer);
        }
    }

}
