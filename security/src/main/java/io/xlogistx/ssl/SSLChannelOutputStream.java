package io.xlogistx.ssl;

import io.xlogistx.common.net.ChannelOutputStream;
import org.zoxweb.server.io.ByteBufferUtil;

import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import java.io.IOException;
import java.nio.ByteBuffer;


import java.util.logging.Logger;

import static javax.net.ssl.SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;

public class SSLChannelOutputStream extends ChannelOutputStream {
    private static final transient Logger log = Logger.getLogger(SSLChannelOutputStream.class.getName());
    public static boolean debug = false;

    private final SSLSessionConfig config;

    protected SSLChannelOutputStream(SSLSessionConfig config, int outAppBufferSize)
    {
        super(config.sslChannel, outAppBufferSize);
        this.config = config;
    }


    /**
     *
     * @param bb unencrypted to be encrypted and sent over the wire
     * @return the number of ecnrypted data sent
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
                       written = ByteBufferUtil.smartWrite(config.ioLock, outChannel, config.outSSLNetData);
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
        ByteBufferUtil.cache(outAppData);
    }

}
