package io.xlogistx.ssl;

import io.xlogistx.common.fsm.State;
import io.xlogistx.common.fsm.TriggerConsumer;
import org.zoxweb.server.task.TaskCallback;

import javax.net.ssl.SSLEngineResult;
import java.nio.ByteBuffer;

import static javax.net.ssl.SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;

public class SSLReadState
        extends State
{



    static class NotHandshaking extends TriggerConsumer<TaskCallback<ByteBuffer, SSLChannelOutputStream>>
    {
        NotHandshaking() {
            super(NOT_HANDSHAKING);
        }

        @Override
        public void accept(TaskCallback<ByteBuffer, SSLChannelOutputStream> callback)
        {
            SSLSessionConfig config = (SSLSessionConfig) getState().getStateMachine().getConfig();
            if(log.isEnabled()) log.getLogger().info("" + config.getHandshakeStatus());

            if(config.sslChannel.isOpen())
            {
                switch(config.getHandshakeStatus())
                {
                    case NOT_HANDSHAKING:
                    {
                        try
                        {
                            int bytesRead = config.sslChannel.read(config.inSSLNetData);
                            if (bytesRead == -1)
                            {
                                log.getLogger().info("SSLCHANNEL-CLOSED-NOT_HANDSHAKING: " + config.getHandshakeStatus() + " bytesread: " + bytesRead);
                                config.close();
                            }
                            else
                            {
                                // even if we have read zero it will trigger BUFFER_UNDERFLOW then we wait for incoming
                                // data

                                SSLEngineResult result = config.smartUnwrap(config.inSSLNetData, config.inAppData);


                                if (log.isEnabled())
                                    log.getLogger().info("AFTER-NOT_HANDSHAKING-PROCESSING: " + result + " bytesread: " + bytesRead + " callback: " + callback);
                                switch (result.getStatus())
                                {
                                    case BUFFER_UNDERFLOW:
                                        // no incoming data available we need to wait for more socket data
                                        // return and let the NIOSocket or the data handler call back
                                        //config.sslChannelSelectableStatus.set(true);
                                        //config.sslRead.set(true);
                                        return;

                                    case BUFFER_OVERFLOW:
                                        throw new IllegalStateException("NOT_HANDSHAKING should never be " + result.getStatus());
                                        // this should never happen
                                    case OK:

                                        if(callback != null) callback.accept(config.inAppData);
                                        // config.sslRead.set(true);
                                        break;
                                    case CLOSED:
                                        // check result here

                                        if(log.isEnabled()) log.getLogger().info("CLOSED-DURING-NOT_HANDSHAKING: " + result + " bytesread: " + bytesRead);

                                        config.close();
                                        break;
                                }
                            }
                        } catch (Exception e) {

                            if(callback != null)
                                callback.exception(e);

                            config.close();
                        }
                    }
                    break;
                    default:
                        publishSync(config.getHandshakeStatus(), callback);
                }
            }

        }
    }




    public SSLReadState()
    {
        super(SSLStateMachine.SessionState.READY);
        register(new NotHandshaking());
    }

}
