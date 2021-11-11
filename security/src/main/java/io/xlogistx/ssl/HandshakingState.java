package io.xlogistx.ssl;

import io.xlogistx.common.fsm.State;
import io.xlogistx.common.fsm.TriggerConsumer;
import org.zoxweb.server.io.ByteBufferUtil;
import org.zoxweb.shared.util.SharedStringUtil;
import org.zoxweb.shared.util.SharedUtil;

import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLSession;
import java.io.IOException;
import java.util.logging.Logger;

import static javax.net.ssl.SSLEngineResult.HandshakeStatus.*;

public class HandshakingState extends State {
    private static final transient Logger log = Logger.getLogger(HandshakingState.class.getName());
    public static boolean debug = true;
    class NeedWrap extends TriggerConsumer<SSLConfig>
    {
        NeedWrap() {
            super(NEED_WRAP);
        }

        @Override
        public void accept(SSLConfig config) {
            try{
                SSLEngineResult result = config.smartWrap(ByteBufferUtil.EMPTY, config.outNetData); // at handshake stage, data in appOut won't be
                // processed hence dummy buffer
                if (debug) log.info( "AFTER-NEED_WRAP-HANDSHAKING: " + result);

                switch (result.getStatus())
                {

                    case BUFFER_UNDERFLOW:
                    case BUFFER_OVERFLOW:

                        throw new IllegalStateException(result.getStatus() + " invalid state context");
                    case OK:
                        int written = ByteBufferUtil.smartWrite(config.sslChannel, config.outNetData);
                        //postHandshakeIfNeeded(config, result, sslChannel);
                        if(debug) log.info("After writing data HANDSHAKING-NEED_WRAP: " + config.outNetData + " written:" + written);
                        publish(config, result.getHandshakeStatus());
                        break;
                    case CLOSED:
                        publish(config.sslChannel, SSLStateMachine.SessionState.CLOSE);
                        break;

                }

            }
            catch (Exception e)
            {
                e.printStackTrace();
                publish(config.sslChannel, SSLStateMachine.SessionState.CLOSE);
            }

        }
    }

    class NeedUnwrap extends TriggerConsumer<SSLConfig>
    {
        NeedUnwrap() {
            super(NEED_UNWRAP);
        }

        @Override
        public void accept(SSLConfig config) {
            try {

                int bytesRead = config.sslChannel.read(config.inNetData);
                if(bytesRead == -1) {
                    if (debug) log.info("SSLCHANNEL-CLOSED-NEED_UNWRAP: " + config.getHandshakeStatus() + " bytesread: " +bytesRead);
                    publish(config.sslChannel, SSLStateMachine.SessionState.CLOSE);
                    return;
                }

                else {



                    //even if we have read zero it will trigger BUFFER_UNDERFLOW then we wait for incoming data
                    SSLEngineResult result = config.smartUnwrap(config.inNetData, ByteBufferUtil.EMPTY);

                    if (debug) log.info("AFTER-NEED_UNWRAP-HANDSHAKING: " + result + " bytesread: " +bytesRead);
                    switch (result.getStatus())
                    {

                        case BUFFER_UNDERFLOW:
                            // no incoming data available we need to wait for more socket data
                            // return and let the NIOSocket or the data handler call back
                            //config.sslChannelSelectableStatus.set(true);
                          return;

                        case BUFFER_OVERFLOW:
                            throw new IllegalStateException("NEED_UNWRAP should never be BUFFER_OVERFLOW");
                            // this should never happen
                        case OK:
                            publish(config, result.getHandshakeStatus());
                            break;
                        case CLOSED:
                            // check result here
                            if (debug) log.info("CLOSED-DURING-NEED_UNWRAP: " + result + " bytesread: " +bytesRead);

                            publish(config.sslChannel, SSLStateMachine.SessionState.CLOSE);
                            break;
                    }
                }
            }
            catch (Exception e)
            {
                e.printStackTrace();
                publish(config.sslChannel, SSLStateMachine.SessionState.CLOSE);
            }

        }
    }





    class NeedTask extends TriggerConsumer<SSLConfig>
    {
        NeedTask() {
            super(NEED_TASK);
        }

        @Override
        public void accept(SSLConfig config) {
            Runnable toRun;
            while((toRun = config.getDelegatedTask()) != null)
            {
                toRun.run();

            }
            SSLEngineResult.HandshakeStatus status = config.getHandshakeStatus();;
            log.info("After run: " + status);
            publish(config, status);
        }
    }



    class Finished extends TriggerConsumer<SSLConfig>
    {
        Finished() {
            super(FINISHED);
        }

        @Override
        public void accept(SSLConfig config) {
            SSLEngineResult.HandshakeStatus status = config.getHandshakeStatus();
            log.info("Finished: " + status);
            publish(config, status);
        }
    }


    class NotHandshaking extends TriggerConsumer<SSLConfig>
    {
        boolean first = false;
        NotHandshaking() {
            super(NOT_HANDSHAKING);
        }

        @Override
        public void accept(SSLConfig config) {
            SSLEngineResult result = null;
            try {
                 result = config.smartWrap(ByteBufferUtil.EMPTY, config.outNetData);
                log.info("LAST-WRAP:" + result);
                switch (result.getStatus())
                {

                    case BUFFER_UNDERFLOW:
                        break;
                    case BUFFER_OVERFLOW:
                        break;
                    case OK:
                        ByteBufferUtil.smartWrite(config.sslChannel, config.outNetData);
                        if (result.getHandshakeStatus() != NOT_HANDSHAKING) {
                          publish(config, config.getHandshakeStatus());
                          return;
                        }
                        break;
                    case CLOSED:
                        publish(config.sslChannel, SSLStateMachine.SessionState.CLOSE);
                        return;

                }

                return;

            } catch (IOException e) {
                e.printStackTrace();
            }







        SSLSession sslSession = config.getSession();
        log.info("Handshake session: " + SharedUtil.toCanonicalID(':',sslSession.getProtocol(),
                sslSession.getCipherSuite(),
                SharedStringUtil.bytesToHex(sslSession.getId())));





            publish(config.sslChannel, SSLStateMachine.SessionState.READY);

        }
    }


    public HandshakingState() {
        super(SSLStateMachine.SessionState.HANDSHAKING);
        register(new NeedTask())
                .register(new NeedWrap())
                .register(new NeedUnwrap())
                .register(new Finished())
//                .register(new NeedUnwrapAgain())
                .register(new NotHandshaking());

    }

}
