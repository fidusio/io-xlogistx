package io.xlogistx.common.ssl;

import io.xlogistx.common.fsm.TriggerConsumer;
import org.zoxweb.server.io.ByteBufferUtil;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.shared.util.SharedStringUtil;
import org.zoxweb.shared.util.SharedUtil;

import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLSession;

import java.io.IOException;
import java.nio.channels.SocketChannel;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Logger;

import static javax.net.ssl.SSLEngineResult.HandshakeStatus.FINISHED;

public class HandshakingTC extends TriggerConsumer<SocketChannel> {

    private static final transient Logger log = Logger.getLogger(SSLNIOTunnel.class.getName());

    public static boolean debug = true;
    private final static AtomicLong HANDSHAKE_COUNTER = new AtomicLong();


    HandshakingTC() {
        super(SSLSessionSM.SessionState.HANDSHAKING);
    }
    @Override
    public void accept(SocketChannel sslChannel) {
        if (sslChannel != null) {

            SSLSessionConfig config = (SSLSessionConfig) getStateMachine().getConfig();
            //SSLEngineResult result = null;
            SSLEngineResult.HandshakeStatus status;
            try {
                if(debug) log.info("Trying to Handshake: " + config.getHandshakeStatus());
                while ((status = config.getHandshakeStatus()) != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
                    if(debug) log.info("Before switch SSLServerEngine status " + status);
                    switch (status) {
                        case FINISHED:
                            if(debug) log.info("IN-FINISHED-STATUS:" + config.getHandshakeStatus());
                            break;
                        case NEED_WRAP: {
                            SSLEngineResult result = config.smartWrap(ByteBufferUtil.EMPTY, config.outNetData); // at handshake stage, data in appOut won't be
                            // processed hence dummy buffer
                            if (debug) log.info( "AFTER-NEED_WRAP-HANDSHAKING: " + result);

                            switch (result.getStatus())
                            {

                                case BUFFER_UNDERFLOW:

                                    break;
                                case BUFFER_OVERFLOW:

                                    break;
                                case OK:
                                    int written = ByteBufferUtil.smartWrite(sslChannel, config.outNetData);
                                    //postHandshakeIfNeeded(config, result, sslChannel);
                                    if(debug) log.info("After writing data HANDSHAKING-NEED_WRAP: " + config.outNetData + " written:" + written);
                                    break;
                                case CLOSED:
                                    publish(sslChannel, SSLSessionSM.SessionState.CLOSE);
                                    break;
                            }
                        }
                            break;
                        case NEED_TASK:
                            Runnable task = config.getDelegatedTask(); // these are the tasks like key generation that
                            // tend to take longer time to complete
                            if (task != null) {
                                task.run(); // it can be run at a different thread.
                            }
                            if (debug) log.info("AFTER-NEED_TASK-HANDSHAKING ");
                            break;
                        case NEED_UNWRAP: {
                            //if (readData)

                            int bytesRead = sslChannel.read(config.inNetData);
                            if(bytesRead == -1) {
                                if (debug) log.info("SSLCHANNEL-CLOSED-NEED_UNWRAP: " + config.getHandshakeStatus() + " bytesread: " +bytesRead);
                                publish(sslChannel, SSLSessionSM.SessionState.CLOSE);
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
                                        return;

                                    case BUFFER_OVERFLOW:
                                        throw new IllegalStateException("NEED_UNWRAP should never be BUFFER_OVERFLOW");
                                        // this should never happen
                                    case OK:
                                        break;
                                    case CLOSED:
                                        // check result here
                                        if (debug) log.info("CLOSED-DURING-NEED_UNWRAP: " + result + " bytesread: " +bytesRead);

                                        publish(sslChannel, SSLSessionSM.SessionState.CLOSE);
                                        break;
                                }
                            }
                        }
                            break;
                        default:
                            throw new IllegalStateException("SHOULD never HAPPEN:" + config.getHandshakeStatus());
                    }
                }
                if (status == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING ) {
//                    config.inNetData.clear();
//                    config.outNetData.clear();

                    long currentCount = HANDSHAKE_COUNTER.incrementAndGet();

                    log.info(config.getHandshakeStatus() + " **************************FINISHED***************************** " + currentCount);
                    SSLSession sslSession = config.getSession();

                    log.info("Handshake session: " + SharedUtil.toCanonicalID(':',sslSession.getProtocol(),
                            sslSession.getCipherSuite(),
                            SharedStringUtil.bytesToHex(sslSession.getId())));


                    if(!config.firstHandshake.getAndSet(true))
                    {

                        // for a weir reason we need todo maybe 2 sslsession.beginhandshake with tlsv1.3
                        if (sslSession.getProtocol().equalsIgnoreCase("tlsv1.3"))
                        {
//                            try
//                            {
                                config.beginHandshake();
                                log.info("AFTER FIRST HANDSHAKE : " + config.getHandshakeStatus());
                                publish(sslChannel, SSLSessionSM.SessionState.HANDSHAKING);
                                return;
//                            }
//                            catch (Exception e)
//                            {
//                                e.printStackTrace();
//                            }
                        }
                    }

                    publish(sslChannel, SSLSessionSM.SessionState.READY);



//                    TaskUtil.getDefaultTaskScheduler().queue(1000, ()->{
//                        log.info(" )()()()()()()()()()()()()()()()()()() " +config.getHandshakeStatus());
//                    });
                }
            } catch (Exception e) {
                e.printStackTrace();
                publish(sslChannel, SSLSessionSM.SessionState.CLOSE);
            }
        }

    }


    private SSLEngineResult postHandshakeIfNeeded(SSLSessionConfig config,  SSLEngineResult res, SocketChannel sslChannel) throws IOException {
        while (res.getHandshakeStatus() == FINISHED && res.getStatus() == SSLEngineResult.Status.OK) {
            if (!config.inNetData.hasRemaining()) {

                int byteRead = sslChannel.read(config.inNetData);
                if(byteRead == -1)
                    throw new IOException("ssl socket closed");
            }
            res = config.smartUnwrap(config.inNetData, ByteBufferUtil.EMPTY);

        }
        return res;
    }
}
