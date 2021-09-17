package io.xlogistx.common.ssl;

import io.xlogistx.common.fsm.*;
import org.zoxweb.server.io.ByteBufferUtil;


import org.zoxweb.server.task.TaskSchedulerProcessor;
import org.zoxweb.shared.util.GetName;

import javax.net.ssl.*;

import java.nio.ByteBuffer;
import java.nio.channels.SelectableChannel;
import java.nio.channels.SocketChannel;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicLong;

public class SSLStateMachine extends StateMachine<SSLConfig>
{



    private final static AtomicLong HANDSHAKE_COUNTER = new AtomicLong();
    public enum SessionState
    implements GetName
    {
        WAIT_FOR_HANDSHAKING("wait-for-handshake"),
        HANDSHAKING("handshaking"),
//        HS_NEED_WRAP("hs_need_wrap"),
//        HS_NEED_UNWRAP("hs_need_unwrap"),
//        HS_NOT_HANDSHAKING("hs_not_handshaking"),
//        HS_FINISHED("hs_finish"),
//        HS_NEED_TASK("hs_need_task"),
        READY("ready-state"),
        CLOSE("close"),

        ;




        private final String name;
        SessionState(String name)
        {
            this.name = name;
        }
        @Override
        public String getName() {
            return name;
        }
    }


    private static final AtomicLong counter = new AtomicLong();
    private static boolean debug = true;

    private SSLStateMachine(long id, TaskSchedulerProcessor tsp) {
        super("SSLSessionStateMachine-" + id, tsp);
    }
    private SSLStateMachine(long id, Executor executor) {
        super("SSLSessionStateMachine-" + id, executor);
    }



    private static void reset(ByteBuffer appIn, ByteBuffer appOut,
                       ByteBuffer netIn,
                       ByteBuffer netOut) {
        appIn.clear();
        appOut.clear();
        netIn.clear();
        netOut.clear();
    }





    public static SSLStateMachine create(SSLContext sslContext, Executor e)
    {
        SSLConfig sslSessionConfig = new SSLConfig(sslContext);
        return create(sslSessionConfig, e);
    }



    public static SSLStateMachine create(SSLConfig config, Executor e){
        SSLStateMachine sslSessionSM = new SSLStateMachine(counter.incrementAndGet(), e);
        sslSessionSM.setConfig(config);

    TriggerConsumerInt<Void> init = new TriggerConsumer<Void>(StateInt.States.INIT) {
          @Override
          public void accept(Void o) {
              log.info(getState().getStateMachine().getName() + " CREATED");
            publish(new Trigger<SelectableChannel>(getState(), null, SessionState.WAIT_FOR_HANDSHAKING));
          }
        };

    TriggerConsumerInt<SocketChannel> waitingForSSLChannel =
        new TriggerConsumer<SocketChannel>(SessionState.WAIT_FOR_HANDSHAKING) {
          @Override
          public void accept(SocketChannel sslChannel) {
            if(debug) log.info(SessionState.WAIT_FOR_HANDSHAKING + ":" + sslChannel);
            if (sslChannel != null) {
              SSLConfig config = (SSLConfig) getStateMachine().getConfig();
              if (config.sslChannel == null) {
                config.sslChannel = sslChannel;
                //config.sslEngine = config.sslContext.createSSLEngine();
                // for now later support client mode
                config.setUseClientMode(false);
                //config.sslEngine.setNeedClientAuth(false);
                // create buffers

                  try {
                      config.beginHandshake();
                      config.inNetData = ByteBufferUtil.allocateByteBuffer(config.getPacketBufferSize());
                      config.outNetData = ByteBufferUtil.allocateByteBuffer(config.getPacketBufferSize());
                      config.inAppData = ByteBufferUtil.allocateByteBuffer(config.getApplicationBufferSize());
                      //config.outAppData = ByteBufferUtil.allocateByteBuffer(config.sslEngine.getSession().getApplicationBufferSize());
                      if(debug) log.info("handshake begun " + config.inNetData.capacity() + ":" + config.inAppData.capacity());

                      //config.sslChannelReadState = false;

                      //reset(config.inNetData, config.outNetData, config.inAppData, config.outAppData);
                      publish(sslChannel, SessionState.HANDSHAKING);

                      // to be changed to
                      //publish(config, config.getHandshakeStatus());
                  } catch (SSLException ex) {
                      ex.printStackTrace();
                      config.close();

                      // maybe we should close
                  }

                  // trigger wait_for_handshake
              }
            }
          }
        };


        TriggerConsumerInt<SocketChannel> ready = new TriggerConsumer<SocketChannel>(SessionState.READY) {
            @Override
            public void accept(SocketChannel sslChannel) {
                if(sslChannel != null)
                {
                    SSLConfig config = (SSLConfig) getStateMachine().getConfig();
                    log.info(getStateMachine().getName() + " socket status " +sslChannel.isOpen() + " READY-STATE SSL ENGINE " + config.getHandshakeStatus()  + " " + sslChannel);
                    //config.sslChannelSelectableStatus.set(true);
                }
            }
        };

        TriggerConsumerInt<SocketChannel> closed = new TriggerConsumer<SocketChannel>(SessionState.CLOSE) {
            @Override
            public void accept(SocketChannel socketChannel) {
                getStateMachine().close();
                SSLConfig config = (SSLConfig) getState().getStateMachine().getConfig();
                config.close();

                if(debug) log.info(getStateMachine().getName() + " " + socketChannel + " closed");
            }
        };

        sslSessionSM.setConfig(config)
            .register(new State(StateInt.States.INIT).register(init))
            .register(new State(SessionState.WAIT_FOR_HANDSHAKING).register(waitingForSSLChannel))
            .register(new State(SessionState.HANDSHAKING).register(new HandshakingTC()))
            .register(new State(SessionState.READY).register(ready))
            .register(new State(SessionState.CLOSE).register(closed))
        ;


        return sslSessionSM;
    }

}
