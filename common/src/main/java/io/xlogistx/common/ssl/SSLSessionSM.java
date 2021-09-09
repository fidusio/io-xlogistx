package io.xlogistx.common.ssl;

import io.xlogistx.common.fsm.*;
import org.zoxweb.server.io.ByteBufferUtil;


import org.zoxweb.server.task.TaskSchedulerProcessor;
import org.zoxweb.shared.util.GetName;

import javax.net.ssl.*;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SelectableChannel;
import java.nio.channels.SocketChannel;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicLong;

public class SSLSessionSM extends StateMachine<SSLSessionConfig>
{


    public enum SessionState
    implements GetName
    {
        WAIT_FOR_HANDSHAKING("wait-for-handshake"),
        HANDSHAKING("handshaking"),
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
    private static boolean debug = false;

    private SSLSessionSM(long id, TaskSchedulerProcessor tsp) {
        super("SSLSessionStateMachine-" + id, tsp);
    }
    private SSLSessionSM(long id, Executor executor) {
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





    public static SSLSessionSM create(SSLContext sslContext, Executor e)
    {
        SSLSessionConfig sslSessionConfig = new SSLSessionConfig();
        sslSessionConfig.sslContext = sslContext;
        return create(sslSessionConfig, e);
    }



    public static SSLSessionSM create(SSLSessionConfig config, Executor e){
        SSLSessionSM sslSessionSM = new SSLSessionSM(counter.getAndIncrement(), e);
        sslSessionSM.setConfig(config);

    TriggerConsumerInt<Void> init = new TriggerConsumer<Void>(StateInt.States.INIT) {
          @Override
          public void accept(Void o) {
              log.info(getState().getStateMachine().getName() + " CREATED");
            publish(new Trigger<SelectableChannel>(getState(), null, SessionState.WAIT_FOR_HANDSHAKING));
          }
        };

    TriggerConsumerInt<SelectableChannel> waitingForSSLChannel =
        new TriggerConsumer<SelectableChannel>(SessionState.WAIT_FOR_HANDSHAKING) {
          @Override
          public void accept(SelectableChannel sslChannel) {
            if(debug) log.info(SessionState.WAIT_FOR_HANDSHAKING + ":" + sslChannel);
            if (sslChannel != null) {
              SSLSessionConfig config = (SSLSessionConfig) getStateMachine().getConfig();
              if (config.sslChannel == null) {
                config.sslChannel = sslChannel;
                config.sslEngine = config.sslContext.createSSLEngine();
                // for now later support client mode
                config.sslEngine.setUseClientMode(false);
                //config.sslEngine.setNeedClientAuth(false);
                // create buffers

                  try {
                      config.sslEngine.beginHandshake();
                      config.inNetData = ByteBufferUtil.allocateByteBuffer(config.sslEngine.getSession().getPacketBufferSize());
                      config.outNetData = ByteBufferUtil.allocateByteBuffer(config.sslEngine.getSession().getPacketBufferSize());
                      config.inAppData = ByteBufferUtil.allocateByteBuffer(config.sslEngine.getSession().getApplicationBufferSize());
                      //config.outAppData = ByteBufferUtil.allocateByteBuffer(config.sslEngine.getSession().getApplicationBufferSize());
                      if(debug) log.info("handshake begun " + config.inNetData.capacity() + ":" + config.inAppData.capacity());

                      //config.sslChannelReadState = false;

                      //reset(config.inNetData, config.outNetData, config.inAppData, config.outAppData);
                      publish(sslChannel, SessionState.HANDSHAKING);
                  } catch (SSLException ex) {
                      ex.printStackTrace();

                      // maybe we should close
                  }

                  // trigger wait_for_handshake
              }
            }
          }
        };

    TriggerConsumerInt<SocketChannel> handShaking =
        new TriggerConsumer<SocketChannel>(SessionState.HANDSHAKING) {

          boolean readData = true;
          SSLEngineResult result;
          SSLEngineResult.HandshakeStatus status;

          @Override
          public void accept(SocketChannel sslChannel) {
            if(debug) log.info("[" + Thread.currentThread() + "] " + SessionState.HANDSHAKING);
            // the handshaking already started
            // we need to unwrap network data to complete the handshaking process
            SSLSessionConfig config = (SSLSessionConfig) getStateMachine().getConfig();
            if (sslChannel != null) {
              try {
                if(debug) log.info("START Handshake " + config.sslEngine.getHandshakeStatus());
                loop: while ((status = config.sslEngine.getHandshakeStatus()) != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
                  if(debug) log.info(Thread.currentThread() + " Before switch SSLServerEngine status " + status);
                  switch (status) {
                    case FINISHED:
                      break loop;
                    case NEED_WRAP:
                      result = config.sslEngine.wrap(ByteBufferUtil.DUMMY, config.outNetData); // at handshake stage, data in appOut won't be
                                                // processed hence dummy buffer
                      if (result.bytesProduced() > 0) {
                        if(debug) log.info("Before writing data : " + config.outNetData);
                        ByteBufferUtil.write(sslChannel, config.outNetData);
                        config.outNetData.clear();
                      }
                      if(debug) log.info(status + " END : " + result);
                      break;
                    case NEED_TASK:
                      Runnable task = config.sslEngine.getDelegatedTask(); // these are the tasks like key generation that
                                                   // tend to take longer time to complete
                      if (task != null) {
                        task.run(); // it can be run at a different thread.
                      }
                      break;
                    case NEED_UNWRAP:
                      if (readData) {
                        int byteRead = sslChannel.read(config.inNetData);
                        log.info("BYTE_READ from socket:" + byteRead);
                        config.inNetData.flip();
                      }
                      result =config.sslEngine.unwrap(config.inNetData, ByteBufferUtil.DUMMY);
                      // at handshake stage, no data produced in appIn hence using dummy buffer
                      log.info("[-> Read status : " + readData + " : " + result);

                      if (config.inNetData.remaining() == 0) {
                        config.inNetData.clear();
                        readData = true;
                      } else { // if there are data left in the buffer
                        readData = false;
                      }
                       log.info("Read status : " + readData + " : " + result + " <-]");
                      if (result.getStatus() == SSLEngineResult.Status.BUFFER_UNDERFLOW) {
                        // enable reading
                        //config.selectorController.enableSelectionKeyReading(sslChannel);
                        return;
                      }
                  }
                }
                if (status == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING || status == SSLEngineResult.HandshakeStatus.FINISHED) {
                  config.inNetData.clear();
                  config.outNetData.clear();

                  log.info(result + " **************************FINISHED*****************************");
                  readData = true;
                  publish(sslChannel, SessionState.READY);
                }
              } catch (IOException e) {
                e.printStackTrace();
                publish(sslChannel, SessionState.CLOSE);
              }
            }
          }
        };

        TriggerConsumerInt<SocketChannel> ready = new TriggerConsumer<SocketChannel>(SessionState.READY) {
            @Override
            public void accept(SocketChannel sslChannel) {
                if(sslChannel != null)
                {

                    SSLSessionConfig config = (SSLSessionConfig) getStateMachine().getConfig();
                    log.info("READY-STATE SSL ENGINE " + config.sslEngine.getHandshakeStatus());
                    //config.sslChannelReadState = true;
                    //config.selectorController.enableSelectionKeyReading(sslChannel);


                    //if(debug) log.info(getState().getName() + " readable " +  config.sslChannelReadState );

                }

            }
        };

        TriggerConsumerInt<SocketChannel> closed = new TriggerConsumer<SocketChannel>(SessionState.CLOSE) {
            @Override
            public void accept(SocketChannel socketChannel) {
                getStateMachine().close();
                SSLSessionConfig config = (SSLSessionConfig) getState().getStateMachine().getConfig();
                config.close();

                if(debug) log.info(getStateMachine().getName() + " " + socketChannel + " closed");
            }
        };

        sslSessionSM.setConfig(config)
            .register(new State(StateInt.States.INIT).register(init))
            .register(new State(SessionState.WAIT_FOR_HANDSHAKING).register(waitingForSSLChannel))
            .register(new State(SessionState.HANDSHAKING).register(handShaking))
            .register(new State(SessionState.READY).register(ready))
            .register(new State(SessionState.CLOSE).register(closed))
        ;


        return sslSessionSM;
    }

}
