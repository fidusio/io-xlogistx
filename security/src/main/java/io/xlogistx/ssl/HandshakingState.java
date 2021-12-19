package io.xlogistx.ssl;

import io.xlogistx.common.fsm.State;
import io.xlogistx.common.fsm.TriggerConsumer;
import io.xlogistx.common.task.CallbackTask;
import org.zoxweb.server.io.ByteBufferUtil;
import org.zoxweb.server.io.UByteArrayOutputStream;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.server.util.RuntimeUtil;
import org.zoxweb.shared.util.SharedStringUtil;
import org.zoxweb.shared.util.SharedUtil;

import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLSession;

import java.nio.ByteBuffer;
import java.util.logging.Logger;

import static javax.net.ssl.SSLEngineResult.HandshakeStatus.*;

public class HandshakingState extends State {
    private static final transient Logger log = Logger.getLogger(HandshakingState.class.getName());
    public static boolean debug = false;

    static class NeedWrap extends TriggerConsumer<CallbackTask<ByteBuffer>>
    {
        private UByteArrayOutputStream baos = new UByteArrayOutputStream(512);
        NeedWrap() {
            super(NEED_WRAP);
        }

    @Override
    public void accept(CallbackTask<ByteBuffer> callback) {
      SSLSessionConfig config = (SSLSessionConfig) getState().getStateMachine().getConfig();
      if (config.getHandshakeStatus() == NEED_WRAP)
      {
            try
            {
              String msg = "[-> " + config.outSSLNetData + " ";

              //if(config.outSSLNetData.hasRemaining()) config.outSSLNetData.clear();

              SSLEngineResult result = config.smartWrap(ByteBufferUtil.EMPTY, config.outSSLNetData); // at handshake stage, data in appOut won't be
              msg+= config.outSSLNetData;
              // processed hence dummy buffer
              if (debug) log.info("AFTER-NEED_WRAP-HANDSHAKING: " + result);

              switch (result.getStatus())
              {
                case BUFFER_UNDERFLOW:
                    throw new IllegalStateException(result.getStatus() + " invalid state context");
                case BUFFER_OVERFLOW:
                    // should process it differently
//                    config.outSSLNetData.compact();
                    //ByteBufferUtil.smartWrite(config.ioLock, config.sslChannel, config.outSSLNetData, false);

                    //
                  //throw new IllegalStateException(result.getStatus() + " invalid state context");

                    //publish(result.getHandshakeStatus(),  callback);
                    //config.outSSLNetData.rewind();
                    //config.outSSLNetData.limit(config.outSSLNetData.capacity());
//                    int appSize = config.getApplicationBufferSize();
//                    ByteBuffer b = ByteBuffer.allocate(appSize + config.outSSLNetData.position());
//                    config.outSSLNetData.flip();
//                    b.put(config.outSSLNetData);
//                    config.outSSLNetData = b;
                    // retry the operation.

                    baos.reset();
                    ByteBufferUtil.write(config.outSSLNetData, baos, false);
                    config.outSSLNetData.reset();
                    ByteBufferUtil.write(baos, config.outSSLNetData);


                    log.info(msg + " " + result + " " + config.outSSLNetData + " <-]");
                    //log.info("STACKTRACE\n" + RuntimeUtil.stackTrace());
                    //publish(config.getHandshakeStatus(), callback);
                  break;
                case OK:
              int written =
                  ByteBufferUtil.smartWrite(config.ioLock, config.sslChannel, config.outSSLNetData);
                  // postHandshakeIfNeeded(config, result, sslChannel);

                    if (debug) log.info("After writing data HANDSHAKING-NEED_WRAP: " + config.outSSLNetData + " written:" + written);
                  publish(result.getHandshakeStatus(), callback);
                  break;
                case CLOSED:
                    config.close();
                  //publish(SSLStateMachine.SessionState.CLOSE, callback);
                  break;
              }

            }
            catch (Exception e)
            {
              e.printStackTrace();
              config.close();
              //publish(SSLStateMachine.SessionState.CLOSE, callback);
            }
          }
        }
    }

    static class NeedUnwrap extends TriggerConsumer<CallbackTask<ByteBuffer>>
    {
        NeedUnwrap() {
            super("NEED_UNWRAP", "NEED_UNWRAP_AGAIN");
        }

    @Override
    public void accept(CallbackTask<ByteBuffer> callback) {
      SSLSessionConfig config = (SSLSessionConfig) getState().getStateMachine().getConfig();
      if (config.getHandshakeStatus() == NEED_UNWRAP || SharedUtil.enumName(config.getHandshakeStatus()).equals("NEED_UNWRAP_AGAIN")) {
        try {

              int bytesRead = config.sslChannel.read(config.inSSLNetData);
              if (bytesRead == -1) {
                if (debug) log.info(
                      "SSLCHANNEL-CLOSED-NEED_UNWRAP: "
                          + config.getHandshakeStatus()
                          + " bytesread: "
                          + bytesRead);
                //publish(SSLStateMachine.SessionState.CLOSE, callback);
                  config.close();
                return;
              }
              else //if (bytesRead > 0)
              {

                // even if we have read zero it will trigger BUFFER_UNDERFLOW then we wait for incoming
                // data
                if (debug) log.info("BEFORE-UNWRAP: " + config.inSSLNetData);
                SSLEngineResult result = config.smartUnwrap(config.inSSLNetData, ByteBufferUtil.EMPTY);


              if (debug) log.info("AFTER-NEED_UNWRAP-HANDSHAKING: " + result + " bytesread: " + bytesRead);
              if (debug) log.info("AFTER-NEED_UNWRAP-HANDSHAKING inNetData: " + config.inSSLNetData + " inAppData: " +  config.inAppData);

                switch (result.getStatus()) {
                  case BUFFER_UNDERFLOW:
                    // no incoming data available we need to wait for more socket data
                    // return and let the NIOSocket or the data handler call back
                    // config.sslChannelSelectableStatus.set(true);
                    // config.sslRead.set(true);
                    return;

                  case BUFFER_OVERFLOW:
                    throw new IllegalStateException("NEED_UNWRAP should never be " + result.getStatus());
                    // this should never happen
                  case OK:
                      publish(result.getHandshakeStatus(), callback);
//                      if(config.inAppData.position() > 0 )
//                          callback.callback(config.inAppData);

//                      if(config.inAppData.position() > 0 )
//                          callback.callback(config.inAppData);
//                    if(callback != null) callback.callback(null);
                    break;
                  case CLOSED:
                    // check result here
                   if (debug) log.info("CLOSED-DURING-NEED_UNWRAP: " + result + " bytesread: " + bytesRead);

                    //publish(SSLStateMachine.SessionState.CLOSE, callback);
                      config.close();
                    break;
                }
              }
            } catch (Exception e) {
              e.printStackTrace();
              config.close();
//              publish(SSLStateMachine.SessionState.CLOSE, callback);
//              if(callback != null)callback.exception(e);
            }
      }
        }
    }





    static class NeedTask extends TriggerConsumer<CallbackTask<ByteBuffer>>
    {
        NeedTask() {
            super(NEED_TASK);
        }

        @Override
        public void accept(CallbackTask<ByteBuffer> callback) {
            SSLSessionConfig config = (SSLSessionConfig) getState().getStateMachine().getConfig();
            Runnable toRun;
            /*= config.getDelegatedTask();
            if(toRun != null)
                toRun.run();*/
            while((toRun = config.getDelegatedTask()) != null)
            {
                toRun.run();

            }
            SSLEngineResult.HandshakeStatus status = config.getHandshakeStatus();;
            if (debug) log.info("After run: " + status);
            publish(status, callback);
        }
    }



    static class Finished extends TriggerConsumer<CallbackTask<ByteBuffer>>
    {
        Finished() {
            super(FINISHED);
        }

        @Override
        public void accept(CallbackTask<ByteBuffer> callback) {
            SSLSessionConfig config = (SSLSessionConfig) getState().getStateMachine().getConfig();
            SSLEngineResult.HandshakeStatus status = config.getHandshakeStatus();
            if (status != NOT_HANDSHAKING)
                log.info("Finished: " + status);
            publish(status, callback);
        }

    }


    static class NotHandshaking extends TriggerConsumer<CallbackTask<ByteBuffer>>
    {
        boolean first = false;
        NotHandshaking() {
            super(NOT_HANDSHAKING);
        }

        @Override
        public void accept(CallbackTask<ByteBuffer> callback) {
            SSLSessionConfig config = (SSLSessionConfig) getState().getStateMachine().getConfig();

//            SSLEngineResult result = null;
//            try {
//                 result = config.smartWrap(ByteBufferUtil.EMPTY, config.outNetData);
//                if (debug) log.info("LAST-WRAP:" + result + " out buffer: " + config.outNetData);
//                switch (result.getStatus())
//                {
//
//                    case BUFFER_UNDERFLOW:
//                        break;
//                    case BUFFER_OVERFLOW:
//                        break;
//                    case OK:
//                        if(config.outNetData.position() > 0)
//                            ByteBufferUtil.smartWrite(config.ioLock, config.sslChannel, config.outNetData);
//
//                        if (result.getHandshakeStatus() != NOT_HANDSHAKING) {
//                          publish(config.getHandshakeStatus(), callback);
//                          return;
//                        }
//                        break;
//                    case CLOSED:
//                        publish(SSLStateMachine.SessionState.CLOSE, callback);
//                        return;
//
//                }
//
//            } catch (Exception e) {
//                e.printStackTrace();
//            }

        SSLSession sslSession = config.getSession();
        //log.info("Handshake session: " + SharedUtil.toCanonicalID(':',sslSession.getProtocol(), sslSession.getCipherSuite(), config.inSSLNetData));

        if (config.inSSLNetData.position() > 0)
        {
            // we have data
            // the mother of all nasties
            publish(NEED_UNWRAP, callback);
        }
//        else
//            config.sslRead.set(true);
            //publish(SSLStateMachine.SessionState.READY, callback);

        }
    }





    public HandshakingState() {
        super(SSLStateMachine.SessionState.HANDSHAKING);
        register(new NeedTask())
                .register(new NeedWrap())
                .register(new NeedUnwrap())
                .register(new Finished())
                .register(new NotHandshaking())
                ;

    }

}
