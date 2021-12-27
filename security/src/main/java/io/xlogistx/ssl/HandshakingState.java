package io.xlogistx.ssl;

import io.xlogistx.common.fsm.State;
import io.xlogistx.common.fsm.TriggerConsumer;
import io.xlogistx.common.task.CallbackTask;
import org.zoxweb.server.io.ByteBufferUtil;
import org.zoxweb.shared.util.SharedUtil;

import javax.net.ssl.SSLEngineResult;
import java.nio.ByteBuffer;
import java.util.logging.Logger;

import static io.xlogistx.ssl.SSLStateMachine.SessionState.POST_HANDSHAKE;
import static javax.net.ssl.SSLEngineResult.HandshakeStatus.*;

public class HandshakingState extends State {
    private static final transient Logger log = Logger.getLogger(HandshakingState.class.getName());
    public static boolean debug = false;

    static class NeedWrap extends TriggerConsumer<CallbackTask<ByteBuffer>>
    {
        //private UByteArrayOutputStream baos = new UByteArrayOutputStream(512);
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
              SSLEngineResult result = config.smartWrap(ByteBufferUtil.EMPTY, config.outSSLNetData); // at handshake stage, data in appOut won't be
              // processed hence dummy buffer
              if (debug) log.info("AFTER-NEED_WRAP-HANDSHAKING: " + result);

              switch (result.getStatus())
              {
                case BUFFER_UNDERFLOW:
                case BUFFER_OVERFLOW:
                    config.forcedClose = true;
                    throw new IllegalStateException(result + " invalid state context " + config.outSSLNetData + " " + config.sslChannel.getRemoteAddress());
                case OK:
              int written =
                  ByteBufferUtil.smartWrite(config.ioLock, config.sslChannel, config.outSSLNetData);

                    if (debug) log.info("After writing data HANDSHAKING-NEED_WRAP: " + config.outSSLNetData + " written:" + written);
                  publishSync(result.getHandshakeStatus(), callback);
                  break;
                case CLOSED:
                    config.close();
                  //publishSync(SSLStateMachine.SessionState.CLOSE, callback);
                  break;
              }

            }
            catch (Exception e)
            {
              log.info(""+e);
              config.close();
              //publishSync(SSLStateMachine.SessionState.CLOSE, callback);
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
                //publishSync(SSLStateMachine.SessionState.CLOSE, callback);
                  config.close();

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
                      publishSync(result.getHandshakeStatus(), callback);
//                      if(config.inAppData.position() > 0 )
//                          callback.callback(config.inAppData);

//                      if(config.inAppData.position() > 0 )
//                          callback.callback(config.inAppData);
//                    if(callback != null) callback.callback(null);
                    break;
                  case CLOSED:
                    // check result here
                   if (debug) log.info("CLOSED-DURING-NEED_UNWRAP: " + result + " bytesread: " + bytesRead);

                    //publishSync(SSLStateMachine.SessionState.CLOSE, callback);
                      config.close();
                    break;
                }
              }
            } catch (Exception e) {
              e.printStackTrace();
              config.close();
//              publishSync(SSLStateMachine.SessionState.CLOSE, callback);
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
            SSLEngineResult.HandshakeStatus status = config.getHandshakeStatus();
            if (debug) log.info("After run: " + status);
            publishSync(status, callback);
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
            publishSync(status, callback);
        }

    }


    static class NotHandshaking extends TriggerConsumer<CallbackTask<ByteBuffer>>
    {
        NotHandshaking() {
            super(NOT_HANDSHAKING);
        }

        @Override
        public void accept(CallbackTask<ByteBuffer> callback)
        {
            SSLSessionConfig config = (SSLSessionConfig) getState().getStateMachine().getConfig();
            // VERY CRUCIAL STEP TO BE PERFORMED
            config.sslos = new SSLOutputStream(config, false );
            publishSync(POST_HANDSHAKE, null);

            if (config.inSSLNetData.position() > 0)
            {
                // we have data
                // the mother of all nasties
                publishSync(NEED_UNWRAP, callback);
            }

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
