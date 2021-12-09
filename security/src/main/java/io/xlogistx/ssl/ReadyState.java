package io.xlogistx.ssl;

import io.xlogistx.common.fsm.State;
import io.xlogistx.common.fsm.TriggerConsumer;
import io.xlogistx.common.task.CallbackTask;

import javax.net.ssl.SSLEngineResult;
import java.nio.ByteBuffer;
import java.util.logging.Logger;

import static javax.net.ssl.SSLEngineResult.HandshakeStatus.*;

public class ReadyState extends State {
    private static final transient Logger log = Logger.getLogger(ReadyState.class.getName());
    public static boolean debug = true;

    private static void info(String str)
    {
        if(debug)
            log.info(str);
    }
    class NeedWrap extends TriggerConsumer<CallbackTask<ByteBuffer>>
    {
        NeedWrap() {
            super(NEED_WRAP);
        }

        @Override
        public void accept(CallbackTask<ByteBuffer> callback)
        {

            SSLSessionConfig config = (SSLSessionConfig) getState().getStateMachine().getConfig();
            if (config.getHandshakeStatus() == NOT_HANDSHAKING)
            {
                try {
                    int bytesRead = config.remoteChannel.read(config.inRemoteData);
                    if (bytesRead == -1) {

                          info(
                              "SSLCHANNEL-CLOSED-NEED_UNWRAP: "
                                  + config.getHandshakeStatus()
                                  + " bytesread: "
                                  + bytesRead);
                        publish(SSLStateMachine.SessionState.CLOSE, callback);
                        return;
                    }


                  SSLEngineResult result = config.smartWrap(config.inRemoteData, config.outSSLNetData); // at handshake stage, data in appOut won't be

                  info("AFTER-NEED_WRAP-PROCESSING: " + result);

                  switch (result.getStatus()) {
                    case BUFFER_UNDERFLOW:
                    case BUFFER_OVERFLOW:
                      throw new IllegalStateException(result.getStatus() + " invalid state context");
                    case OK:
                      if(callback != null ) callback.callback(config.outSSLNetData);

                      break;
                    case CLOSED:
                      publish(SSLStateMachine.SessionState.CLOSE, callback);
                      break;
                  }

                } catch (Exception e) {
                  //e.printStackTrace();
                  publish(SSLStateMachine.SessionState.CLOSE, callback);
                }
            }

        }
    }

    class NeedUnwrap extends TriggerConsumer<CallbackTask<ByteBuffer>>
    {
        NeedUnwrap() {
            super(NEED_UNWRAP);
        }

    @Override
    public void accept(CallbackTask<ByteBuffer> callback) {
      SSLSessionConfig config = (SSLSessionConfig) getState().getStateMachine().getConfig();
      if (config.getHandshakeStatus() == NOT_HANDSHAKING) {
        try {

              int bytesRead = config.sslChannel.read(config.inSSLNetData);
              if (bytesRead == -1) {

                  info(
                      "SSLCHANNEL-CLOSED-NEED_UNWRAP: "
                          + config.getHandshakeStatus()
                          + " bytesread: "
                          + bytesRead);
                publish(SSLStateMachine.SessionState.CLOSE, callback);
                return;
              }
              else //if(bytesRead > 0)
              {

                // even if we have read zero it will trigger BUFFER_UNDERFLOW then we wait for incoming
                // data
                SSLEngineResult result = config.smartUnwrap(config.inSSLNetData, config.inAppData);


                  info("AFTER-NEED_UNWRAP-PROCESSING: " + result + " bytesread: " + bytesRead);
                switch (result.getStatus()) {
                  case BUFFER_UNDERFLOW:
                    // no incoming data available we need to wait for more socket data
                    // return and let the NIOSocket or the data handler call back
                    // config.sslChannelSelectableStatus.set(true);
                    return;

                  case BUFFER_OVERFLOW:
                    throw new IllegalStateException("NEED_UNWRAP should never be " + result.getStatus());
                    // this should never happen
                  case OK:
//                    publish(config, result.getHandshakeStatus());
                    if(callback != null) callback.callback(config.inAppData);
                    break;
                  case CLOSED:
                    // check result here

                      info("CLOSED-DURING-NEED_UNWRAP: " + result + " bytesread: " + bytesRead);

                    publish(SSLStateMachine.SessionState.CLOSE, callback);
                    break;
                }
              }
            } catch (Exception e) {
              //e.printStackTrace();
              publish(SSLStateMachine.SessionState.CLOSE, callback);
              if(callback != null)callback.exception(e);
            }
      }
        }
    }














    public ReadyState() {
        super(SSLStateMachine.SessionState.READY);

        register(new NeedWrap()).register(new NeedUnwrap());
    }

}