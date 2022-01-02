package io.xlogistx.ssl;

import io.xlogistx.common.fsm.State;
import io.xlogistx.common.fsm.TriggerConsumer;

import org.zoxweb.server.task.TaskCallback;

import javax.net.ssl.SSLEngineResult;
import java.nio.ByteBuffer;
import java.util.logging.Logger;

import static javax.net.ssl.SSLEngineResult.HandshakeStatus.*;

public class ReadyState extends State {
    private static final transient Logger log = Logger.getLogger(ReadyState.class.getName());
    public static boolean debug = false;

    private static void info(String str)
    {
        if(debug)
            log.info(str);
    }
//    class NeedWrap extends TriggerConsumer<CallbackTask<ByteBuffer>>
//    {
//
//
//        NeedWrap() {
//            super(NEED_WRAP);
//        }
//
//        @Override
//        public void accept(CallbackTask<ByteBuffer> callback)
//        {
//
//            SSLSessionConfig config = (SSLSessionConfig) getState().getStateMachine().getConfig();
//            if (config.getHandshakeStatus() == NOT_HANDSHAKING)
//            {
//
//
//                try {
//                    int bytesRead = config.remoteChannel.read(config.inRemoteData);
//                    if (bytesRead == -1) {
//
//                          info(
//                              "SSLCHANNEL-CLOSED-NEED_UNWRAP: "
//                                  + config.getHandshakeStatus()
//                                  + " bytesread: "
//                                  + bytesRead);
//
//                        config.close();
//
//                        return;
//                    }
//                     config.sslos.write(config.inRemoteData);
//
//                } catch (Exception e) {
//
//                  if(callback != null)callback.exception(e);
//                  config.close();
//
//                }
//            }
//
//        }
//    }

    class NeedUnwrap extends TriggerConsumer<TaskCallback<ByteBuffer, SSLChanelOutputStream>>
    {
        NeedUnwrap() {
            super(NEED_UNWRAP);
        }

    @Override
    public void accept(TaskCallback<ByteBuffer, SSLChanelOutputStream> callback) {
      SSLSessionConfig config = (SSLSessionConfig) getState().getStateMachine().getConfig();
      if(debug) log.info("" + config.getHandshakeStatus());
      if (config.getHandshakeStatus() == NOT_HANDSHAKING && config.sslChannel.isOpen()) {
        try {

              int bytesRead = config.sslChannel.read(config.inSSLNetData);
              if (bytesRead == -1) {

                  info(
                      "SSLCHANNEL-CLOSED-NEED_UNWRAP: "
                          + config.getHandshakeStatus()
                          + " bytesread: "
                          + bytesRead);
                  config.close();
              }
              else
              {

                // even if we have read zero it will trigger BUFFER_UNDERFLOW then we wait for incoming
                // data
                SSLEngineResult result = config.smartUnwrap(config.inSSLNetData, config.inAppData);


                if (debug) log.info("AFTER-NEED_UNWRAP-PROCESSING: " + result + " bytesread: " + bytesRead + " callback: " + callback);
                switch (result.getStatus()) {
                  case BUFFER_UNDERFLOW:
                    // no incoming data available we need to wait for more socket data
                    // return and let the NIOSocket or the data handler call back
                    // config.sslChannelSelectableStatus.set(true);
                    //config.sslRead.set(true);
                    return;

                  case BUFFER_OVERFLOW:
                    throw new IllegalStateException("NEED_UNWRAP should never be " + result.getStatus());
                    // this should never happen
                  case OK:

                    if(callback != null) callback.accept(config.inAppData);
                     // config.sslRead.set(true);
                    break;
                  case CLOSED:
                    // check result here

                      if(debug) log.info("CLOSED-DURING-NEED_UNWRAP: " + result + " bytesread: " + bytesRead);

                    config.close();
                    break;
                }
              }
            } catch (Exception e) {
              //e.printStackTrace();
                if(callback != null)callback.exception(e);

                config.close();
            }
        }
      }
    }














    public ReadyState() {
        super(SSLStateMachine.SessionState.READY);
        register(new NeedUnwrap());
        //register(new NeedWrap())
    }

}
