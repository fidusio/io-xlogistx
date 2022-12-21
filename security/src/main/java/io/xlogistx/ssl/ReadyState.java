package io.xlogistx.ssl;

import io.xlogistx.common.fsm.State;
import io.xlogistx.common.fsm.TriggerConsumer;
import org.zoxweb.server.task.TaskCallback;

import javax.net.ssl.SSLEngineResult;
import java.nio.ByteBuffer;

import static javax.net.ssl.SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;

public class ReadyState
        extends State
{

    public static final String APP_DATA = "APP_DATA";


    static class AppData extends TriggerConsumer<TaskCallback<ByteBuffer, SSLChannelOutputStream>>
    {
        AppData() {
            super(APP_DATA);
        }

    @Override
    public void accept(TaskCallback<ByteBuffer, SSLChannelOutputStream> callback)
    {
      SSLSessionConfig config = (SSLSessionConfig) getState().getStateMachine().getConfig();
      if(log.isEnabled()) log.getLogger().info("" + config.getHandshakeStatus());
      if (config.getHandshakeStatus() == NOT_HANDSHAKING && config.sslChannel.isOpen())
      {
        try {

              int bytesRead = config.sslChannel.read(config.inSSLNetData);
              if (bytesRead == -1) {

                  log.getLogger().info(
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


                if (log.isEnabled())
                    log.getLogger().info("AFTER-NEED_UNWRAP-PROCESSING: " + result + " bytesread: " + bytesRead + " callback: " + callback);
                switch (result.getStatus())
                {
                  case BUFFER_UNDERFLOW:
                    // no incoming data available we need to wait for more socket data
                    // return and let the NIOSocket or the data handler call back
                    //config.sslChannelSelectableStatus.set(true);
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

                      if(log.isEnabled()) log.getLogger().info("CLOSED-DURING-NEED_UNWRAP: " + result + " bytesread: " + bytesRead);

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
      }
    }














    public ReadyState() {
        super(SSLStateMachine.SessionState.READY);
        register(new AppData());
        //register(new NeedWrap())
    }

}
