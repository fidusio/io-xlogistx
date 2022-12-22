package io.xlogistx.ssl;

import io.xlogistx.common.fsm.State;
import io.xlogistx.common.fsm.TriggerConsumer;
import org.zoxweb.server.io.ByteBufferUtil;
import org.zoxweb.server.task.TaskCallback;
import org.zoxweb.shared.util.SharedUtil;

import javax.net.ssl.SSLEngineResult;
import java.nio.ByteBuffer;
import java.util.concurrent.atomic.AtomicLong;

import static io.xlogistx.ssl.SSLStateMachine.SessionState.POST_HANDSHAKE;
import static javax.net.ssl.SSLEngineResult.HandshakeStatus.*;

public class SSLHandshakingState extends State {

    private final static AtomicLong counter = new AtomicLong(0);

    static class NeedWrap extends TriggerConsumer<TaskCallback<ByteBuffer, SSLChannelOutputStream>>
    {
        //private UByteArrayOutputStream baos = new UByteArrayOutputStream(512);
        NeedWrap()
        {
            super(NEED_WRAP);
        }
        @Override
        public void accept(TaskCallback<ByteBuffer, SSLChannelOutputStream> callback)
        {
            SSLSessionConfig config = (SSLSessionConfig) getState().getStateMachine().getConfig();
            if (config.getHandshakeStatus() == NEED_WRAP)
            {
              try
              {
                  SSLEngineResult result = config.smartWrap(ByteBufferUtil.EMPTY, config.outSSLNetData);
                  // at handshake stage, data in appOut won't be
                  // processed hence dummy buffer
                  if (log.isEnabled())
                      log.getLogger().info("AFTER-NEED_WRAP-HANDSHAKING: " + result);

                  switch (result.getStatus())
                  {
                      case BUFFER_UNDERFLOW:
                      case BUFFER_OVERFLOW:
                          config.forcedClose = true;
                          throw new IllegalStateException(result + " invalid state context " + config.outSSLNetData + " " + config.sslChannel.getRemoteAddress());
                      case OK:
                          int written = ByteBufferUtil.smartWrite(null, config.sslChannel, config.outSSLNetData);
                          if (log.isEnabled())
                              log.getLogger().info(result.getHandshakeStatus() + " After writing data HANDSHAKING-NEED_WRAP: " + config.outSSLNetData + " written:" + written);
                          publishSync(result.getHandshakeStatus(), callback);
                          break;
                      case CLOSED:
                          config.close();
                          break;
                  }
              }
              catch (Exception e)
              {
                  if(log.isEnabled())
                      e.printStackTrace();

                  config.close();
              }
            }
        }
    }

    static class NeedUnwrap extends TriggerConsumer<TaskCallback<ByteBuffer, SSLChannelOutputStream>>
    {
        NeedUnwrap()
        {
            super("NEED_UNWRAP", "NEED_UNWRAP_AGAIN");
        }

    @Override
    public void accept(TaskCallback<ByteBuffer, SSLChannelOutputStream> callback)
    {
        SSLSessionConfig config = (SSLSessionConfig) getState().getStateMachine().getConfig();
        if(log.isEnabled()) log.getLogger().info("Entry: " + config.getHandshakeStatus());

        if (config.getHandshakeStatus() == NEED_UNWRAP || SharedUtil.enumName(config.getHandshakeStatus()).equals("NEED_UNWRAP_AGAIN"))
        {
            try {

                  int bytesRead = config.sslChannel.read(config.inSSLNetData);
                  if (bytesRead == -1)
                  {
                      if (log.isEnabled()) log.getLogger().info("SSLCHANNEL-CLOSED-NEED_UNWRAP: " + config.getHandshakeStatus() + " bytes read: " + bytesRead);
                      config.close();
                  }
                  else //if (bytesRead > 0)
                  {

                    // even if we have read zero it will trigger BUFFER_UNDERFLOW then we wait for incoming
                    // data
                    if (log.isEnabled()) log.getLogger().info("BEFORE-UNWRAP: " + config.inSSLNetData + " bytes read " + bytesRead);
                    SSLEngineResult result = config.smartUnwrap(config.inSSLNetData, ByteBufferUtil.EMPTY);


                  if (log.isEnabled()) log.getLogger().info("AFTER-NEED_UNWRAP-HANDSHAKING: " + result + " bytes read: " + bytesRead);
                  if (log.isEnabled()) log.getLogger().info("AFTER-NEED_UNWRAP-HANDSHAKING inNetData: " + config.inSSLNetData + " inAppData: " +  config.inAppData);

                    switch (result.getStatus()) {
                      case BUFFER_UNDERFLOW:
                        // no incoming data available we need to wait for more socket data
                        // return and let the NIOSocket or the data handler call back
                        // config.sslChannelSelectableStatus.set(true);
                        // config.sslRead.set(true);
                        return;
                      case BUFFER_OVERFLOW:
                        throw new IllegalStateException("NEED_UNWRAP should never happen: " + result.getStatus());
                        // this should never happen
                      case OK:
                          publishSync(result.getHandshakeStatus(), callback);
                        break;
                      case CLOSED:
                        // check result here
                       if (log.isEnabled()) log.getLogger().info("CLOSED-DURING-NEED_UNWRAP: " + result + " bytes read: " + bytesRead);
                          config.close();
                        break;
                    }
                  }
            }
            catch (Exception e)
            {
                if(log.isEnabled())
                    e.printStackTrace();
                config.close();
            }
          }
//        else
//        {
//            if (log.isEnabled()) log.getLogger().info("we are in unwrap and status: " + config.getHandshakeStatus());
//
//            publishSync(config.getHandshakeStatus(), callback);
//
//        }

    }
    }





    static class NeedTask extends TriggerConsumer<TaskCallback<ByteBuffer, SSLChannelOutputStream>>
    {
        NeedTask() {
            super(NEED_TASK);
        }

        @Override
        public void accept(TaskCallback<ByteBuffer, SSLChannelOutputStream> callback) {
            SSLSessionConfig config = (SSLSessionConfig) getState().getStateMachine().getConfig();
            Runnable toRun;
            while((toRun = config.getDelegatedTask()) != null)
            {
                toRun.run();

            }
            SSLEngineResult.HandshakeStatus status = config.getHandshakeStatus();
            if (log.isEnabled())
                log.getLogger().info("After run: " + status);
            publishSync(status, callback);
        }
    }



    static class Finished extends TriggerConsumer<TaskCallback<ByteBuffer, SSLChannelOutputStream>>
    {

        Finished() {
            super(FINISHED);
        }

        @Override
        public void accept(TaskCallback<ByteBuffer, SSLChannelOutputStream> callback) {
            SSLSessionConfig config = (SSLSessionConfig) getState().getStateMachine().getConfig();


            // ********************************************
            // Very crucial steps
            // ********************************************
            if(config.remoteAddress != null)
            {
                // we have a SSL tunnel
                publishSync(POST_HANDSHAKE, config);
            }

            if (config.inSSLNetData.position() > 0)
            {
                //**************************************************
                // ||-----DATA BUFFER------ ||
                // ||Handshake data|App data||
                // ||-----------------------||
                // The buffer has app data that needs to be decrypted
                //**************************************************
                publishSync(config.getHandshakeStatus(), callback);
            }
        }
    }











    public SSLHandshakingState() {
        super(SSLStateMachine.SessionState.HANDSHAKING);
        counter.incrementAndGet();
        register(new NeedTask())
                .register(new NeedWrap())
                .register(new NeedUnwrap())
                .register(new Finished())
                ;

    }

}
