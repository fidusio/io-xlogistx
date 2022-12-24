package io.xlogistx.ssl;

import io.xlogistx.common.fsm.*;
import org.zoxweb.server.task.TaskCallback;
import org.zoxweb.shared.crypto.SSLContextInfo;
import org.zoxweb.shared.util.GetName;

import java.nio.ByteBuffer;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicLong;

public class SSLStateMachine extends StateMachine<SSLSessionConfig>
{



    //private final static AtomicLong HANDSHAKE_COUNTER = new AtomicLong();
    public enum SessionState
    implements GetName
    {
        READY("ready-state"),
        HANDSHAKING("handshaking"),
        POST_HANDSHAKE("post-handshake"),


        /**
         * Read data state will unwrap data via it trigger in the read state
         * and in the handshaking state will unwrap data for the handshake process
         * it is identified by checking the SSLEngine NOT_HANDSHAKING status
         */

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


//    private SSLStateMachine(long id, TaskSchedulerProcessor tsp) {
//        super("SSLSessionStateMachine-" + id, tsp);
//    }
    private SSLStateMachine(long id, Executor executor) {
        super("SSLSessionStateMachine-" + id, executor);
    }









    public static SSLStateMachine create(SSLContextInfo sslContext, Executor e)
    {
        SSLSessionConfig sslSessionConfig = new SSLSessionConfig(sslContext);
        return create(sslSessionConfig, e);
    }



    public static SSLStateMachine create(SSLSessionConfig config, Executor e){
        SSLStateMachine sslSessionSM = new SSLStateMachine(counter.incrementAndGet(), e);
        sslSessionSM.setConfig(config);
        config.stateMachine = sslSessionSM;

    TriggerConsumerInt<Void> init = new TriggerConsumer<Void>(StateInt.States.INIT) {
          @Override
          public void accept(Void o) {
              if(log.isEnabled()) log.getLogger().info(getState().getStateMachine().getName() + " CREATED");
              //SSLSessionConfig config = (SSLSessionConfig) getStateMachine().getConfig();
              //publish(new Trigger<SelectableChannel>(getState(), null, SessionState.WAIT_FOR_HANDSHAKING));
          }
        };

    TriggerConsumerInt<TaskCallback<ByteBuffer, SSLChannelOutputStream>> closed =
        new TriggerConsumer<TaskCallback<ByteBuffer, SSLChannelOutputStream>>(SessionState.CLOSE) {
          @Override
          public void accept(TaskCallback<ByteBuffer, SSLChannelOutputStream> callback) {

            SSLSessionConfig config = (SSLSessionConfig) getState().getStateMachine().getConfig();
            synchronized (config) {
              if (!config.isClosed()) {
                config.close();
              }
            }

            if (log.isEnabled()) log.getLogger().info(getStateMachine().getName() + " " + callback + " closed");
          }
        };

        sslSessionSM.setConfig(config)
                .register(new State(StateInt.States.INIT).register(init))
                .register(new SSLHandshakingState())
                .register(new SSLReadState())
                .register(new State(SessionState.CLOSE).register(closed))
        ;


        return sslSessionSM;
    }

}
