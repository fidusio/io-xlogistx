package io.xlogistx.ssl;

import io.xlogistx.common.fsm.*;
import io.xlogistx.common.task.CallbackTask;
import org.zoxweb.server.task.TaskSchedulerProcessor;
import org.zoxweb.shared.util.GetName;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicLong;

public class SSLStateMachine extends StateMachine<SSLSessionConfig>
{



    private final static AtomicLong HANDSHAKE_COUNTER = new AtomicLong();
    public enum SessionState
    implements GetName
    {
        HANDSHAKING("handshaking"),
        /**
         * Read data state will unwrap data via it trigger in the read state
         * and in the handshaking state will unwrap data for the handshake process
         * it is identified by checking the SSLEngine NOT_HANDSHAKING status
         */
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









    public static SSLStateMachine create(SSLContext sslContext, Executor e)
    {
        SSLSessionConfig sslSessionConfig = new SSLSessionConfig(sslContext);
        return create(sslSessionConfig, e);
    }



    public static SSLStateMachine create(SSLSessionConfig config, Executor e){
        SSLStateMachine sslSessionSM = new SSLStateMachine(counter.incrementAndGet(), e);
        sslSessionSM.setConfig(config);

    TriggerConsumerInt<Void> init = new TriggerConsumer<Void>(StateInt.States.INIT) {
          @Override
          public void accept(Void o) {
              log.info(getState().getStateMachine().getName() + " CREATED");
              SSLSessionConfig config = (SSLSessionConfig) getStateMachine().getConfig();
              //publish(new Trigger<SelectableChannel>(getState(), null, SessionState.WAIT_FOR_HANDSHAKING));
          }
        };





        TriggerConsumerInt<CallbackTask<ByteBuffer>> closed = new TriggerConsumer<CallbackTask<ByteBuffer>>(SessionState.CLOSE) {
            @Override
            public void accept(CallbackTask<ByteBuffer> callback) {

                SSLSessionConfig config = (SSLSessionConfig) getState().getStateMachine().getConfig();
                config.close();
                getStateMachine().close();

                if(debug) log.info(getStateMachine().getName() + " " + callback + " closed");
            }
        };

        sslSessionSM.setConfig(config)
            .register(new State(StateInt.States.INIT).register(init))
            .register(new ReadyState())
            .register(new HandshakingState())
            .register(new State(SessionState.CLOSE).register(closed))
        ;


        return sslSessionSM;
    }

}
