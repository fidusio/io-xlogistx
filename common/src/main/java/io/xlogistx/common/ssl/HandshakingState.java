package io.xlogistx.common.ssl;

import io.xlogistx.common.fsm.State;
import io.xlogistx.common.fsm.TriggerConsumer;


import java.util.logging.Logger;

import static javax.net.ssl.SSLEngineResult.HandshakeStatus.*;

public class HandshakingState extends State {
    private static final transient Logger log = Logger.getLogger(HandshakingState.class.getName());
    class NeedWrap extends TriggerConsumer<SSLConfig>
    {
        NeedWrap() {
            super(NEED_WRAP);
        }

        @Override
        public void accept(SSLConfig config) {

        }
    }

    class NeedUnwrap extends TriggerConsumer<SSLConfig>
    {
        NeedUnwrap() {
            super(NEED_UNWRAP);
        }

        @Override
        public void accept(SSLConfig config) {

        }
    }


    class NeedTask extends TriggerConsumer<SSLConfig>
    {
        NeedTask() {
            super(NEED_TASK);
        }

        @Override
        public void accept(SSLConfig config) {
            Runnable toRun;
            while((toRun = config.getDelegatedTask()) != null)
            {
                toRun.run();
            }
            publish(config, config.getHandshakeStatus());
        }
    }



    class Finished extends TriggerConsumer<SSLConfig>
    {
        Finished() {
            super(FINISHED);
        }

        @Override
        public void accept(SSLConfig config) {

        }
    }


    class NotHandshaking extends TriggerConsumer<SSLConfig>
    {
        NotHandshaking() {
            super(NOT_HANDSHAKING);
        }

        @Override
        public void accept(SSLConfig config) {

        }
    }


    public HandshakingState() {
        super(SSLStateMachine.SessionState.HANDSHAKING);
        register(new NeedTask())
                .register(new NeedWrap())
                .register(new NeedUnwrap())
                .register(new Finished())
                .register(new NotHandshaking());
    }

}
