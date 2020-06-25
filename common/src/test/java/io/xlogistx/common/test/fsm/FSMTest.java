package io.xlogistx.common.test.fsm;

import io.xlogistx.common.fsm.*;
import org.zoxweb.shared.util.Const;

import java.util.Arrays;
import java.util.logging.Logger;

import static java.lang.System.out;

public class FSMTest {

    private static Logger log = Logger.getLogger(FSMTest.class.getName());

    public static void main(String ...args)
    {
        StateMachineInt fsm = new StateMachine("Test");
        TriggerConsumer<Object> init = new TriggerConsumer<Object>("init") {
            @Override
            public void accept(Object o) {
                log.info(Arrays.toString(canonicalIDs()));
                getState().getStateMachine().publish(new Trigger<Long>(getState(), Const.TimeInMillis.SECOND.MILLIS, "wait"));

            }
        };

        TriggerConsumer<Long> wait = new TriggerConsumer<Long>("wait") {
            private long delta;
            private Runnable run = new Runnable() {
                @Override
                public void run() {
                    delta = System.currentTimeMillis() - delta;
                    log.info("wait post " + delta);
                }
            };
            @Override
            public void accept(Long aLong) {
                log.info(Arrays.toString(canonicalIDs()));
                delta = System.currentTimeMillis();
                getState().getStateMachine().getTSP().queue(aLong, run);

            }
        };

        fsm.register(new State("Init").register(init)).register(new State("wait").register(wait));

        fsm.start();


    }
}
