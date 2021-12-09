package io.xlogistx.common.fsm;

import java.util.function.Consumer;

public class TriggerConsumerHolder<T>
    implements Consumer<T>
{
    private Consumer inner;

    TriggerConsumerHolder(Consumer<?> inner)
    {
        this.inner = inner;
    }

    public void accept(T t)
    {
        if (inner instanceof TriggerConsumer)
        {
            TriggerConsumer temp = (TriggerConsumer) inner;
            temp.execCounter.incrementAndGet();
            temp.getState().getStateMachine().setCurrentState(temp.getState());

        }
        if( TriggerConsumer.debug)
            TriggerConsumer.log.info("" + inner);

        inner.accept(t);
    }
}
