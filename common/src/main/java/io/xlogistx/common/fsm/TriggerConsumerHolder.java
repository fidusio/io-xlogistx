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
            ((TriggerConsumer<Object>) inner).execCounter.incrementAndGet();
        }
        TriggerConsumer.log.info("" + inner);
        inner.accept(t);
    }
}
