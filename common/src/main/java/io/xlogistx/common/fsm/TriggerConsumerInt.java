package io.xlogistx.common.fsm;


import java.util.function.Consumer;

public interface TriggerConsumerInt<T>
    extends Consumer<T>
{
    String[] canonicalIDs();

    StateInt getState();

    void setSate(StateInt state);

}
