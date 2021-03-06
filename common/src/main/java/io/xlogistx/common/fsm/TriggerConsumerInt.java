package io.xlogistx.common.fsm;


import java.util.function.Consumer;
import java.util.function.Function;

public interface TriggerConsumerInt<T>
    extends Consumer<T>
{
    String[] canonicalIDs();

    StateInt getState();

    void setSate(StateInt state);

    <R> TriggerConsumerInt setFunction(Function<T, R> function);
    <R> Function<T, R> getFunction();

}
