package io.xlogistx.common.fsm;


import org.zoxweb.shared.util.GetName;

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


    void publish(TriggerInt triggerInt);
    <D> void publish(D data, String canID);
    <D>void  publish(D data, Enum<?> canID);

    public StateMachineInt getStateMachine();

}
