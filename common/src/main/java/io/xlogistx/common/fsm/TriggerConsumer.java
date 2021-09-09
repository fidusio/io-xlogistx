package io.xlogistx.common.fsm;

import org.zoxweb.shared.util.GetName;

import java.util.Arrays;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Function;
import java.util.logging.Logger;

public abstract class TriggerConsumer<T>
implements TriggerConsumerInt<T>
{
    final static Logger log = Logger.getLogger(TriggerConsumer.class.getName());
    private final String[] canonicalIDs;
    private StateInt state;
    protected AtomicLong execCounter = new AtomicLong();
    private  Function<T, ?> function;


    public TriggerConsumer(Function f, String ...canonicalIDs)
    {
        this(canonicalIDs);
        function = f;
    }
    public TriggerConsumer(Function f, GetName ...canonicalIDs)
    {
        this(canonicalIDs);
        function = f;
    }
    public TriggerConsumer(String ...canonicalIDs)
    {
        this.canonicalIDs = canonicalIDs;
    }
    public TriggerConsumer(GetName...gnCanonicalIDs)
    {

        canonicalIDs = new String[gnCanonicalIDs.length];
        for(int i = 0; i < canonicalIDs.length; i++)
        {
            canonicalIDs[i] = gnCanonicalIDs[i].getName();
        }
    }

    @Override
    public String[] canonicalIDs() {
        return canonicalIDs;
    }

    public StateInt getState()
    {
        return state;
    }

    public void setSate(StateInt state)
    {
        this.state = state;
    }

   public<R> TriggerConsumerInt<T> setFunction(Function<T, R> function)
   {
       this.function = function;
       return this;
   }

   public<R> Function getFunction()
   {
       return function;
   }


    @Override
    public String toString() {
        return "TriggerConsumer{" +
                "canonicalIDs=" + Arrays.toString(canonicalIDs) +
                ", state=" + state + ", exec-counter=" + execCounter.get() +
                '}';
    }

    @Override
    public void publish(TriggerInt triggerInt) {
        if(triggerInt != null)
            getState().getStateMachine().publish(triggerInt);
    }

    public void publish(T data, String canID) {
        if(canID != null)
            getState().getStateMachine().publish(new Trigger(getState(), data, canID));
    }

    public void publish(T data, GetName canID) {
        if(canID != null)
            getState().getStateMachine().publish(new Trigger(getState(), data, canID));
    }

    public StateMachineInt getStateMachine()
    {
        return getState().getStateMachine();
    }
}
