package io.xlogistx.common.fsm;

import org.zoxweb.shared.util.SharedUtil;

import java.util.Arrays;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Function;
import java.util.logging.Logger;

public abstract class TriggerConsumer<T>
implements TriggerConsumerInt<T>
{
    final static Logger log = Logger.getLogger(TriggerConsumer.class.getName());
    public static boolean debug = false;
    private final String[] canonicalIDs;
    private StateInt state;
    protected AtomicLong execCounter = new AtomicLong();
    private  Function<T, ?> function;


    public TriggerConsumer(Function f, String ...canonicalIDs)
    {
        this(canonicalIDs);
        function = f;
    }
    public TriggerConsumer(Function f, Enum<?> ...canonicalIDs)
    {
        this(canonicalIDs);
        function = f;
    }
    public TriggerConsumer(String ...canonicalIDs)
    {
        this.canonicalIDs = canonicalIDs;
    }
    public TriggerConsumer(Enum<?>...gnCanonicalIDs)
    {

        canonicalIDs = new String[gnCanonicalIDs.length];
        for(int i = 0; i < canonicalIDs.length; i++)
        {
            canonicalIDs[i] = SharedUtil.enumName(gnCanonicalIDs[i]);
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

    public <D>void publish(String canID, D data) {
        if(canID != null)
            getState().getStateMachine().publish(new Trigger(getState(), canID, data));
    }

    public <D> void publish(Enum<?> canID, D data) {
        if(canID != null)
            getState().getStateMachine().publish(new Trigger(getState(), SharedUtil.enumName(canID), data));
    }

    public void publishSync(TriggerInt triggerInt) {
        if(triggerInt != null)
            getState().getStateMachine().publishSync(triggerInt);
    }

    public <D>void publishSync(String canID, D data) {
        if(canID != null)
            getState().getStateMachine().publishSync(new Trigger(getState(), canID, data));
    }

    public <D> void publishSync(Enum<?> canID, D data) {
        if(canID != null)
            getState().getStateMachine().publishSync(new Trigger(getState(), SharedUtil.enumName(canID), data));
    }

    public StateMachineInt getStateMachine()
    {
        return getState().getStateMachine();
    }
}
