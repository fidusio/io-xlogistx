package io.xlogistx.common.fsm;

import java.util.HashSet;
import java.util.Set;

public class State<P>
    implements StateInt<P>
{

    private String name;
    private P config;
    private transient TriggerConsumerInt<?>[] cashedTriggers = new TriggerConsumerInt[0];
    private StateMachineInt stateMachine;

    private Set<TriggerConsumerInt<?>> triggerConsumers = new HashSet<>();
    public State(String name)
    {
        this.name = name;
    }

    @Override
    public synchronized TriggerConsumerInt<?>[] triggers() {
        return cashedTriggers;
    }

    @Override
    public String getName() {
        return name;
    }

    public synchronized StateInt register(TriggerConsumerInt<?> tc)
    {
        triggerConsumers.add(tc);
        tc.setSate(this);
        cashedTriggers = triggerConsumers.toArray(new TriggerConsumerInt[0]);
        return this;
    }

    @Override
    public StateMachineInt getStateMachine() {
        return stateMachine;
    }

    @Override
    public void setStateMachine(StateMachineInt smi) {
        stateMachine = smi;
    }

    public P getProperties()
    {
        return config;
    }

    public void setProperties(P config)
    {
        this.config = config;
    }

    public String toString()
    {
        return getName();
    }
}
