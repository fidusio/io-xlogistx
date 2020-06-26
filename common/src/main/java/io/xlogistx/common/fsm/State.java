package io.xlogistx.common.fsm;

import org.zoxweb.shared.util.GetName;
import org.zoxweb.shared.util.NVBase;
import org.zoxweb.shared.util.NVGenericMap;

import java.util.HashSet;
import java.util.Set;

public class State<P>
    implements StateInt<P>
{

    private String name;
    private NVGenericMap data = new NVGenericMap();
    private transient TriggerConsumerInt<?>[] cashedTriggers = new TriggerConsumerInt[0];
    private StateMachineInt stateMachine;

    private Set<TriggerConsumerInt<?>> triggerConsumers = new HashSet<>();
    public State(String name, NVBase<?> ...props)
    {
        this.name = name;
        if(props != null)
        {
            for (NVBase<?> nvb : props) {
                data.add(nvb);
            }
        }
    }
    public State(GetName name, NVBase<?> ...props)
    {
        this(name.getName(), props);
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

    public NVGenericMap getProperties()
    {
        return data;
    }

    public String toString()
    {
        return getName();
    }
}
