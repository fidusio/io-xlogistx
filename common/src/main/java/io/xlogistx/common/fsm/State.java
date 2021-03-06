package io.xlogistx.common.fsm;

import org.zoxweb.shared.util.GetName;
import org.zoxweb.shared.util.NVBase;
import org.zoxweb.shared.util.NVGenericMap;


import java.util.LinkedHashMap;
import java.util.Map;

public class State<P>
    implements StateInt<P>
{

    private String name;
    private NVGenericMap data = new NVGenericMap();
    //private transient TriggerConsumerInt<?>[] cashedTriggers = new TriggerConsumerInt[0];
    private StateMachineInt stateMachine;

    private Map<String, TriggerConsumerInt<?>> triggerConsumers = new LinkedHashMap<String, TriggerConsumerInt<?>> ();
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
        return triggerConsumers.values().toArray(new TriggerConsumerInt<?>[triggerConsumers.size()]);
    }

    @Override
    public TriggerConsumerInt<?> lookupTriggerConsumer(String canonicalID) {
        return triggerConsumers.get(canonicalID);
    }

    @Override
    public TriggerConsumerInt<?> lookupTriggerConsumer(GetName canonicalID) {
        return lookupTriggerConsumer(canonicalID.getName());
    }

    @Override
    public String getName() {
        return name;
    }

    public synchronized StateInt register(TriggerConsumerInt<?> tc)
    {
        for(String canID : tc.canonicalIDs())
            triggerConsumers.put(canID, tc);
        tc.setSate(this);
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
