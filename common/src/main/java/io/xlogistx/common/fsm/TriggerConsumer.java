package io.xlogistx.common.fsm;

import org.zoxweb.shared.util.CanonicalID;

public abstract class TriggerConsumer<T>
implements TriggerConsumerInt<T>
{
    private String canonicalIDs[];
    private StateInt state;

    public TriggerConsumer(String ...canonicalIDs)
    {
        this.canonicalIDs = canonicalIDs;
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



}
