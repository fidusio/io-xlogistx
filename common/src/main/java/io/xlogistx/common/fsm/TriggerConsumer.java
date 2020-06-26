package io.xlogistx.common.fsm;

import org.zoxweb.shared.util.CanonicalID;
import org.zoxweb.shared.util.GetName;

public abstract class TriggerConsumer<T>
implements TriggerConsumerInt<T>
{
    private String canonicalIDs[];
    private StateInt state;

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



}
