package io.xlogistx.common.fsm;


import org.zoxweb.shared.util.GetName;
import org.zoxweb.shared.util.SharedUtil;

import java.util.EventObject;
import java.util.concurrent.atomic.AtomicLong;

public class Trigger<D>
extends EventObject
implements TriggerInt<D>
{
    private final static AtomicLong counter = new AtomicLong();

    private final String canonicalID;
    private final D data;
    private final StateInt lastState;
    private final long id = counter.getAndIncrement();
    private final long timestamp = System.currentTimeMillis();

    /**
     *  Constructs a trigger Event.
     * @param source of the event
     * @param lastState last state
     * @param data event data
     * @param canonicalID of the trigger
     */
    public Trigger(Object source, StateInt lastState, D data, String canonicalID) {
        super(source);
        this.lastState = lastState;
        this.data = data;
        this.canonicalID = canonicalID;
    }

    public Trigger(Object source, StateInt lastState, D data, Enum<?> canonicalID) {
        this(source, lastState, data, SharedUtil.enumName(canonicalID));
    }
    public Trigger(StateInt state, D data, String canonicalID)
    {
        this(state, state, data, canonicalID);
    }

    public Trigger(StateInt state, D data, Enum<?> name)
    {
        this(state, state, data,  SharedUtil.enumName(name));
    }

    @Override
    public StateInt lastState() {
        return lastState;
    }

    @Override
    public D get() {
        return data;
    }



    @Override
    public String getCanonicalID() {
        return canonicalID;
    }


    public long getID()
    {
        return id;
    }

    public long getTimestamp()
    {
        return timestamp;
    }

    @Override
    public String toString() {
        return "Trigger{" +
                "canonicalID='" + canonicalID + '\'' +
                ", data=" + data +
                ", lastState=" + lastState +
                ", id=" + id +
                ", timestamp=" + timestamp +
                '}';
    }
}
