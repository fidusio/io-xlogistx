package io.xlogistx.common.fsm;


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
     * @param canonicalID of the trigger
     * @param lastState last state
     * @param data event data
     */
    public Trigger(Object source, String canonicalID, StateInt lastState, D data) {
        super(source);
        this.lastState = lastState;
        this.data = data;
        this.canonicalID = canonicalID;
    }

    public Trigger(Object source, Enum<?> canonicalID, StateInt lastState, D data) {
        this(source, SharedUtil.enumName(canonicalID), lastState, data);
    }
    public Trigger(StateInt state, String canonicalID, D data)
    {
        this(state, canonicalID, state, data);
    }


    public Trigger(StateInt state, Enum<?> name, D data)
    {
        this(state, SharedUtil.enumName(name), state, data);
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
