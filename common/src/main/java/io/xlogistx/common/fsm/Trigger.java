package io.xlogistx.common.fsm;


import org.zoxweb.shared.util.GetName;

import java.util.EventObject;
import java.util.concurrent.atomic.AtomicLong;

public class Trigger<T>
extends EventObject
implements TriggerInt<T>
{
    private final static AtomicLong counter = new AtomicLong();

    private final String canonicalID;
    private final T data;
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
    public Trigger(Object source, StateInt lastState, T data, String canonicalID) {
        super(source);
        this.lastState = lastState;
        this.data = data;
        this.canonicalID = canonicalID;
    }

    public Trigger(Object source, StateInt lastState, T data, GetName canonicalID) {
        this(source, lastState, data, canonicalID.getName());
    }
    public Trigger(StateInt state, T data, String canonicalID)
    {
        this(state, state, data, canonicalID);
    }

    public Trigger(StateInt state, T data, GetName name)
    {
        this(state, state, data, name.getName());
    }

    @Override
    public StateInt lastState() {
        return lastState;
    }

    @Override
    public T get() {
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
