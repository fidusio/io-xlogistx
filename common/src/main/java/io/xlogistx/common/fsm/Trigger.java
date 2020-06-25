package io.xlogistx.common.fsm;

import org.zoxweb.shared.util.CanonicalID;

import java.util.EventObject;
import java.util.concurrent.atomic.AtomicLong;

public class Trigger<T>
extends EventObject
implements TriggerInt<T>
{
    private static AtomicLong counter = new AtomicLong();

    private String canonicalID;
    private T data;
    private StateInt lastState;
    private long id = counter.getAndIncrement();
    private long timestamp = System.currentTimeMillis();

    /**
     * Constructs a prototypical Event.
     *
     * @param source the object on which the Event initially occurred
     * @throws IllegalArgumentException if source is null
     */
    public Trigger(Object source, StateInt state, T data, String canonicalID) {
        super(source);
        this.lastState = state;
        this.data = data;
        this.canonicalID = canonicalID;
    }
    public Trigger(StateInt state, T data, String canonicalID)
    {
        this(state, state, data, canonicalID);
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
