package io.xlogistx.common.fsm;


import org.zoxweb.shared.util.GetName;

import java.util.function.Supplier;

public interface TriggerInt<T>
extends Supplier<T>
{
    StateInt lastState();
    String getCanonicalID();

    long getID();

    long getTimestamp();
}
