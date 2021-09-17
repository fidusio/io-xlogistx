package io.xlogistx.common.fsm;


import org.zoxweb.shared.util.GetName;

import java.util.function.Supplier;

public interface TriggerInt<D>
extends Supplier<D>
{
    StateInt lastState();
    String getCanonicalID();

    long getID();

    long getTimestamp();
}
