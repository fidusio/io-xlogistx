package io.xlogistx.common.task;

import org.zoxweb.shared.data.PropertyDAO;

public class OnOff
{
    public final Runnable on;
    public final Runnable off;

    public OnOff(Runnable on, Runnable off)
    {
        this.on = on;
        this.off = off;
    }
}
