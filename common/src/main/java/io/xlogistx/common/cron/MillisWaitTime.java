package io.xlogistx.common.cron;

import org.zoxweb.shared.util.WaitTime;

public class MillisWaitTime
implements WaitTime<MillisWaitTime>
{
    private final long waitTime;
    public MillisWaitTime(long waitTime)
    {
        this.waitTime = waitTime;
    }
    @Override
    public long nextWait() {
        return waitTime;
    }

    @Override
    public MillisWaitTime getType() {
        return this;
    }
}
