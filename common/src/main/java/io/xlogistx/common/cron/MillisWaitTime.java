package io.xlogistx.common.cron;

import org.jetbrains.annotations.NotNull;
import org.zoxweb.shared.util.WaitTime;

import java.util.concurrent.TimeUnit;

public class MillisWaitTime
implements WaitTime<MillisWaitTime>
{
    private final long waitTime;
    private volatile long expiryTime;
    public MillisWaitTime(long waitTime)
    {
        this.waitTime = waitTime;
        nextWait();
    }
    @Override
    public synchronized long nextWait() {
        expiryTime = System.currentTimeMillis() + waitTime;
        return waitTime;
    }

    @Override
    public MillisWaitTime getType() {
        return this;
    }

    /**
     * Returns the remaining delay associated with this object, in the
     * given time unit.
     *
     * @param unit the time unit
     * @return the remaining delay; zero or negative values indicate
     * that the delay has already elapsed
     */
    @Override
    public long getDelay(@NotNull TimeUnit unit) {
        return unit.convert(expiryTime - System.currentTimeMillis(), TimeUnit.MILLISECONDS);
    }
}
