package io.xlogistx.common.cron;

import com.cronutils.model.Cron;
import com.cronutils.model.time.ExecutionTime;
import org.jetbrains.annotations.NotNull;
import org.zoxweb.shared.util.WaitTime;

import java.time.ZonedDateTime;
import java.util.concurrent.TimeUnit;

public class CronWaitTime
implements WaitTime<Cron>
{

    private final ExecutionTime executionTime;
    private final Cron cron;
    public CronWaitTime(Cron cron)
    {
        this.cron = cron;
        executionTime = ExecutionTime.forCron(cron);
    }

    @Override
    public long nextWait()
    {
        return executionTime.timeToNextExecution(ZonedDateTime.now()).get().toMillis();
    }

    @Override
    public Cron getType() {
        return cron;
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
        return unit.convert(nextWait(), TimeUnit.MILLISECONDS);
    }
}
