package io.xlogistx.common.cron;

import com.cronutils.model.Cron;
import com.cronutils.model.time.ExecutionTime;
import org.zoxweb.shared.util.WaitTime;

import java.time.ZonedDateTime;

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
}
