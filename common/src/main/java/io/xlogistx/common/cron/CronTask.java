package io.xlogistx.common.cron;

import com.cronutils.model.Cron;
import com.cronutils.model.time.ExecutionTime;
import org.zoxweb.server.task.TaskSchedulerProcessor;
import org.zoxweb.shared.util.Appointment;


import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.logging.Logger;

public class CronTask
    implements Runnable, AutoCloseable
{

    private static final transient Logger log = Logger.getLogger(CronTask.class.getName());
    private final Cron cron;
    private final Runnable command;
    private final ExecutionTime executionTime;
    private final TaskSchedulerProcessor tsp;
    private Appointment appointment;

    public CronTask(TaskSchedulerProcessor tsp, Cron cron, Runnable command)
    {
        this.tsp = tsp;
        this.cron = cron;
        this.command = command;
        executionTime = ExecutionTime.forCron(cron);
        next(0);
    }

    public void run()
    {
        command.run();
        next(0);
    }


    private synchronized void next(long millisIncrement)
    {
        ZonedDateTime zdt = ZonedDateTime.now().plus(millisIncrement, ChronoUnit.MILLIS);

        long millisFromNow = executionTime.timeToNextExecution(zdt).get().toMillis();
        //log.info(Const.TimeInMillis.toString(millisFromNow));
        if(millisFromNow > 0)
        {
                if(appointment == null)
                    appointment = tsp.queue(millisFromNow, this);
                else
                    appointment.setDelayInMillis(millisFromNow);
        }
        else
        {
            log.info("We have negative time " + millisFromNow);
            next(5);
        }
    }

    public Cron getCron()
    {
        return cron;
    }

    public synchronized void close()
    {
        appointment.close();
    }

    public Appointment getAppointment()
    {
        return appointment;
    }
}
