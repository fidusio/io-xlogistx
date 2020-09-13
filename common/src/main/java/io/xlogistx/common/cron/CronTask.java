package io.xlogistx.common.cron;


import org.zoxweb.server.task.TaskSchedulerProcessor;
import org.zoxweb.shared.util.Appointment;
import org.zoxweb.shared.util.Const;
import org.zoxweb.shared.util.WaitTime;



import java.util.logging.Logger;

public class CronTask
    implements Runnable, AutoCloseable
{

    private static final transient Logger log = Logger.getLogger(CronTask.class.getName());

    private final Runnable command;

    private final TaskSchedulerProcessor tsp;
    private Appointment appointment;
    private final WaitTime waitTime;



    public CronTask(TaskSchedulerProcessor tsp, WaitTime waitTime, Runnable command)
    {
        this.tsp = tsp;
        this.waitTime = waitTime;
        this.command = command;
        next();
    }

    public void run()
    {
        command.run();

        if(!appointment.isClosed())
            next();
    }


    private synchronized void next()
    {

       long millisFromNow = waitTime.nextWait();


       log.info(Thread.currentThread()+ " next execution :" + Const.TimeInMillis.toString(millisFromNow));

        if (appointment == null)
            appointment = tsp.queue(millisFromNow, this);
        else
            appointment.setDelayInNanos(millisFromNow, 0);



    }

    public WaitTime getWaitTime()
    {
        return waitTime;
    }

    public Runnable getCommand()
    {
        return command;
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
