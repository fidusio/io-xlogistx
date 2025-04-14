package io.xlogistx.common.cron;


import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.task.TaskSchedulerProcessor;
import org.zoxweb.shared.util.Appointment;
import org.zoxweb.shared.util.Const;
import org.zoxweb.shared.util.WaitTime;

public class CronTask
    implements Runnable, AutoCloseable
{

    public static final LogWrapper log = new LogWrapper(CronTask.class);

    private final Runnable command;

    private final TaskSchedulerProcessor tsp;
    private Appointment appointment;
    private final WaitTime<?> waitTime;



    public CronTask(TaskSchedulerProcessor tsp, WaitTime<?> waitTime, Runnable command)
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


       if(log.isEnabled()) log.getLogger().info(Thread.currentThread() + " next execution :" + Const.TimeInMillis.toString(millisFromNow));

       if (appointment == null)
           appointment = tsp.queue(millisFromNow, this);
       else
           appointment.setDelayInNanos(millisFromNow, 0);



    }

    public WaitTime<?> getWaitTime()
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
