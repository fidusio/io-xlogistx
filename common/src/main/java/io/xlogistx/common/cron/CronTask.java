package io.xlogistx.common.cron;


import org.zoxweb.server.task.TaskSchedulerProcessor;
import org.zoxweb.shared.util.Appointment;
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


    private void next()
    {

       long millisFromNow = waitTime.nextWait();

       //log.info(nextExecutionTime + " seconds: " + nextExecutionTime.getSecond() + " delay " + millisFromNow);

        if (appointment == null)
            appointment = tsp.queue(millisFromNow, this);
        else
            appointment.setDelayInNanos(millisFromNow, 0);



    }

    public WaitTime getWaitTime()
    {
        return waitTime;
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
