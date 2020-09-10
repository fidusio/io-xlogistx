package io.xlogistx.common.cron;

import com.cronutils.model.definition.CronDefinition;
import com.cronutils.model.definition.CronDefinitionBuilder;
import com.cronutils.parser.CronParser;
import org.zoxweb.server.task.TaskSchedulerProcessor;
import org.zoxweb.shared.util.Appointment;
import org.zoxweb.shared.util.WaitTime;


import static com.cronutils.model.CronType.UNIX;

public class CronTool {

    private final TaskSchedulerProcessor tsp;
    final CronParser unixParser;
    public CronTool(TaskSchedulerProcessor tsp)
    {
        this.tsp = tsp;
        CronDefinition cronDefinition = CronDefinitionBuilder.instanceDefinitionFor(UNIX);
        unixParser = new CronParser(cronDefinition);
    }

    public Appointment cron(String cronSchedule, Runnable command)
    {
        return new CronTask(tsp, new CronWaitTime(unixParser.parse(cronSchedule)), command).getAppointment();
    }

    public Appointment cron(WaitTime wt, Runnable command)
    {
        return new CronTask(tsp, wt, command).getAppointment();
    }
}
