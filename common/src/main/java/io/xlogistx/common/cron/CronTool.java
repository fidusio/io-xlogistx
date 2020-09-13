package io.xlogistx.common.cron;

import com.cronutils.model.definition.CronDefinition;
import com.cronutils.model.definition.CronDefinitionBuilder;
import com.cronutils.parser.CronParser;
import io.xlogistx.common.task.RunnableProperties;
import org.zoxweb.server.task.TaskSchedulerProcessor;
import org.zoxweb.server.util.ReflectionUtil;
import org.zoxweb.shared.util.Appointment;
import org.zoxweb.shared.util.Const;
import org.zoxweb.shared.util.SharedUtil;
import org.zoxweb.shared.util.WaitTime;


import java.lang.reflect.InvocationTargetException;
import java.util.HashMap;
import java.util.Map;

import static com.cronutils.model.CronType.UNIX;

public class CronTool {

    public enum Type {
        DAY,
        NIGHT,
        ;

        public static Type lookup(String type)
        {
            return SharedUtil.lookupEnum(type, Type.values());
        }
    }

    private final TaskSchedulerProcessor tsp;
    private final CronParser unixParser;
    private final Map<String, CronTask> registeredTask = new HashMap<String, CronTask>();
    public CronTool(TaskSchedulerProcessor tsp)
    {
        this.tsp = tsp;
        CronDefinition cronDefinition = CronDefinitionBuilder.instanceDefinitionFor(UNIX);
        unixParser = new CronParser(cronDefinition);
    }


    public Appointment cron(CronSchedulerConfig cc)
            throws
            ClassNotFoundException,
            NoSuchMethodException,
            InvocationTargetException,
            InstantiationException,
            IllegalAccessException
    {
        RunnableProperties bean = ReflectionUtil.createBean(cc.getBean());
        bean.setProperties(cc.getProperties());
        return cron(cc.getSchedule(), bean);
    }

    public Appointment cron(String cronSchedule, Runnable command)
    {
        CronTask ct = lookupRegisteredCronTask(cronSchedule);
        if(ct != null)
        {
            if(ct.getCommand() instanceof CronScheduler)
            {
                ((CronScheduler)ct.getCommand()).schedule(cronSchedule, command);
                    return ct.getAppointment();
            }
        }

        try
        {
            return new CronTask(tsp, new MillisWaitTime(Const.TimeInMillis.toMillis(cronSchedule)), command).getAppointment();
        }
        catch(Exception e)
        {
        }

        return new CronTask(tsp, new CronWaitTime(unixParser.parse(cronSchedule)), command).getAppointment();
    }

    public Appointment cron(WaitTime wt, Runnable command)
    {
        return new CronTask(tsp, wt, command).getAppointment();
    }

    public synchronized CronTask registerCronTask(String type, WaitTime wt, Runnable command)
    {
        Type eType = Type.lookup(type);
        CronTask ct = lookupRegisteredCronTask(eType.name());
        if(ct == null)
            ct = registerCronTask(type, new CronTask(tsp, wt, command));
        return ct;

    }

    public synchronized CronTask registerCronTask(String type, CronTask ct)
    {
        CronTask ctCurrent = lookupRegisteredCronTask(type);
        if(ctCurrent == null) {
            ctCurrent = ct;
            registeredTask.put(Type.lookup(type).name(), ctCurrent);
        }
        return ctCurrent;
    }

    public CronTask lookupRegisteredCronTask(String type)
    {
        Type eType = SharedUtil.lookupEnum(type, Type.values());
        if(eType == null)
            return null;
        return registeredTask.get(eType.name());
    }






}
