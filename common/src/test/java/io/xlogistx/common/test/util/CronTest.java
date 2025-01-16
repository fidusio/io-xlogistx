package io.xlogistx.common.test.util;


import com.cronutils.model.Cron;
import com.cronutils.model.CronType;
import com.cronutils.model.definition.CronDefinition;
import com.cronutils.model.definition.CronDefinitionBuilder;
import com.cronutils.model.time.ExecutionTime;
import com.cronutils.parser.CronParser;
import io.xlogistx.common.cron.CronTool;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.shared.util.Const;

import java.time.Duration;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.logging.Logger;


public class CronTest {
    private static final transient Logger log = Logger.getLogger(CronTest.class.getName());
    public static void unixCron() {
        CronDefinition cronDefinition = CronDefinitionBuilder.instanceDefinitionFor(CronType.UNIX);
        CronParser unixParser = new CronParser(cronDefinition);
        String[] expressions = {" 0 5 * * 1", "0 */6 * * *"};
        for (String expression : expressions) {
            Cron cron = unixParser.parse(expression);
            System.out.println(cron.asString());
            ExecutionTime executionTime = ExecutionTime.forCron(cron);
            ZonedDateTime now = ZonedDateTime.now();
            System.out.println(String.format("Given cron '%s', and reference date '%s'\nlast execution was '%s'\nnext execution will be '%s', time to next exec %s",
                    cron.asString(), now, executionTime.lastExecution(now).get(), executionTime.nextExecution(now).get(), Const.TimeInMillis.toString(executionTime.timeToNextExecution(now).get().toMillis()))
            );
        }
    }

    public static void unixCronCalc(String expression, int iterations) {
        CronDefinition cronDefinition = CronDefinitionBuilder.instanceDefinitionFor(CronType.UNIX);
        CronParser unixParser = new CronParser(cronDefinition);

        Cron cron = unixParser.parse(expression);
        System.out.println(cron.asString());
        ExecutionTime executionTime = ExecutionTime.forCron(cron);
        ZonedDateTime zdt = ZonedDateTime.now();
        for(int i = 0; i < iterations; i++)
        {

            Duration duration = executionTime.timeToNextExecution(zdt).get();
            System.out.println(zdt + ", " +duration.toMillis());
            zdt = executionTime.nextExecution(zdt).get();
        }

    }


    public static void main(String ...args)
    {
        try {
            CronTool ct = new CronTool(TaskUtil.defaultTaskScheduler());
            int index = 0;
            String cron = args[index++];
            long minDelay = Const.TimeInMillis.toMillis(args[index++]);
            unixCronCalc(cron, 10);

            ct.cron(args[0],
                    () -> {log.info("[1:" + Thread.currentThread() + "-" + new Date());
                           TaskUtil.sleep(5000);
                           log.info(" 2:" + Thread.currentThread() + "-" + new Date() +"]");});
        }
        catch (Exception e)
        {
            e.printStackTrace();
            System.exit(-1);
        }
    }
}
