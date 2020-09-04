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
import java.time.ZonedDateTime;
import java.util.Date;


public class CronTest {
    public void unixCron() {
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


    public static void main(String ...args)
    {
        CronTool ct = new CronTool(TaskUtil.getDefaultTaskScheduler());
        ct.cron(args[0], ()->{System.out.println(new Date());});
    }
}
