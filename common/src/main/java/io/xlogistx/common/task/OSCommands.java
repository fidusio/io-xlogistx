package io.xlogistx.common.task;


import org.zoxweb.server.util.RuntimeUtil;
import org.zoxweb.shared.util.NVGenericMap;

import java.util.List;
import java.util.logging.Logger;

public class OSCommands
extends RunnableProperties
{

    private static final Logger log = Logger.getLogger(OSCommands.class.getName());

    @Override
    public void run()
    {
        NVGenericMap nvgm = getProperties();
        if(nvgm != null)
        {
            List<String> commands = nvgm.getValue("commands");
            if(commands != null)
            {
                for(String command : commands)
                {
                    try
                    {
                        log.info("Will execute os command: " + command);
                        log.info("Execution Result: " + RuntimeUtil.runAndFinish(command));
                    }
                    catch(Exception e)
                    {
                        e.printStackTrace();
                    }
                }
            }

        }
    }
}
