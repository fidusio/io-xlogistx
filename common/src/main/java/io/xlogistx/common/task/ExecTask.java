package io.xlogistx.common.task;

import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.server.util.RuntimeUtil;
import org.zoxweb.shared.data.RuntimeResultDAO;
import org.zoxweb.shared.filters.MatchPatternFilter;
import org.zoxweb.shared.util.*;

import java.io.File;
import java.io.FileFilter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class ExecTask {

    public final static LogWrapper log = new LogWrapper(ExecTask.class.getName());

    public NVGenericMap execCommands(String[] commands, long delay) throws IOException, InterruptedException {
        int passCount = 0;
        NVGenericMap ret = new NVGenericMap();
        long ts = System.currentTimeMillis();
        for(String cmd : commands)
        {
            RuntimeResultDAO rrd =  RuntimeUtil.runAndFinish(cmd);

            if(rrd.getExitCode() == 0)
                passCount++;
            log.getLogger().info(rrd.getExitCode() + " " + cmd);
            if(delay > 0)
                TaskUtil.sleep(delay);
        }
        ts = System.currentTimeMillis() - ts;
        log.getLogger().info("commands count: " + commands.length + " pass count: " + passCount);
        ret.add(new NVInt("exec-counts", commands.length));
        ret.add(new NVInt("exec-passed", passCount));
        ret.add("exec-time", Const.TimeInMillis.toString(ts));
        return ret;
    }


    public NVGenericMap execTasks(String command, String token, File dir, String ff, long delay) throws IOException, InterruptedException {
        SUS.checkIfNulls("null command of dir", command, dir);




        if (ff == null)
        {
            if (!dir.isDirectory() && !dir.isFile())
            {

                String t = dir.getAbsolutePath();
                int matchIndex = t.lastIndexOf(File.separator);
                if (matchIndex == -1)
                    matchIndex = t.lastIndexOf("/");


                if (matchIndex != -1)
                {
                    dir = new File(t.substring(0, matchIndex));
                    ff = t.substring(matchIndex + 1);
                }
            }
        }

        if(!dir.isDirectory())
            throw new IllegalArgumentException("dir is not a directory");
        List<String> commands = new ArrayList<String >();
        File[] matchingFiles = null;

        MatchPatternFilter mpf = ff != null ? MatchPatternFilter.createMatchFilter(ff) : null;

        matchingFiles = dir.listFiles((FileFilter)(f)->{
            if(f.isFile())
            {
                if (mpf != null)
                {
                    return mpf.isValid(f.getName());
                }
                else
                    return true;
            }
            return false;
        });
        for (File f : matchingFiles)
        {
            commands.add(SharedStringUtil.embedText(command, token, f.getAbsolutePath()));
        }

        return execCommands(commands.toArray(new String[0]), delay);


    }


    public static void main(String ...args)
    {
        try
        {
            ParamUtil.ParamMap params = ParamUtil.parse("=", args);
            String command = params.stringValue("cmd");
            String ff = params.stringValue("ff", true);
            String token = params.stringValue("token", true);
            String dir = params.stringValue("dir", true);
            long delay = Const.TimeInMillis.toMillisNullZero(params.stringValue("delay", true));

            NVGenericMap result = new ExecTask().execTasks(command, token, new File(dir), ff, delay);
            log.getLogger().info(GSONUtil.toJSONGenericMap(result,true,false, false));


        }
        catch(Exception e)
        {
            e.printStackTrace();
        }
    }
}
