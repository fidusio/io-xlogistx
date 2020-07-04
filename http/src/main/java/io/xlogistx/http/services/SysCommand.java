package io.xlogistx.http.services;

import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.server.util.RuntimeUtil;
import org.zoxweb.server.util.SuppliedRun;
import org.zoxweb.shared.annotation.EndPointProp;
import org.zoxweb.shared.annotation.SecurityProp;
import org.zoxweb.shared.data.SimpleMessage;
import org.zoxweb.shared.http.HTTPMethod;
import org.zoxweb.shared.http.HTTPStatusCode;
import org.zoxweb.shared.security.SecurityConsts;
import org.zoxweb.shared.util.*;

import java.io.IOException;
import java.util.logging.Logger;

public class SysCommand
implements SetNVProperties
{
    private static Logger log = Logger.getLogger(SysCommand.class.getName());

    private NVGenericMap config;

    @EndPointProp(methods = {HTTPMethod.GET}, name="system-reboot", uris="/system/reboot")
    @SecurityProp(authentications = {SecurityConsts.AuthenticationType.BASIC,
                                    SecurityConsts.AuthenticationType.BEARER,
                                    SecurityConsts.AuthenticationType.JWT},
                 roles="local-admin")
    public SimpleMessage reboot()
    {
        if (getProperties() != null) {
            String command = getProperties().getValue("reboot-command");
            Long delay = getProperties().getValue("reboot-delay");
            if (command == null || delay == null)
            {
                return new SimpleMessage("Reboot: command or delay missing from config",  HTTPStatusCode.BAD_REQUEST.CODE);
            }
            TaskUtil.getDefaultTaskScheduler().queue(delay, new SuppliedRun<String>(command) {
                @Override
                public void run() {
                    try {
                        log.info("will exec command: " + get());
                        RuntimeUtil.runAndFinish(get());
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }

                }
            });
            return new SimpleMessage("System will reboot in " + Const.TimeInMillis.toString(delay), HTTPStatusCode.OK.CODE);
        }
        else
        {
            return new SimpleMessage("reboot misconfigured", HTTPStatusCode.BAD_REQUEST.CODE, "reconfigure endpoint");
        }

    }
    @EndPointProp(methods = {HTTPMethod.GET}, name="system-shutdown", uris="/system/shutdown")
    @SecurityProp(authentications = {SecurityConsts.AuthenticationType.BASIC,
                                     SecurityConsts.AuthenticationType.BEARER,
                                     SecurityConsts.AuthenticationType.JWT},
                  roles="local-admin")
    public SimpleMessage shutdown()
    {
        if (getProperties() != null) {
            String command = getProperties().getValue("shutdown-command");
            Long delay = getProperties().getValue("shutdown-delay");
            if (command == null || delay == null)
            {
                return new SimpleMessage("Shutdown: command or delay missing from config",  HTTPStatusCode.BAD_REQUEST.CODE);
            }
            TaskUtil.getDefaultTaskScheduler().queue(delay, new SuppliedRun<String>(command) {
                @Override
                public void run() {
                    try {
                        log.info("will exec command: " + get());
                        RuntimeUtil.runAndFinish(get());
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }

                }
            });
            return new SimpleMessage("System will shutdown in " + Const.TimeInMillis.toString(delay), HTTPStatusCode.OK.CODE);
        }
        else
        {
            return new SimpleMessage("shutdown misconfigured", HTTPStatusCode.BAD_REQUEST.CODE, "reconfigure endpoint");
        }

    }

    @Override
    public void setProperties(NVGenericMap nvgm) {
        config = nvgm;
    }

    @Override
    public NVGenericMap getProperties() {
        return config;
    }
}
