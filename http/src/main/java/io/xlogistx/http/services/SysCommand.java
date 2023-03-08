package io.xlogistx.http.services;


import io.xlogistx.common.data.PropertyHolder;
import org.zoxweb.server.task.SupplierTask;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.server.util.RuntimeUtil;
import org.zoxweb.shared.annotation.EndPointProp;
import org.zoxweb.shared.annotation.SecurityProp;
import org.zoxweb.shared.crypto.CryptoConst;
import org.zoxweb.shared.data.SimpleMessage;
import org.zoxweb.shared.http.HTTPMethod;
import org.zoxweb.shared.http.HTTPStatusCode;
import org.zoxweb.shared.util.Const;

import java.io.IOException;



@SecurityProp(authentications = {CryptoConst.AuthenticationType.BASIC,
        CryptoConst.AuthenticationType.BEARER,
        CryptoConst.AuthenticationType.JWT},
//              protocols = {URIScheme.HTTPS},
              roles = "local-admin,remote-admin")
public class SysCommand
extends PropertyHolder
{




    @EndPointProp(methods = {HTTPMethod.GET}, name="system-reboot", uris="/system/reboot")
    public SimpleMessage systemReboot()
    {
        if (getProperties() != null) {
            String command = getProperties().getValue("reboot-command");
            Long delay = getProperties().getValue("reboot-delay");
            if (command == null || delay == null)
            {
                return new SimpleMessage("Reboot: command or delay missing from config",  HTTPStatusCode.BAD_REQUEST.CODE);
            }
            TaskUtil.getDefaultTaskScheduler().queue(delay, new SupplierTask<String>(command) {
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
            return new SimpleMessage("reboot miss configured", HTTPStatusCode.BAD_REQUEST.CODE, "reconfigure endpoint");
        }

    }
    @EndPointProp(methods = {HTTPMethod.GET}, name="system-shutdown", uris="/system/shutdown")
    public SimpleMessage systemShutdown()
    {
        if (getProperties() != null) {
            String command = getProperties().getValue("shutdown-command");
            Long delay = getProperties().getValue("shutdown-delay");
            if (command == null || delay == null)
            {
                return new SimpleMessage("Shutdown: command or delay missing from config",  HTTPStatusCode.BAD_REQUEST.CODE);
            }
            TaskUtil.getDefaultTaskScheduler().queue(delay, new SupplierTask<String>(command) {
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
            return new SimpleMessage("shutdown miss configured", HTTPStatusCode.BAD_REQUEST.CODE, "reconfigure endpoint");
        }
    }


    protected void refreshProperties()
    {
    }
}
