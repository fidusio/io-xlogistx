package io.xlogistx.http.services;

import io.xlogistx.common.data.PropertyHolder;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.server.util.DateUtil;
import org.zoxweb.server.util.RuntimeUtil;
import org.zoxweb.shared.annotation.EndPointProp;
import org.zoxweb.shared.annotation.ParamProp;
import org.zoxweb.shared.annotation.SecurityProp;
import org.zoxweb.shared.http.HTTPMethod;
import org.zoxweb.shared.security.SecurityConsts.AuthenticationType;
import org.zoxweb.shared.util.*;

import java.util.Date;


public class Ping
    extends PropertyHolder
{


    private Const.SizeInBytes sib = Const.SizeInBytes.M;
    @EndPointProp(methods = {HTTPMethod.GET}, name="ping", uris="/ping/{detailed}")
    @SecurityProp(authentications = {AuthenticationType.ALL})
    public NVGenericMap ping(@ParamProp(name="detailed", optional = true) boolean detailed)
    {
        NVGenericMap response = new NVGenericMap();
        response.add("message", "App server is up and running.");
        response.add("timestamp", DateUtil.DEFAULT_GMT_MILLIS.format(new Date()));
        response.add(getProperties().get("server_name"));
        response.add(getProperties().get("version"));
        if(detailed)
        {

            response.add("jdk_version", System.getProperty("java.version"));
            response.add("uptime", Const.TimeInMillis.toString(System.currentTimeMillis() - TaskUtil.START_TIME_MILLIS));
            response.add("current_thread", Thread.currentThread().getName());
            response.add("os", System.getProperty("os.name") + "," + System.getProperty("os.version")
            + "," + System.getProperty("os.arch"));
            //response.getProperties().add("version", )
            response.add(TaskUtil.getDefaultTaskScheduler().getProperties());
            response.add(TaskUtil.getDefaultTaskProcessor().getProperties());
            response.add(RuntimeUtil.vmSnapshot(sib));
        }
        return response;
    }

    @Override
    protected void refreshProperties() {
        if(getProperties() != null)
        {
            String sizeInBytes = getProperties().getValue("size_in_bytes");
            if (sizeInBytes != null)
            {
                Const.SizeInBytes sibValue = SharedUtil.enumValue(Const.SizeInBytes.class, sizeInBytes);
                if(sibValue != null)
                    sib = sibValue;
            }
        }
    }
}
