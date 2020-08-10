package io.xlogistx.http.services;

import io.xlogistx.common.data.PropertyHolder;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.server.util.RuntimeUtil;
import org.zoxweb.shared.annotation.EndPointProp;
import org.zoxweb.shared.annotation.ParamProp;
import org.zoxweb.shared.annotation.SecurityProp;
import org.zoxweb.shared.data.SimpleMessage;
import org.zoxweb.shared.http.HTTPMethod;
import org.zoxweb.shared.http.HTTPStatusCode;
import org.zoxweb.shared.security.SecurityConsts.AuthenticationType;
import org.zoxweb.shared.util.Const;
import org.zoxweb.shared.util.NVGenericMap;
import org.zoxweb.shared.util.NVPair;
import org.zoxweb.shared.util.SharedUtil;


public class Ping
    extends PropertyHolder
{

    private Const.SizeInBytes sib = Const.SizeInBytes.M;
    @EndPointProp(methods = {HTTPMethod.GET}, name="ping", uris="/ping/{detailed}")
    @SecurityProp(authentications = {AuthenticationType.ALL})
    public SimpleMessage ping(@ParamProp(name="detailed", optional = true) boolean detailed)
    {
        SimpleMessage response = new SimpleMessage("App server is up and running.", HTTPStatusCode.OK.CODE);
        response.setCreationTime(System.currentTimeMillis());
        if(detailed)
        {

            response.getProperties().add("jdk_version", System.getProperty("java.version"));
            response.getProperties().add("uptime", Const.TimeInMillis.toString(System.currentTimeMillis() - TaskUtil.START_TIME_MILLIS));
            response.getProperties().add("current_thread", Thread.currentThread().getName());
            //response.getProperties().add("version", )
            response.getProperties().add(TaskUtil.getDefaultTaskScheduler().getProperties());
            response.getProperties().add(TaskUtil.getDefaultTaskProcessor().getProperties());
            response.getProperties().add(RuntimeUtil.vmSnapshot(sib));
        }
        return response;
    }

    @Override
    protected void propertiesUpdated() {
        if(getProperties() != null)
        {
            String sizeInBytes = getProperties().getValue("size_in_bytes");
            if (sizeInBytes != null)
            {
                Const.SizeInBytes sibValue = (Const.SizeInBytes) SharedUtil.enumValue(Const.SizeInBytes.class, sizeInBytes);
                if(sibValue != null)
                    sib = sibValue;
            }
        }
    }
}
