package io.xlogistx.http.services;

import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.shared.annotation.EndPointProp;
import org.zoxweb.shared.annotation.ParamProp;
import org.zoxweb.shared.annotation.SecurityProp;
import org.zoxweb.shared.data.SimpleMessage;
import org.zoxweb.shared.http.HTTPMethod;
import org.zoxweb.shared.http.HTTPStatusCode;
import org.zoxweb.shared.security.AuthenticationType;
import org.zoxweb.shared.util.Const;
import org.zoxweb.shared.util.NVPair;



public class Ping {

    @EndPointProp(methods = {HTTPMethod.GET}, name="ping", uris="/ping")
    @SecurityProp(authentications = {AuthenticationType.ALL})
    public SimpleMessage ping(@ParamProp(name="detailed", optional = true) boolean detailed)
    {
        SimpleMessage response = new SimpleMessage("App server is up and running.", HTTPStatusCode.OK.CODE);
        response.setCreationTime(System.currentTimeMillis());
        if(detailed)
        {
            response.getProperties().add(new NVPair("uptime", Const.TimeInMillis.toString(System.currentTimeMillis() - TaskUtil.START_TIME_MILLIS)));
        }
        return response;
    }
}
