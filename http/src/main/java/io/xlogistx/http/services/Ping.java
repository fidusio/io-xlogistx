package io.xlogistx.http.services;

import org.zoxweb.shared.annotation.EndPointProp;
import org.zoxweb.shared.annotation.SecurityProp;
import org.zoxweb.shared.data.SimpleMessage;
import org.zoxweb.shared.http.HTTPMethod;
import org.zoxweb.shared.http.HTTPStatusCode;
import org.zoxweb.shared.security.AuthenticationType;

public class Ping {

    @EndPointProp(methods = {HTTPMethod.GET}, name="ping", uris="/ping")
    @SecurityProp(authentications = {AuthenticationType.ALL})
    public SimpleMessage ping()
    {
        SimpleMessage response = new SimpleMessage("App server is up and running.", HTTPStatusCode.OK.CODE);
        response.setCreationTime(System.currentTimeMillis());
        return response;
    }
}
