package io.xlogistx.http.services;

import io.xlogistx.shiro.ShiroUtil;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.shared.annotation.EndPointProp;
import org.zoxweb.shared.annotation.ParamProp;
import org.zoxweb.shared.annotation.SecurityProp;
import org.zoxweb.shared.http.HTTPMethod;
import org.zoxweb.shared.security.SecConst;

public class Logout {
    public static final LogWrapper log = new LogWrapper(Logout.class).setEnabled(true);

    @EndPointProp(methods = {HTTPMethod.GET, HTTPMethod.POST}, name = "subject-logout", uris = "/logout/{appID}")
    @SecurityProp(authentications = {SecConst.AuthenticationType.ALL})
    public void logout(@ParamProp(name = "appID", optional = true) String appID) {
        ShiroUtil.subject().logout();
    }

}
