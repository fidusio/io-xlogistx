package io.xlogistx.http.services;

import io.xlogistx.shiro.ShiroUtil;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.Permission;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.shared.annotation.EndPointProp;
import org.zoxweb.shared.annotation.ParamProp;
import org.zoxweb.shared.annotation.SecurityProp;
import org.zoxweb.shared.crypto.CryptoConst;
import org.zoxweb.shared.http.HTTPMethod;
import org.zoxweb.shared.security.shiro.ShiroSessionData;

public class Login {
    public static final LogWrapper log = new LogWrapper(Login.class).setEnabled(true);

    @EndPointProp(methods = {HTTPMethod.GET}, name = "subject-login", uris = "/subject/login/{appID}")
    @SecurityProp(authentications = {CryptoConst.AuthenticationType.ALL})
    public ShiroSessionData login(@ParamProp(name = "appID", optional = true) String appID) {
        if (log.isEnabled()) log.getLogger().info("appID: " + appID);
        AuthorizationInfo ai = ShiroUtil.lookupAuthorizationInfo(ShiroUtil.subject());

        ShiroSessionData ssd = new ShiroSessionData();
        ssd.setSubjectID((String) ShiroUtil.subject().getPrincipal());
        if (ai != null) {

            for (Permission permission : ai.getObjectPermissions()) {
                //this is very bad just temp
                ssd.addPermissions(permission.toString());
            }
            ssd.setRoles(ai.getRoles());
        }

        return ssd;
    }

//    @Override
//    @EndPointProp(methods = {HTTPMethod.GET}, name="subject-login", uris="/subject/login/*")
//    public void handle(@ParamProp(name="session-data", source = Const.ParamSource.RESOURCE, optional=true)HTTPSessionData sessionData)
//    {
//        HTTPMessageConfigInterface request = sessionData.protocolHandler.getRequest();
//
//
//        // login the subject
//        SecurityUtils.getSubject().login(ShiroUtil.httpAuthorizationToAuthToken(request.getAuthorization()));
//        AuthorizationInfo ai = ShiroUtil.lookupAuthorizationInfo(ShiroUtil.subject());
//        if(ai != null)
//        {
//            ShiroSessionData ssd = new ShiroSessionData();
//            ssd.setPermissions(ai.getStringPermissions());
//            ssd.setRoles(ai.getRoles());
//        }
//    }


}
