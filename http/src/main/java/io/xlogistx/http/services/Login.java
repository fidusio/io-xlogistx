package io.xlogistx.http.services;

import io.xlogistx.common.http.HTTPProtocolHandler;
import io.xlogistx.common.http.HTTPRawHandler;
import io.xlogistx.shiro.ShiroUtil;
import org.apache.shiro.subject.Subject;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.util.DateUtil;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.shared.annotation.EndPointProp;
import org.zoxweb.shared.annotation.ParamProp;
import org.zoxweb.shared.annotation.SecurityProp;
import org.zoxweb.shared.crypto.CryptoConst;
import org.zoxweb.shared.http.*;
import org.zoxweb.shared.security.AccessException;
import org.zoxweb.shared.util.*;

import java.io.IOException;
import java.util.Date;

public class Login
        implements HTTPRawHandler {
    public static final LogWrapper log = new LogWrapper(Login.class).setEnabled(true);


    @EndPointProp(methods = {HTTPMethod.GET}, name = "login", uris = "/login/{appID}")
    @SecurityProp(authentications = {CryptoConst.AuthenticationType.ALL})
    @Override
    public boolean handle(@ParamProp(name = "raw-content", source = Const.ParamSource.RESOURCE, optional = true) HTTPProtocolHandler hph) throws IOException {
        Subject subject = ShiroUtil.subject();

        if(!subject.isAuthenticated())
            throw new AccessException("Not authenticated");

        subject.getSession(true);

        if (log.isEnabled()) {
            log.getLogger().info("Session : "  + ShiroUtil.toString(subject.getSession()));
        }

        subject.getSession(true);
        if (log.isEnabled()) {
            log.getLogger().info("Session : "  + ShiroUtil.toString(subject.getSession()));
        }

        HTTPMessageConfigInterface response  = hph.buildResponse(HTTPStatusCode.OK,
                HTTPHeader.SERVER.toHTTPHeader(((GetNamedVersion) ResourceManager.SINGLETON.lookup(ResourceManager.Resource.HTTP_SERVER)).getName()));

        response.setContentType("application/json");
        response.getHeaders().build(HTTPHeader.SET_COOKIE, HTTPConst.SESSION_ID + "=" +subject.getSession().getId() + "; Path=/; HttpOnly; Secure; SameSite=Strict");


        NVGenericMap responseData = new NVGenericMap();
        responseData.build("login", "ok")
                .build(new NVPair("timestamp", DateUtil.DEFAULT_GMT_MILLIS.format(new Date())));

        response.setContent(GSONUtil.toJSONDefault(responseData, true));


//        HTTPUtil.formatResponse(response, hph.getResponseStream())
//                .writeTo(hph.getOutputStream());

        return true;
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
