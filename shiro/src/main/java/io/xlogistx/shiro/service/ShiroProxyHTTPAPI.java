package io.xlogistx.shiro.service;

import org.apache.shiro.authc.AuthenticationToken;
import org.zoxweb.server.http.HTTPAPIEndPoint;
import org.zoxweb.shared.http.HTTPMessageConfigInterface;
import org.zoxweb.shared.security.shiro.ShiroSessionData;

public class ShiroProxyHTTPAPI
extends HTTPAPIEndPoint<AuthenticationToken, ShiroSessionData>
{
    public ShiroProxyHTTPAPI(HTTPMessageConfigInterface config) {
        super(config);
        setDataDecoder(new ShiroSessionDataDecoder());
        setDataEncoder(new AuthenticationTokenEncoder());
    }
}
