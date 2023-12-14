package io.xlogistx.shiro.service;

import org.zoxweb.server.http.HTTPAPIEndPoint;
import org.zoxweb.shared.http.HTTPAuthorization;
import org.zoxweb.shared.http.HTTPMessageConfigInterface;
import org.zoxweb.shared.security.shiro.ShiroSubjectData;

public class ShiroProxyHTTPAPI
extends HTTPAPIEndPoint<HTTPAuthorization, ShiroSubjectData>
{
    public ShiroProxyHTTPAPI(HTTPMessageConfigInterface config) {
        super(config);
    }
}
