package io.xlogistx.shiro.service;

import org.zoxweb.server.http.HTTPAPIDecoder;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.shared.http.HTTPResponseData;
import org.zoxweb.shared.security.shiro.ShiroSessionData;

public class ShiroSessionDataDecoder
extends HTTPAPIDecoder<ShiroSessionData>
{
    @Override
    public ShiroSessionData decode(HTTPResponseData responseData)
    {
        return GSONUtil.fromJSONDefault(responseData.getData(), ShiroSessionData.class);
    }
}
