package io.xlogistx.shiro.service;

import org.zoxweb.server.http.HTTPAPIDecoder;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.shared.http.HTTPResponseData;
import org.zoxweb.shared.security.SecSessionData;

public class ShiroSessionDataDecoder
extends HTTPAPIDecoder<SecSessionData>
{
    @Override
    public SecSessionData decode(HTTPResponseData responseData)
    {
        return GSONUtil.fromJSONDefault(responseData.getData(), SecSessionData.class);
    }
}
