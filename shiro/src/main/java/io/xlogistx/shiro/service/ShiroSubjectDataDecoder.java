package io.xlogistx.shiro.service;

import org.zoxweb.server.http.HTTPAPIDecoder;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.shared.http.HTTPResponseData;
import org.zoxweb.shared.security.shiro.ShiroSubjectData;

public class ShiroSubjectDataDecoder
extends HTTPAPIDecoder<ShiroSubjectData>
{
    @Override
    public ShiroSubjectData decode(HTTPResponseData responseData)
    {
        return GSONUtil.fromJSONDefault(responseData.getData(), ShiroSubjectData.class);
    }
}
