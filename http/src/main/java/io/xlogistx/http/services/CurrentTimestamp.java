package io.xlogistx.http.services;

import org.zoxweb.server.util.DateUtil;
import org.zoxweb.shared.annotation.EndPointProp;
import org.zoxweb.shared.http.HTTPMethod;
import org.zoxweb.shared.util.NVGenericMap;
import org.zoxweb.shared.util.NVPair;
import java.util.Date;


public class CurrentTimestamp {
    @EndPointProp(methods = {HTTPMethod.GET}, name="timestamp", uris="/timestamp")
    public NVGenericMap timestamp()
    {
        NVGenericMap response = new NVGenericMap();
        response.add(new NVPair("current_time", DateUtil.DEFAULT_GMT_MILLIS.format(new Date())));
        return response;
    }
}
