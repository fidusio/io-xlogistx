package io.xlogistx.http.services;

import org.zoxweb.server.util.DateUtil;
import org.zoxweb.shared.annotation.EndPointProp;
import org.zoxweb.shared.http.HTTPMethod;
import org.zoxweb.shared.util.NVGenericMap;

import java.util.Date;


public class CurrentTimestamp {
    @EndPointProp(methods = {HTTPMethod.GET}, name = "timestamp", uris = "/timestamp")
    public NVGenericMap timestamp() {
        return new NVGenericMap().build("current_time", DateUtil.DEFAULT_GMT_MILLIS.format(new Date()));
    }
}
