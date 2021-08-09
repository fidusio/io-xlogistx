package io.xlogistx.http;

import io.xlogistx.common.data.MethodHolder;
import org.zoxweb.shared.http.HTTPEndPoint;

public interface HTTPServerMapper {
    boolean isInstanceNative(Object beanInstance);

    void mapHEP(EndPointsManager endPointsManager, HTTPEndPoint hep, MethodHolder mh, Object beanInstance);
}
