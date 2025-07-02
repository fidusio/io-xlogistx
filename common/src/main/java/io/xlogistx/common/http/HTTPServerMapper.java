package io.xlogistx.common.http;

import io.xlogistx.common.data.MethodContainer;
import org.zoxweb.shared.http.HTTPEndPoint;

public interface HTTPServerMapper {
    boolean isInstanceNative(Object beanInstance);

    void mapHEP(EndPointsManager endPointsManager, HTTPEndPoint hep, MethodContainer mh, Object beanInstance);
}
