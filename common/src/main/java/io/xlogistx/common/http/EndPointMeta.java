package io.xlogistx.common.http;

import io.xlogistx.common.data.MethodHolder;
import org.zoxweb.shared.http.HTTPEndPoint;

public class EndPointMeta {
    public final HTTPEndPoint httpEndPoint;
    public final MethodHolder methodHolder;

    public EndPointMeta(HTTPEndPoint hep, MethodHolder mh) {
        this.httpEndPoint = hep;
        this.methodHolder = mh;
    }
}