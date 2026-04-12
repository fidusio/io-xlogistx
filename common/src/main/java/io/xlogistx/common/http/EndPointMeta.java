package io.xlogistx.common.http;

import io.xlogistx.common.data.MethodContainer;
import org.zoxweb.shared.http.HTTPEndPoint;

public class EndPointMeta {
    public final HTTPEndPoint httpEndPoint;
    public final MethodContainer methodContainer;


    public EndPointMeta(HTTPEndPoint hep, MethodContainer mh) {
        this.httpEndPoint = hep;
        this.methodContainer = mh;
    }

    @Override
    public String toString() {
        return "EndPointMeta{" +
                "httpEndPoint=" + httpEndPoint +
                ", methodContainer=" + methodContainer +
                '}';
    }
}