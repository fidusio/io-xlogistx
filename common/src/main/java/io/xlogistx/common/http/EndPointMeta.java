package io.xlogistx.common.http;

import io.xlogistx.common.data.MethodHolder;
import org.zoxweb.shared.http.HTTPEndPoint;

public class EndPointMeta
{
    public final HTTPEndPoint httpEndPoint;
    public final MethodHolder methodHolder;
    public final boolean isWS;
    public EndPointMeta(HTTPEndPoint hep, MethodHolder mh)
    {
        this(hep, mh, false);
    }
    public EndPointMeta(HTTPEndPoint hep, MethodHolder mh, boolean isWS)
    {
        this.httpEndPoint = hep;
        this.methodHolder = mh;
        this.isWS = isWS;
    }
}