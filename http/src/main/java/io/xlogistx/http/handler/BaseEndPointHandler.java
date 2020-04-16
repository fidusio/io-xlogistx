package io.xlogistx.http.handler;

import com.sun.net.httpserver.HttpHandler;
import org.zoxweb.shared.http.HTTPEndPoint;
import org.zoxweb.shared.util.SharedUtil;

public abstract class BaseEndPointHandler
    implements HttpHandler
{
    private HTTPEndPoint hpe;


    public HTTPEndPoint getHTTPEndPoint()
    {
        return hpe;
    }

    public void setHTTPEndPoint(HTTPEndPoint hpe)
    {
        SharedUtil.checkIfNulls("HTTPEndPoint can't be null", hpe);
        this.hpe = hpe;
        init();
    }

    protected abstract void init();
}
