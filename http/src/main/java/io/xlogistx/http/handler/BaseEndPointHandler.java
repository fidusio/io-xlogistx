package io.xlogistx.http.handler;

import com.sun.net.httpserver.HttpHandler;
import org.zoxweb.shared.http.HTTPEndPoint;
import org.zoxweb.shared.util.SharedUtil;

import java.util.concurrent.atomic.AtomicLong;

public abstract class BaseEndPointHandler
    implements HttpHandler
{

    protected AtomicLong callCounter = new AtomicLong();
    protected HTTPEndPoint hep;


    public HTTPEndPoint getHTTPEndPoint()
    {
        return hep;
    }

    public void setHTTPEndPoint(HTTPEndPoint hep)
    {
        SharedUtil.checkIfNulls("HTTPEndPoint can't be null", hep);
        this.hep = hep;
        init();
    }

    protected abstract void init();
}
