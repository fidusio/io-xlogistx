package io.xlogistx.http.handler;

import com.sun.net.httpserver.HttpHandler;
import io.xlogistx.common.data.MethodHolder;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.shared.http.HTTPEndPoint;
import org.zoxweb.shared.util.SharedUtil;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;


public abstract class BaseEndPointHandler
    implements HttpHandler
{
    public final static LogWrapper log = new LogWrapper(BaseEndPointHandler.class);
    protected AtomicLong callCounter = new AtomicLong();

    private HTTPEndPoint hep;
    protected MethodHolder methodHolder;
    private static final AtomicInteger counter = new AtomicInteger();
    public final int ID = counter.incrementAndGet();

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


    public MethodHolder getMethodHolder()
    {
        return methodHolder;
    }



    protected abstract void init();
}
