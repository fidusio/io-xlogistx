package io.xlogistx.http.servlet;

import io.xlogistx.common.data.MethodHolder;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.shared.api.APIError;

import org.zoxweb.shared.http.HTTPEndPoint;
import org.zoxweb.shared.http.HTTPMethod;

import org.zoxweb.shared.http.HTTPStatusCode;
import org.zoxweb.shared.security.AccessException;
import org.zoxweb.shared.util.Const;
import org.zoxweb.shared.util.NVEntity;


import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.concurrent.atomic.AtomicLong;


public class HTTPBeanServlet
extends HttpServlet {
    public static final APIError DEFAULT_API_ERROR = new APIError(new AccessException("Access denied.", null, true));
    public final static LogWrapper log = new LogWrapper(HTTPBeanServlet.class);
    private static AtomicLong serviceCounter = new AtomicLong();
    private final MethodHolder mh;
    private final HTTPEndPoint hep;


    public HTTPBeanServlet(HTTPEndPoint hep, MethodHolder mh) {
        this.hep = hep;
        this.mh = mh;
    }

    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        log.getLogger().info("" + hep);
    }



    public MethodHolder getMethodHolder()
    {
        return mh;
    }

    public HTTPEndPoint getHTTPEndPoint()
    {
        return hep;
    }

    @Override
    protected void service(HttpServletRequest req, HttpServletResponse res)
            throws ServletException, IOException
    {
        long delta = System.nanoTime();
        long counter = serviceCounter.incrementAndGet();
        int size = 0;

        try
        {

            HTTPMethod hm = HTTPMethod.lookup(req.getMethod());
            if (hm == null)
            {
                super.service(req, res);
                return;
            }
            log.getLogger().info("HTTPMethod:" + hm);
            if (!hep.isHTTPMethodSupported(hm))
            {
                size = HTTPServletUtil.sendJSON(req, res, HTTPStatusCode.SERVICE_UNAVAILABLE, (NVEntity) new APIError("Service not support"));
                return;
            }



//            switch(hm)
//            {
//
//                case GET:
//                    break;
//                case POST:
//                    break;
//                case HEAD:
//                    break;
//                case OPTIONS:
//                    break;
//                case PUT:
//                    break;
//                case DELETE:
//                    break;
//                case TRACE:
//                    break;
//                case CONNECT:
//                    break;
//                case PATCH:
//                    break;
//                case COPY:
//                    break;
//                case LINK:
//                    break;
//                case UNLINK:
//                    break;
//                case PURGE:
//                    break;
//                case LOCK:
//                    break;
//                case UNLOCK:
//                    break;
//                case PROPFIND:
//                    break;
//                case VIEW:
//                    break;
//            }


        }
        finally
        {
            //postService(req, res);
            delta = System.nanoTime() - delta;
            log.getLogger().info(getServletName() + ":" + req.getMethod() + ":PT:" + Const.TimeInMillis.nanosToString(delta) +":TOTAL CALLS:" + counter + ":response size:" + size);
        }
    }
}
