package io.xlogistx.http.handler;

import com.sun.net.httpserver.HttpExchange;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.shared.http.HTTPEndPoint;
import org.zoxweb.shared.http.HTTPStatusCode;
import org.zoxweb.shared.util.Const;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.logging.Logger;

public class EndPointHandler
extends BaseEndPointHandler {
    private static transient Logger log = Logger.getLogger(EndPointHandler.class.getName());

    private Object bean;
    private Method method;


    public EndPointHandler(Object bean, Method method)
    {
        this.bean = bean;
        this.method = method;
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        // validate authentication
        long ts = System.nanoTime();
        long count = callCounter.getAndIncrement();


        //log.info("[" + count + "]:" + getHTTPEndPoint().getName());
        // validate path

        // inspect method


        // invoke method
        Object result = null;
        try
        {
            if (hep.isMethodSupported(exchange.getRequestMethod()))
            {
                result = method.invoke(bean);
                if (result instanceof Void) {
                    exchange.sendResponseHeaders(HTTPStatusCode.OK.CODE, 0);
                } else {
                    HTTPHandlerUtil.sendJSONResponse(exchange, HTTPStatusCode.OK, result);
                }
            }
            else
            {
                // method not supported
                HTTPHandlerUtil.sendErrorMessage(exchange, HTTPStatusCode.NOT_FOUND, exchange.getRequestMethod() + " not FOUND");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        finally {
            exchange.close();
        }

        // based on result return response
        //log.info("[" + count + "]:" + getHTTPEndPoint().getName() + "   END");
        ts = System.nanoTime() - ts;
        log.info("[" + count + "]:" + hep.getName() + " took " + Const.TimeInMillis.nanosToString(ts));
    }

    protected void init()
    {
    }
}
