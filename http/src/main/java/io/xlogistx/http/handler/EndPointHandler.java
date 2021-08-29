package io.xlogistx.http.handler;

import com.sun.net.httpserver.HttpExchange;
import io.xlogistx.common.data.MethodHolder;
import org.zoxweb.server.util.ReflectionUtil;
import org.zoxweb.shared.http.HTTPStatusCode;
import org.zoxweb.shared.util.Const;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.Map;
import java.util.logging.Logger;

public class EndPointHandler
extends BaseEndPointHandler {
    private static transient Logger log = Logger.getLogger(EndPointHandler.class.getName());



    public EndPointHandler(MethodHolder methodHolder)
    {
        this.methodHolder = methodHolder;

    }



    @Override
    public void handle(HttpExchange exchange) throws IOException {
        // validate authentication
        long ts = System.nanoTime();
        long count = callCounter.getAndIncrement();
        // validate path
        // inspect method
        // invoke method
        Object result = null;
        try
        {

            if (getHTTPEndPoint().isMethodSupported(exchange.getRequestMethod()))
            {
                //log.info("Processing: " + getHTTPEndPoint());
                Map<String, Object> parameters = HTTPHandlerUtil.buildParameters(exchange);
                //log.info("Parameters:" + parameters);

                result = ReflectionUtil.invokeMethod(methodHolder.getInstance(),
                                                     methodHolder.getMethodAnnotations(),
                                                     parameters);
                //log.info("Result:" + result);
                if (result == null) {
                    HTTPHandlerUtil.sendSimpleMessage(exchange, HTTPStatusCode.OK, "Success");
                } else {
                    HTTPHandlerUtil.sendResponse(exchange, HTTPStatusCode.OK, null, result);
                }
            }
            else
            {
                // method not supported
                HTTPHandlerUtil.sendErrorMessage(exchange, HTTPStatusCode.NOT_FOUND, exchange.getRequestMethod() + " not supported.", true);
            }
        }
        catch(InvocationTargetException e)
        {
            e.getCause().printStackTrace();
            HTTPHandlerUtil.sendErrorMessage(exchange, HTTPStatusCode.SERVICE_UNAVAILABLE, "error invoking resource:" + e.getCause(), true);
        }
        catch (Exception e) {
            e.printStackTrace();
            HTTPHandlerUtil.sendErrorMessage(exchange, HTTPStatusCode.SERVICE_UNAVAILABLE, "error invoking resource", true);
        }
        finally {
            exchange.close();
        }


        // based on result return response
        //log.info("[" + count + "]:" + getHTTPEndPoint().getName() + "   END");
        ts = System.nanoTime() - ts;
        if (count % 100 == 0)
            log.info("[" + count + "]:" + getHTTPEndPoint().getName() + " took " + Const.TimeInMillis.nanosToString(ts));
    }

    protected void init()
    {
    }

}
