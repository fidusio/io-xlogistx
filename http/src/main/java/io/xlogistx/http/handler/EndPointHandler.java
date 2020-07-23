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

    private MethodHolder methodHolder;


    public EndPointHandler(MethodHolder methodHolder)
    {
        this.methodHolder = methodHolder;

    }

    public ReflectionUtil.MethodAnnotations getMethodAnnotations()
    {
        return methodHolder.getMethodAnnotations();
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        // validate authentication
        long ts = System.nanoTime();
        long count = callCounter.getAndIncrement();

//        URI uri = exchange.getRequestURI();
//        log.info("uri:" + uri);
//        log.info("query:" + uri.getQuery());
//        log.info("raw query:" + uri.getRawQuery());
//        log.info("uri path:" + uri.getPath());
//        log.info("context path:"+exchange.getHttpContext().getPath());
//        log.info("request headers:" + exchange.getRequestHeaders().entrySet());
//        log.info("content type:" + ((LinkedList<String>)exchange.getRequestHeaders().get(HTTPHeaderName.CONTENT_TYPE.getName())).get(0));



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
        log.info("[" + count + "]:" + getHTTPEndPoint().getName() + " took " + Const.TimeInMillis.nanosToString(ts));
    }

    protected void init()
    {
    }

}
