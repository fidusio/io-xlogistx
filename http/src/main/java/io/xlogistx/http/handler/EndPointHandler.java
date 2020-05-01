package io.xlogistx.http.handler;

import com.sun.net.httpserver.HttpExchange;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.server.util.ReflectionUtil;
import org.zoxweb.shared.http.HTTPEndPoint;
import org.zoxweb.shared.http.HTTPStatusCode;
import org.zoxweb.shared.util.Const;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.net.URI;
import java.util.logging.Logger;

public class EndPointHandler
extends BaseEndPointHandler {
    private static transient Logger log = Logger.getLogger(EndPointHandler.class.getName());

    private Object bean;
    private ReflectionUtil.AnnotationMap annotationMap;
    private ReflectionUtil.MethodAnnotations[] methodAnnotations;


    public EndPointHandler(Object bean, ReflectionUtil.AnnotationMap annotationMap)
    {
        this.bean = bean;
        this.annotationMap = annotationMap;
        this.methodAnnotations = annotationMap.getMethodsAnnotations().values().toArray( new ReflectionUtil.MethodAnnotations[0]);
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        // validate authentication
        long ts = System.nanoTime();
        long count = callCounter.getAndIncrement();

        URI uri = exchange.getRequestURI();
        log.info("uri:" + uri);
        log.info("query:" + uri.getQuery());
        log.info("raw query:" + uri.getRawQuery());
        log.info("uri path:" + uri.getPath());
        log.info("context path:"+exchange.getHttpContext().getPath());

        // validate path
        // inspect method
        // invoke method
        Object result = null;
        try
        {
            if (hep.isMethodSupported(exchange.getRequestMethod()))
            {
                Parameter params[] =  methodAnnotations[0].method.getParameters();

                result = methodAnnotations[0].method.invoke(bean);
                if (result instanceof Void) {
                    exchange.sendResponseHeaders(HTTPStatusCode.OK.CODE, 0);
                } else {
                    HTTPHandlerUtil.sendJSONResponse(exchange, HTTPStatusCode.OK, result, true);
                }
            }
            else
            {
                // method not supported
                HTTPHandlerUtil.sendErrorMessage(exchange, HTTPStatusCode.NOT_FOUND, exchange.getRequestMethod() + " not supported.", true);
            }
        } catch (Exception e) {
            e.printStackTrace();
            HTTPHandlerUtil.sendErrorMessage(exchange, HTTPStatusCode.SERVICE_UNAVAILABLE, "error invoking resource", true);
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
