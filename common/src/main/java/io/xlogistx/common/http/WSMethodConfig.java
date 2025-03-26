package io.xlogistx.common.http;

import io.xlogistx.common.data.MethodHolder;

import javax.websocket.server.ServerEndpointConfig;
import java.lang.annotation.Annotation;

public class WSMethodConfig
{



    ServerEndpointConfig fd;
    private Annotation methodAnnotation;
    public final MethodHolder methodHolder;


    public WSMethodConfig(MethodHolder methodHolder)
    {
        this.methodHolder = methodHolder;
    }
    public Annotation getMethodAnnotation()
    {
        return methodAnnotation;
    }

    public WSMethodConfig setMethodAnnotation(Annotation methodAnnotation)
    {
        this.methodAnnotation = methodAnnotation;
        return this;
    }


}
