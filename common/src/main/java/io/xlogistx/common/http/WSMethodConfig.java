package io.xlogistx.common.http;

import io.xlogistx.common.data.MethodContainer;

import javax.websocket.server.ServerEndpointConfig;
import java.lang.annotation.Annotation;

public class WSMethodConfig {


    ServerEndpointConfig fd;
    private Annotation methodAnnotation;
    public final MethodContainer methodContainer;


    public WSMethodConfig(MethodContainer methodContainer) {
        this.methodContainer = methodContainer;
    }

    public Annotation getMethodAnnotation() {
        return methodAnnotation;
    }

    public WSMethodConfig setMethodAnnotation(Annotation methodAnnotation) {
        this.methodAnnotation = methodAnnotation;
        return this;
    }


}
