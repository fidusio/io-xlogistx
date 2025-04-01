package io.xlogistx.common.data;

import org.zoxweb.server.util.ReflectionUtil;
import org.zoxweb.shared.security.ResourceSecurity;


public class MethodHolder {
    public final Object instance;
    public final ReflectionUtil.MethodAnnotations methodAnnotations;
    public final ResourceSecurity resourceSec;

    public MethodHolder(Object instance, ReflectionUtil.MethodAnnotations methodAnnotations, ResourceSecurity resourceSec)
    {
        if (!ReflectionUtil.hasMethod(instance, methodAnnotations.method))
            throw new IllegalArgumentException("Method not supported by instance " + methodAnnotations.method);
        this.instance = instance;
        this.methodAnnotations = methodAnnotations;
        this.resourceSec = resourceSec;
    }

//    public Object getInstance()
//    {
//        return instance;
//    }

//    public ReflectionUtil.MethodAnnotations getMethodAnnotations()
//    {
//        return methodAnnotations;
//    }


}
