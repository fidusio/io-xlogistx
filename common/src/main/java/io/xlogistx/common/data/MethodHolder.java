package io.xlogistx.common.data;

import org.zoxweb.server.util.ReflectionUtil;



public class MethodHolder {
    private Object instance;
    private ReflectionUtil.MethodAnnotations methodAnnotations;

    public MethodHolder(Object instance, ReflectionUtil.MethodAnnotations methodAnnotations)
    {
        if (!ReflectionUtil.hasMethod(instance, methodAnnotations.method))
            throw new IllegalArgumentException("Method not supported by instance " + methodAnnotations.method);
        this.instance = instance;
        this.methodAnnotations = methodAnnotations;
    }

    public Object getInstance()
    {
        return instance;
    }

    public ReflectionUtil.MethodAnnotations getMethodAnnotations()
    {
        return methodAnnotations;
    }


}
