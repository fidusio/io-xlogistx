package io.xlogistx.common.data;

import org.zoxweb.server.util.ReflectionUtil;
import org.zoxweb.shared.security.ResourceSecurity;
import org.zoxweb.server.security.SecureInvoker;
import org.zoxweb.shared.util.SUS;

import java.lang.reflect.InvocationTargetException;
import java.util.Map;


public class MethodContainer {
    public final Object instance;
    public final ReflectionUtil.MethodAnnotations methodAnnotations;
    public final ResourceSecurity resourceSec;
    private final SecureInvoker secureMethodInvoker;

    public MethodContainer(Object instance, ReflectionUtil.MethodAnnotations methodAnnotations, ResourceSecurity resourceSec, SecureInvoker secureInvocation) {
        SUS.checkIfNulls("Nulls founds", instance, methodAnnotations, secureInvocation);
        if (!ReflectionUtil.hasMethod(instance, methodAnnotations.method))
            throw new IllegalArgumentException("Method not supported by instance " + methodAnnotations.method);
        this.instance = instance;
        this.methodAnnotations = methodAnnotations;
        this.resourceSec = resourceSec;
        this.secureMethodInvoker = secureInvocation;
    }


    public <V> V invoke(Object... parameters) throws InvocationTargetException, IllegalAccessException {
        return secureMethodInvoker.invoke(true, false, instance, methodAnnotations.method, parameters);
    }


    public <V> V invoke(Map<String, Object> parameters) throws InvocationTargetException, IllegalAccessException {
        return secureMethodInvoker.invoke(true, instance, methodAnnotations, parameters);
    }



}
