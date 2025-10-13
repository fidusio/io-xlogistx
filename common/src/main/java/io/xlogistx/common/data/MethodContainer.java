package io.xlogistx.common.data;

import org.zoxweb.server.security.SecureInvoker;
import org.zoxweb.server.util.ReflectionUtil;
import org.zoxweb.shared.security.ResourceSecurity;
import org.zoxweb.shared.util.SUS;

import java.lang.reflect.InvocationTargetException;
import java.util.LinkedHashMap;
import java.util.Map;


public class MethodContainer {
    public final Object instance;
    public final ReflectionUtil.MethodAnnotations methodAnnotations;
    public final ResourceSecurity resourceSec;
    private final SecureInvoker secureMethodInvoker;
    private static final Map<Class<?>, Object> instanceCache = new LinkedHashMap<>();


    public MethodContainer(Class<?> clazz, ReflectionUtil.MethodAnnotations methodAnnotations, ResourceSecurity resourceSec, SecureInvoker secureInvocation) throws InvocationTargetException, NoSuchMethodException, InstantiationException, IllegalAccessException {
        SUS.checkIfNulls("Nulls clazz or methodAnnotations or secureInvocation", clazz, methodAnnotations, secureInvocation);
        instance = createInstance(clazz);
        if (!ReflectionUtil.hasMethod(instance, methodAnnotations.method))
            throw new IllegalArgumentException("Method not supported by instance " + methodAnnotations.method);
        this.methodAnnotations = methodAnnotations;
        this.resourceSec = resourceSec;
        this.secureMethodInvoker = secureInvocation;
    }

    public MethodContainer(Object instance, ReflectionUtil.MethodAnnotations methodAnnotations, ResourceSecurity resourceSec, SecureInvoker secureInvocation) {
        SUS.checkIfNulls("Nulls instance or methodAnnotations or secureInvocation", instance, methodAnnotations, secureInvocation);
        if (!ReflectionUtil.hasMethod(instance, methodAnnotations.method))
            throw new IllegalArgumentException("Method not supported by instance " + methodAnnotations.method);
        // cache it first
        synchronized (instanceCache) {
            instanceCache.putIfAbsent(instance.getClass(), instance);
        }
        // always use the cached value
        this.instance = instanceCache.get(instance.getClass());
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

    public static Object createInstance(Class<?> clazz) throws NoSuchMethodException, InvocationTargetException, InstantiationException, IllegalAccessException {
        SUS.checkIfNulls("Null clazz", clazz);
        synchronized (instanceCache) {
            if (instanceCache.get(clazz) == null)
                instanceCache.put(clazz, clazz.getDeclaredConstructor().newInstance());

            return instanceCache.get(clazz);
        }
    }

    public String toString() {
        return instance.getClass().getName() + "::" + methodAnnotations.method.getName() + "##" + instance.hashCode();
    }


}
