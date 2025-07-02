package io.xlogistx.shiro;

import org.zoxweb.server.security.SecUtil;
import org.zoxweb.server.util.ReflectionUtil;
import org.zoxweb.server.security.SecureInvoker;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Map;

public class ShiroInvoker
        implements SecureInvoker {
    public static final ShiroInvoker SINGLETON = new ShiroInvoker();

    private ShiroInvoker() {
    }

    @Override
    public <V> V invoke(boolean authCheck, boolean strict, Object bean, Method method, Object... parameters) throws InvocationTargetException, IllegalAccessException {
        if(authCheck)
            ShiroUtil.authorizationCheckPoint(SecUtil.SINGLETON.lookupCachedResourceSecurity(method));
        return (V) ReflectionUtil.invokeMethod(strict, bean, method, parameters);
    }

    @Override
    public <V> V invoke(boolean authCheck, Object bean, ReflectionUtil.MethodAnnotations methodAnnotations, Map<String, Object> parameters) throws InvocationTargetException, IllegalAccessException {
        if(authCheck)
            ShiroUtil.authorizationCheckPoint(SecUtil.SINGLETON.lookupCachedResourceSecurity(methodAnnotations.method));

        return (V)ReflectionUtil.invokeMethod(bean, methodAnnotations, parameters);
    }
}
