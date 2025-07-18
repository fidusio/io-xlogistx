package io.xlogistx.http.services;


import io.xlogistx.http.EndpointsUtil;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.server.util.JMod;
import org.zoxweb.server.util.ReflectionUtil;
import org.zoxweb.shared.annotation.EndPointProp;
import org.zoxweb.shared.annotation.ParamProp;
import org.zoxweb.shared.annotation.SecurityProp;
import org.zoxweb.shared.crypto.CryptoConst;
import org.zoxweb.shared.data.SimpleMessage;
import org.zoxweb.shared.http.HTTPMethod;
import org.zoxweb.shared.http.HTTPStatusCode;
import org.zoxweb.shared.util.Const;
import org.zoxweb.shared.util.NVBoolean;
import org.zoxweb.shared.util.NVGenericMap;


public class AppCommand
{


    @EndPointProp(methods = {HTTPMethod.GET}, name = "app-shutdown", uris = "/app/shutdown")
    @SecurityProp(authentications = {CryptoConst.AuthenticationType.ALL}, permissions = "app:shutdown")
    public SimpleMessage appShutdown() {

        EndpointsUtil.SINGLETON.shutdown();

        long delay = Const.TimeInMillis.SECOND.MILLIS * 5;
        TaskUtil.defaultTaskScheduler().queue(delay, () -> System.exit(0));
        return new SimpleMessage("App will shutdown in " + Const.TimeInMillis.toString(delay), HTTPStatusCode.OK.CODE);
    }


    @EndPointProp(methods = {HTTPMethod.GET}, name = "class-logger", uris = "/app/logger/{className}/{status}")
    @SecurityProp(authentications = {CryptoConst.AuthenticationType.ALL}, permissions = "app:logger:read, app:logger:write")
    public NVGenericMap loggerAccess(@ParamProp(name = "className") String className, @ParamProp(name = "status") boolean status) throws ClassNotFoundException, IllegalAccessException {
        Class<?> clazz = Class.forName(className);
        LogWrapper lp = ReflectionUtil.getValueFromField(clazz, LogWrapper.class, JMod.FINAL, JMod.PUBLIC, JMod.STATIC);
        if (lp != null) {
            lp.setEnabled(status);
            NVGenericMap ret = new NVGenericMap();

            ret.add("class", clazz.getName());
            ret.add(new NVBoolean("logger_stat", lp.isEnabled()));
            return ret;
        }
        throw new IllegalArgumentException("LogWrapper not fount");


    }
}
