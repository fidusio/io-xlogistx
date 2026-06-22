package io.xlogistx.http.services;


import io.xlogistx.common.http.EndPointMeta;
import io.xlogistx.common.http.HTTPProtocolHandler;
import io.xlogistx.http.EndpointsUtil;
import io.xlogistx.opsec.ssl.IdentityStore;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.server.util.JMod;
import org.zoxweb.server.util.ReflectionUtil;
import org.zoxweb.shared.annotation.EndPointProp;
import org.zoxweb.shared.annotation.ParamProp;
import org.zoxweb.shared.annotation.SecurityProp;
import org.zoxweb.shared.data.SimpleMessage;
import org.zoxweb.shared.http.HTTPMethod;
import org.zoxweb.shared.http.HTTPStatusCode;
import org.zoxweb.shared.security.SecConst;
import org.zoxweb.shared.util.Const;
import org.zoxweb.shared.util.NVGenericMap;
import org.zoxweb.shared.util.ResourceManager;


public class AppCommand {

    public static final LogWrapper log = new LogWrapper(AppCommand.class);

    @EndPointProp(methods = {HTTPMethod.GET}, name = "app-shutdown", uris = "/app/shutdown")
    @SecurityProp(authentications = {SecConst.AuthenticationType.ALL}, permissions = "app:shutdown")
    public SimpleMessage appShutdown() {

        EndpointsUtil.SINGLETON.shutdown();

        long delay = Const.TimeInMillis.SECOND.MILLIS * 5;
        TaskUtil.defaultTaskScheduler().queue(delay, () -> System.exit(0));
        return new SimpleMessage("App will shutdown in " + Const.TimeInMillis.toString(delay), HTTPStatusCode.OK.CODE);
    }


    @EndPointProp(methods = {HTTPMethod.GET}, name = "class-logger", uris = "/app/logger/{className}/{status}")
    @SecurityProp(authentications = {SecConst.AuthenticationType.ALL}, permissions = "app:logger:read, app:logger:write")
    public NVGenericMap loggerAccess(@ParamProp(name = "className") String className, @ParamProp(name = "status") boolean status) throws ClassNotFoundException, IllegalAccessException {
        Class<?> clazz = Class.forName(className);
        LogWrapper lp = ReflectionUtil.getValueFromField(clazz, LogWrapper.class, JMod.FINAL, JMod.PUBLIC, JMod.STATIC);
        if (lp != null) {
            lp.setEnabled(status);
            NVGenericMap ret = new NVGenericMap();

            ret.add("class", clazz.getName());
            ret.add("logger_stat", lp.isEnabled() ? "enabled" : "disabled");
            return ret;
        }
        throw new IllegalArgumentException("LogWrapper not fount");

    }

    @EndPointProp(methods = {HTTPMethod.GET}, name = "expose-app-api", uris = "/app/api/")
    @SecurityProp(authentications = {SecConst.AuthenticationType.ALL}, permissions = "app:apis:read")
    public NVGenericMap exposeAppAPI() throws IllegalAccessException {
        HTTPProtocolHandler hph = EndpointsUtil.SINGLETON.getProtocolHandler();
        EndPointMeta[] allUris = hph.getEndPointsManager().allEndPointMetas();
        NVGenericMap endPointsMeta = new NVGenericMap("api-endpoints");
        for (EndPointMeta meta : allUris) {
            endPointsMeta.add(meta.httpEndPoint.toProperties(true));
        }
        return endPointsMeta;
    }


    @EndPointProp(methods = {HTTPMethod.GET}, name = "certs-reload", uris = "/app/certs-reload")
    @SecurityProp(authentications = {SecConst.AuthenticationType.ALL}, permissions = "app:certs:reload")
    public HTTPStatusCode certsReload() {
        IdentityStore store = ResourceManager.lookupResource(IdentityStore.REC_NAME);
        log.getLogger().info("Certificate reload store found: " + (store != null));
        if (store != null) {
            try {
                store.reload();
                return HTTPStatusCode.OK;

            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return HTTPStatusCode.NOT_FOUND;
    }

}
