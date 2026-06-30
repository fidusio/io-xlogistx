package io.xlogistx.http;

import io.xlogistx.common.data.MethodContainer;
import io.xlogistx.common.http.HTTPProtocolHandler;
import io.xlogistx.shiro.ShiroUtil;
import org.zoxweb.server.util.DateUtil;
import org.zoxweb.shared.http.*;
import org.zoxweb.shared.util.ResourceManager;

import java.util.Date;
import java.util.concurrent.atomic.AtomicBoolean;

public class EndpointsUtil {
    public static final EndpointsUtil SINGLETON = new EndpointsUtil();
    private final AtomicBoolean onStartupCallStatus = new AtomicBoolean(false);
    private final AtomicBoolean postStartupCallStatus = new AtomicBoolean(false);
    private final AtomicBoolean onShutdownCallStatus = new AtomicBoolean(false);
    ;

    private EndpointsUtil() {
    }


    /**
     *
     * @return null or value
     * @param <V> return type
     * @exception SecurityException in case of error
     */
    public <V> V startup() {
        if (!onStartupCallStatus.getAndSet(true)) {
            MethodContainer onStartup = ResourceManager.SINGLETON.lookup("on-startup");
            if (onStartup != null) {
                try {
                    return onStartup.invoke();
                } catch (Exception e) {
                    e.printStackTrace();
                    throw new SecurityException(e);
                }
            }
        }

        return null;
    }


    /**
     *
     * @return null or value
     * @param <V> return type
     * @exception SecurityException in case of error
     */
    public <V> V postStartup() {
        if (!postStartupCallStatus.getAndSet(true)) {
            MethodContainer postStartup = ResourceManager.SINGLETON.lookup("post-startup");
            if (postStartup != null) {
                try {
                    return postStartup.invoke();
                } catch (Exception e) {
                    e.printStackTrace();
                    throw new SecurityException(e);
                }
            }
        }

        return null;
    }

    public <V> V shutdown() {
        if (!onShutdownCallStatus.getAndSet(true)) {
            MethodContainer shutdown = ResourceManager.SINGLETON.lookup("on-shutdown");
            if (shutdown != null) {
                try {
                    return shutdown.invoke();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }

        return null;
    }

    public HTTPProtocolHandler getProtocolHandler() {
        return ShiroUtil.getFromThreadContext(HTTPProtocolHandler.SESSION_CONTEXT);
    }

    public HTTPMessageConfigInterface redirect302(String redirectUrl) {
        return redirectConfig(HTTPStatusCode.FOUND, redirectUrl);
    }


    public HTTPMessageConfigInterface redirectConfig(HTTPStatusCode status, String redirectURL) {
        HTTPMessageConfigInterface ret = new HTTPMessageConfig();
        ret.setHTTPStatusCode(status);
        ret.getHeaders().build(HTTPHeader.LOCATION, redirectURL)
                .build(HTTPHeader.SERVER, NIOHTTPServer.VERSION.toCanonicalID())
                .build(HTTPHeader.DATE, DateUtil.REDIRECT_FORMAT.format(new Date()))
                .build(HTTPHeader.CACHE_CONTROL, "no-store")
                .build(HTTPConst.CommonHeader.CONNECTION_KEEP_ALIVE);
        ret.setContentLength(0);
        ret.setContentType("text/html; charset=utf-8");

        return ret;
    }
}
