package io.xlogistx.http;

import io.xlogistx.common.data.MethodContainer;
import org.zoxweb.shared.util.ResourceManager;

import java.util.concurrent.atomic.AtomicBoolean;

public class EndpointsUtil {
    public static final EndpointsUtil SINGLETON = new EndpointsUtil();
    private final AtomicBoolean onStartupCallStatus = new AtomicBoolean(false);
    private final AtomicBoolean postStartupCallStatus = new AtomicBoolean(false);
    private final AtomicBoolean onShutdownCallStatus = new AtomicBoolean(false);
    private EndpointsUtil(){}


    /**
     *
     * @return null or value
     * @param <V> return type
     * @exception SecurityException in case of error
     */
    public <V> V startup()
    {
        if(!onStartupCallStatus.getAndSet(true))
        {
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
    public <V> V postStartup()
    {
        if(!postStartupCallStatus.getAndSet(true))
        {
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

    public <V> V shutdown()
    {
        if(!onShutdownCallStatus.getAndSet(true))
        {
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
}
