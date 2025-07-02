package io.xlogistx.http;

import io.xlogistx.common.data.MethodContainer;
import org.zoxweb.shared.util.ResourceManager;

import java.util.concurrent.atomic.AtomicBoolean;

public class EndpointsUtil {
    public static final EndpointsUtil SINGLETON = new EndpointsUtil();
    private final AtomicBoolean startCallStatus = new AtomicBoolean(false);
    private final AtomicBoolean shutdownCallStatus = new AtomicBoolean(false);
    private EndpointsUtil(){}


    /**
     *
     * @return null or value
     * @param <V> return type
     * @exception SecurityException in case of error
     */
    public <V> V startup()
    {
        if(!startCallStatus.getAndSet(true))
        {
            MethodContainer shutdown = ResourceManager.SINGLETON.lookup("on-startup");
            if (shutdown != null) {
                try {
                    return shutdown.invoke();
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
        if(!shutdownCallStatus.getAndSet(true))
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
