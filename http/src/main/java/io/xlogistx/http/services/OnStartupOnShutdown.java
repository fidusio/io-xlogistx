package io.xlogistx.http.services;

import io.xlogistx.common.data.PropertyHolder;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.shared.annotation.OnShutdown;
import org.zoxweb.shared.annotation.OnStartup;
import org.zoxweb.shared.util.NVGenericMap;

public class OnStartupOnShutdown
    extends PropertyHolder<NVGenericMap>
{
    public static final LogWrapper log = new LogWrapper(OnStartupOnShutdown.class).setEnabled(true);

    @OnStartup
    public void onStartup()
    {
        log.getLogger().info("OnStartup");
    }

    @OnShutdown
    public void onShutdown()
    {
        log.getLogger().info("OnShutdown");
    }


    @Override
    protected void refreshProperties() {

    }
}
