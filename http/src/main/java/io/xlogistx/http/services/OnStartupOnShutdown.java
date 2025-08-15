package io.xlogistx.http.services;

import io.xlogistx.common.data.PropertyContainer;
import io.xlogistx.opsec.OPSecUtil;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.shared.annotation.OnShutdown;
import org.zoxweb.shared.annotation.OnStartup;
import org.zoxweb.shared.util.NVGenericMap;

public class OnStartupOnShutdown
        extends PropertyContainer<NVGenericMap> {
    public static final LogWrapper log = new LogWrapper(OnStartupOnShutdown.class).setEnabled(true);

    @OnStartup
    public void onStartup() {
        log.getLogger().info("OnStartup");
        OPSecUtil.SINGLETON.loadProviders();
    }

    @OnShutdown
    public void onShutdown() {
        log.getLogger().info("OnShutdown");
    }


    @Override
    protected void refreshProperties() {

    }
}
