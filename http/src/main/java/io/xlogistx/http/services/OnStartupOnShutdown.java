package io.xlogistx.http.services;

import io.xlogistx.common.data.PropertyContainer;
import io.xlogistx.opsec.OPSecUtil;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.shared.annotation.OnShutdown;
import org.zoxweb.shared.annotation.OnStartup;
import org.zoxweb.shared.annotation.PostStartup;
import org.zoxweb.shared.util.NVGenericMap;

public class OnStartupOnShutdown
        extends PropertyContainer<NVGenericMap> {
    public static final LogWrapper log = new LogWrapper(OnStartupOnShutdown.class).setEnabled(true);
    public static final OnStartupOnShutdown SINGLETON = new OnStartupOnShutdown();


    private OnStartupOnShutdown() {
    }

    @OnStartup
    public void onStartup() {
        log.getLogger().info("OnStartup: " + this);
        OPSecUtil.singleton();
    }

    @PostStartup
    public void afterStartup() {
        log.getLogger().info("PostStartup: " + this);
    }

    @OnShutdown
    public void onShutdown() {
        log.getLogger().info("OnShutdown: " + this);
    }


    @Override
    protected void refreshProperties() {
        log.getLogger().info("Properties to set");
    }
}
