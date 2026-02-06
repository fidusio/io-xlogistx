package io.xlogistx.common.data;

import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.shared.util.NVGMProperties;
import org.zoxweb.shared.util.NVGenericMap;

import java.util.concurrent.atomic.AtomicLong;

public abstract class PropertyContainer<T>
        extends NVGMProperties {
    public final static LogWrapper log = new LogWrapper(PropertyContainer.class).setEnabled(false);
    private final static AtomicLong idCounter = new AtomicLong(0);
    private final long id = idCounter.incrementAndGet();
    private volatile T externalTask;

    protected PropertyContainer() {
        super(false);
    }

    @Override
    public void setProperties(NVGenericMap nvgm) {
        super.setProperties(nvgm);
        refreshProperties();

    }

    public long getID() {
        return id;
    }

    protected abstract void refreshProperties();


    public void setExternalTask(T externalTask) {
        this.externalTask = externalTask;
    }

    public T getExternalTask() {
        return externalTask;
    }

}
