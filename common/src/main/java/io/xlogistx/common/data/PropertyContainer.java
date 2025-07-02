package io.xlogistx.common.data;

import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.shared.util.NVGenericMap;
import org.zoxweb.shared.util.SetNVProperties;

import java.util.concurrent.atomic.AtomicLong;

public abstract class PropertyContainer<T>
implements SetNVProperties
{
    public final static LogWrapper log = new LogWrapper(PropertyContainer.class).setEnabled(false);
    private final static AtomicLong idCounter = new AtomicLong(0);
    private final long id = idCounter.incrementAndGet();
    private volatile T externalTask;

    private NVGenericMap nvgm;

    @Override
    public void setProperties(NVGenericMap nvgm) {
        this.nvgm = nvgm;
        refreshProperties();

    }

    @Override
    public NVGenericMap getProperties() {
        return nvgm;

    }

    public long getID()
    {
        return id;
    }

    protected abstract void refreshProperties();


    public void setExternalTask(T externalTask)
    {
        this.externalTask = externalTask;
    }

    public T getExternalTask()
    {
        return externalTask;
    }

}
