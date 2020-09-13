package io.xlogistx.common.task;

import org.zoxweb.shared.util.NVGenericMap;
import org.zoxweb.shared.util.SetNVProperties;

public abstract class RunnableProperties
    implements Runnable, SetNVProperties
{

    private NVGenericMap properties;
    public RunnableProperties()
    {
        this(null);
    }


    public RunnableProperties(NVGenericMap nvgm)
    {
        setProperties(nvgm);
    }

    public NVGenericMap getProperties()
    {
        return properties;
    }

    public void setProperties(NVGenericMap nvgm)
    {
        this.properties = nvgm;
    }
}
