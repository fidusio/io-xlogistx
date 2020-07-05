package io.xlogistx.common.data;

import org.zoxweb.shared.util.NVGenericMap;
import org.zoxweb.shared.util.SetNVProperties;

public abstract class PropertyHolder
implements SetNVProperties
{
    private NVGenericMap nvgm;

    @Override
    public void setProperties(NVGenericMap nvgm) {
        this.nvgm = nvgm;
        propertiesUpdated();

    }

    @Override
    public NVGenericMap getProperties() {
        return nvgm;

    }

    protected abstract void propertiesUpdated();
}
