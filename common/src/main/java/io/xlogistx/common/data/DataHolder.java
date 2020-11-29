package io.xlogistx.common.data;

import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.shared.util.NVEntity;
import org.zoxweb.shared.util.NVGenericMap;
import org.zoxweb.shared.util.SharedBase64;

public class DataHolder
{
    private final NVEntity nve;
    private final NVGenericMap nvgm;

    private DataHolder(NVEntity nve)
    {
        this.nve = nve;
        this.nvgm = null;
    }

    private DataHolder(NVGenericMap nvgm)
    {
        this.nve = null;
        this.nvgm = nvgm;
    }

    public NVGenericMap getProperties()
    {
        return nvgm;
    }

    public <V extends NVEntity> V getNVEntity()
    {
        return (V) nve;
    }

    public static DataHolder parseJSON(String json)
    {
        try
        {
            // try as NV Entity
            NVEntity nve = GSONUtil.fromJSON(json);
            return new DataHolder(nve);
        }
        catch (Exception e)
        {

        }
        return new DataHolder(GSONUtil.fromJSONGenericMap(json, null, SharedBase64.Base64Type.URL));
    }
}
