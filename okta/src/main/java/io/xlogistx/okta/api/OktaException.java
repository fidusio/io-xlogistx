package io.xlogistx.okta.api;



import org.zoxweb.shared.util.*;

import java.io.IOException;



public class OktaException
extends IOException
implements GetNVProperties
{


    private transient NVGenericMap nvgm;
    public OktaException(int status, NVGenericMap nvgm)
    {
        SharedUtil.checkIfNulls("NVGenericMap null", nvgm);
        this.nvgm = nvgm;
        nvgm.setName(OktaException.class.getSimpleName());
        setStatus(status);
    }

    public int getStatus()
    {
        return nvgm.getValue("status");
    }

    OktaException setStatus(int status)
    {
        nvgm.add(new NVInt("status", status));
        return this;
    }


    public String getErrorCode()
    {
        return nvgm.getValue("errorCode");
    }

    public String getErrorSummary()
    {
        return nvgm.getValue("errorSummary");
    }

    public String getErrorLink()
    {
        return nvgm.getValue("errorLink");
    }

    public String getErrorId()
    {
        return nvgm.getValue("errorId");
    }

    public NVPairList getErrorCauses()
    {
        return (NVPairList) nvgm.get("errorCauses");
    }


    @Override
    public NVGenericMap getProperties() {
        return nvgm;
    }

    @Override
    public String toString() {
        return  ""+nvgm;

    }
}
