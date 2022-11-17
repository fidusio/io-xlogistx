package io.xlogistx.okta.api;

import org.zoxweb.shared.util.NVGenericMap;

import java.io.IOException;
import java.util.Arrays;


public class OktaException
extends IOException {


    private int status;
    private String errorCode;
    private String errorSummary;
    private String errorLink;
    private String errorId;
    private  NVGenericMap[] errorCauses;
    public OktaException()
    {
    }

    public int getStatus()
    {
        return status;
    }

    OktaException setStatus(int status)
    {
        this.status = status;
        return this;
    }


    public String getErrorCode()
    {
        return errorCode;
    }

    public String getErrorSummary()
    {
        return errorSummary;
    }

    public String getErrorLink()
    {
        return errorLink;
    }

    public String getErrorId()
    {
        return errorId;
    }

    public NVGenericMap[] getErrorCauses()
    {
        return errorCauses;
    }


    @Override
    public String toString() {
        return "OktaException{" +
                "status=" + status +
                ", errorCode='" + errorCode + '\'' +
                ", errorSummary='" + errorSummary + '\'' +
                ", errorLink='" + errorLink + '\'' +
                ", errorId='" + errorId + '\'' +
                ", errorCauses=" + Arrays.toString(errorCauses) +
                '}';
    }
}
