package io.xlogistx.okta.api;

import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.util.GSONUtil;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class OktaErrorCode
{

    private  static Map<String, OktaErrorCode> CODES;
    private static final Lock LOCK = new ReentrantLock();

    public static Map<String, OktaErrorCode> getErrorMap()
    {
        if (CODES == null)
        {
            LOCK.lock();
            try
            {
                if(CODES == null)
                {
                    OktaErrorCode[] codes = GSONUtil.fromJSONDefault(IOUtil.inputStreamToString(OktaErrorCode.class.getClassLoader().getResourceAsStream("OktaErrorList.json"), true), OktaErrorCode[].class);
                    if(codes != null && codes.length > 0)
                    {
                        CODES = new LinkedHashMap<>();
                        for(OktaErrorCode oec : codes)
                            CODES.put(oec.getCodeId(), oec);
                    }
                }

            }
            catch (Exception e)
            {
                e.printStackTrace();
            }
            finally
            {
                LOCK.unlock();
            }
        }

        return CODES;
    }

    private  String codeId;
    private int httpStatus;
    private String description;

    public String getCodeId() {
        return codeId;
    }

    public OktaErrorCode setCodeId(String codeId) {
        this.codeId = codeId;
        return this;
    }

    public int getHttpStatus() {
        return httpStatus;
    }

    public OktaErrorCode setHttpStatus(int httpStatus) {
        this.httpStatus = httpStatus;
        return this;
    }

    public String getDescription() {
        return description;
    }

    public OktaErrorCode setDescription(String description) {
        this.description = description;
        return this;
    }

    @Override
    public String toString() {
        return "OktaErrorCode{" +
                "codeId='" + codeId + '\'' +
                ", httpStatus=" + httpStatus +
                ", description='" + description + '\'' +
                '}';
    }
}
