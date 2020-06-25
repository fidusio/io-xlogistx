package io.xlogistx.common;

import org.zoxweb.shared.data.PropertyDAO;

import org.zoxweb.shared.http.HTTPMessageConfig;
import org.zoxweb.shared.http.HTTPMessageConfigInterface;
import org.zoxweb.shared.http.HTTPMethod;
import org.zoxweb.shared.util.*;

import java.util.Date;

public class TaskConfig
    extends PropertyDAO
{


    public enum Param
        implements GetNVConfig
    {
        HTTP_CONFIG(NVConfigManager.createNVConfigEntity("http_config", "HTTPConfig", "HTTPConfig", false, true, HTTPMessageConfig.class, NVConfigEntity.ArrayType.NOT_ARRAY)),
        INIT_DELAY(NVConfigManager.createNVConfig("init_delay", "InitialDelay", "InitDelay", false, true, Date.class)),
        RETRIES(NVConfigManager.createNVConfig("retries", "Retries", "Retries", false, true, int.class)),
        RETRY_DELAY(NVConfigManager.createNVConfig("retry_delay", "Retry delay in case of failure", "RetryDelay", false, true, Date.class)),
        REPEATS(NVConfigManager.createNVConfig("repeats", "Repeats", "Repeats", false, true, int.class)),
        REPEAT_DELAY(NVConfigManager.createNVConfig("repeat_delay", "RepeatDelay", "RepeatDelay", false, true, Date.class))
        ;

        private final NVConfig nvc;

        Param(NVConfig nvc)
        {
            this.nvc = nvc;
        }

        public NVConfig getNVConfig()
        {
            return nvc;
        }
    }

    public static final NVConfigEntity NVC_TASK_CONFIG = new NVConfigEntityLocal("TASK_CONFIG",
            null,
            "TaskConfig",
            true,
            false,
            false,
            false,
            TaskConfig.class,
            SharedUtil.extractNVConfigs(Param.values()),
            null,
            false,
            PropertyDAO.NVC_PROPERTY_DAO);
    public TaskConfig()
    {
        super(NVC_TASK_CONFIG);
    }

    public HTTPMessageConfigInterface getHTTPConfig()
    {
        HTTPMessageConfigInterface ret =  lookupValue(Param.HTTP_CONFIG);
        if(ret != null)
        {
            if (ret.getMethod() == null)
            {
                ret.setMethod(HTTPMethod.GET);
            }
        }

        return ret;
    }

    public long getInitDelay()
    {
        return lookupValue(Param.INIT_DELAY);
    }
    public int getRetries()
    {
        return lookupValue(Param.RETRIES);
    }

    public long getRetryDelay()
    {
        return lookupValue(Param.RETRY_DELAY);
    }

    public int getRepeats()
    {
        return lookupValue(Param.REPEATS);
    }

    public long getRepeatDelay()
    {
        return lookupValue(Param.REPEAT_DELAY);
    }


}
