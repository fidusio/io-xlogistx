package io.xlogistx.common.cron;

import org.zoxweb.shared.data.SetNameDescriptionDAO;
import org.zoxweb.shared.util.*;

import java.util.Date;

public class CronConfig
    extends SetNameDescriptionDAO
{
    public enum Param
            implements GetNVConfig
    {
        SCHEDULES(NVConfigManager.createNVConfigEntity("schedules", "Cron Schedules", "Schedules", false, true, CronSchedulerConfig.NVC_CRON_SCHEDULER_CONFIG, NVConfigEntity.ArrayType.LIST)),
        SETUP_DELAY(NVConfigManager.createNVConfig("setup_delay", "Setup delay in millis", "SetupDelay", false, true, Date.class)),
        API_ENDPOINT(NVConfigManager.createNVConfig("api_endpoint", "API Endpoint Service", "APIEndPoint", false, true, String.class)),
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



    /**
     * This NVConfigEntity type constant is set to an instantiation of a NVConfigEntityLocal object based on DataContentDAO.
     */
    public static final NVConfigEntity NVC_CRON_CONFIG = new NVConfigEntityLocal("cron_config",
            null,
            "CronConfig",
            true,
            false,
            false,
            false,
            CronConfig.class,
            SharedUtil.extractNVConfigs(Param.values()),
            null,
            false,
            SetNameDescriptionDAO.NVC_NAME_DESCRIPTION_DAO);

    public CronConfig()
    {
        super(NVC_CRON_CONFIG);
    }


    public CronSchedulerConfig[] getConfigs()
    {
       ArrayValues<NVEntity> av = (ArrayValues<NVEntity>) lookup(Param.SCHEDULES);
       return (CronSchedulerConfig[]) av.values(new CronSchedulerConfig[av.size()]);
    }

    public long getSetupDelay()
    {
        return lookupValue(Param.SETUP_DELAY);
    }

    public void setSetupDelay(long delay)
    {
        setValue(Param.SETUP_DELAY, delay);
    }

    public String getAPIEndpoint()
    {
        return lookupValue(Param.API_ENDPOINT);
    }

    public void getAPIEndpoint(String apiEndpoint)
    {
        setValue(Param.API_ENDPOINT, apiEndpoint);
    }
}
