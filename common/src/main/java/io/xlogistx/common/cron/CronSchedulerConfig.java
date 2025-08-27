package io.xlogistx.common.cron;

import org.zoxweb.shared.data.PropertyDAO;
import org.zoxweb.shared.util.*;


public class CronSchedulerConfig
        extends PropertyDAO {
    public enum Param
            implements GetNVConfig {
        BEAN(NVConfigManager.createNVConfig("bean", "Bean class name", "Bean", false, true, String.class)),
        SCHEDULE(NVConfigManager.createNVConfig("schedule", "cron syntax", "Cron", false, true, String.class)),
        ;
        private final NVConfig nvc;

        Param(NVConfig nvc) {
            this.nvc = nvc;
        }

        public NVConfig getNVConfig() {
            return nvc;
        }
    }


    /**
     * This NVConfigEntity type constant is set to an instantiation of a NVConfigEntityLocal object based on DataContentDAO.
     */
    public static final NVConfigEntity NVC_CRON_SCHEDULER_CONFIG = new NVConfigEntityPortable("cron_scheduler_config",
            null,
            "CronSchedulerConfig",
            true,
            false,
            false,
            false,
            CronSchedulerConfig.class,
            SharedUtil.extractNVConfigs(Param.values()),
            null,
            false,
            PropertyDAO.NVC_PROPERTY_DAO);


    public CronSchedulerConfig() {
        super(NVC_CRON_SCHEDULER_CONFIG);
    }


    public String getSchedule() {
        return lookupValue(Param.SCHEDULE);
    }

    public void setSchedule(String schedule) {
        setValue(Param.SCHEDULE, schedule);
    }

    public String getBean() {
        return lookupValue(Param.BEAN);
    }

    public void setBean(String bean) {
        setValue(Param.BEAN, bean);
    }


}
