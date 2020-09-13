package io.xlogistx.common.cron;

public interface CronScheduler
{
    boolean schedule(String cronSchedule, Runnable runnable);
}
