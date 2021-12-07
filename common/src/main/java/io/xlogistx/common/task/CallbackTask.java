package io.xlogistx.common.task;

public interface CallbackTask<P>
{
    void exception(Exception e);
    void callback(P param);
}
