package io.xlogistx.common.data;

import org.zoxweb.shared.util.NamedDescription;
import org.zoxweb.shared.util.SharedUtil;

public class DataTriggerAfterWait<D>
    extends NamedDescription
{
    private long waitTime;
    private D data;


    public DataTriggerAfterWait(String name, long waitTime)
    {
        super(name);
        setWaitTime(waitTime);
    }

    public DataTriggerAfterWait(Enum<?> name, long waitTime)
    {
        super(SharedUtil.enumName(name));
        setWaitTime(waitTime);
    }

    public DataTriggerAfterWait(String name)
    {
        super(name);
    }

    public DataTriggerAfterWait(Enum<?> name)
    {
        super(SharedUtil.enumName(name));
    }

    public long getWaitTime() {
        return waitTime;
    }

    public void setWaitTime(long waitTime) {
        if(waitTime < 0)
            throw new IllegalStateException("Invalid value " + waitTime + " must be >= 0");
        this.waitTime = waitTime;
    }

    public D getData()
    {
        return data;
    }

    public void setData(D data)
    {
        this.data = data;
    }
}
