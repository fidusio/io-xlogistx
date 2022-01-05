package io.xlogistx.ssl;




import io.xlogistx.common.net.BaseSessionCallback;

import java.io.OutputStream;
public abstract class SSLSessionCallback extends BaseSessionCallback<SSLSessionConfig>
{
    @Override
    public void exception(Exception e) {
        // exception handling

        log.info( e + "");
    }
    final public OutputStream get()
    {
        return getConfig().sslos;
    }
}
