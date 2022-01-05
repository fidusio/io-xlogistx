package io.xlogistx.ssl;




import io.xlogistx.common.net.BaseSessionCallback;
import java.io.OutputStream;

public abstract class SSLSessionCallback extends BaseSessionCallback<SSLSessionConfig>
{

    final public OutputStream get()
    {
        return getConfig().sslos;
    }
}
