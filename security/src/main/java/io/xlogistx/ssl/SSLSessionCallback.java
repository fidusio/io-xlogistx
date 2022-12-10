package io.xlogistx.ssl;




import io.xlogistx.common.net.BaseSessionCallback;
import java.io.OutputStream;

public abstract class SSLSessionCallback extends BaseSessionCallback<SSLSessionConfig>
{

    public final OutputStream get()
    {
        return getConfig().sslOutputStream;
    }
}
