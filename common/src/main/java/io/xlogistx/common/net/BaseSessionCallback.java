package io.xlogistx.common.net;

import org.zoxweb.server.net.SessionCallback;

import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.logging.Logger;

public abstract class BaseSessionCallback<C> extends SessionCallback<C, ByteBuffer, OutputStream>
{
    private ChannelOutputStream cos = null;
    protected  static final transient Logger log = Logger.getLogger(BaseSessionCallback.class.getName());



    @Override
    public void exception(Exception e) {
        // exception handling

        log.info( e + "");
    }

}
