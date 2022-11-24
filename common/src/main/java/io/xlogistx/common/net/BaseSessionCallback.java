package io.xlogistx.common.net;

import org.zoxweb.server.net.SessionCallback;

import java.io.OutputStream;
import java.nio.ByteBuffer;


public abstract class BaseSessionCallback<CF>
        extends SessionCallback<CF, ByteBuffer, OutputStream>
{
}
