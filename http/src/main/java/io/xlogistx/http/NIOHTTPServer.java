package io.xlogistx.http;

import io.xlogistx.common.data.MethodHolder;
import io.xlogistx.common.http.EndPointsManager;
import io.xlogistx.common.http.HTTPServerMapper;
import org.zoxweb.server.net.NIOSocket;
import org.zoxweb.shared.http.HTTPEndPoint;
import org.zoxweb.shared.http.HTTPServerConfig;
import org.zoxweb.shared.util.DaemonController;
import org.zoxweb.shared.util.SharedUtil;

import java.io.IOException;

public class NIOHTTPServer
        implements DaemonController,
        HTTPServerMapper
{
    private final HTTPServerConfig config;
    private final NIOSocket nioSocket;

    public NIOHTTPServer(HTTPServerConfig config, NIOSocket nioSocket)
    {
        SharedUtil.checkIfNulls("HTTPServerConfig null", config);
        this.config = config;
        this.nioSocket = nioSocket;
    }

    public NIOSocket getNIOSocket()
    {
        return nioSocket;
    }

    public HTTPServerConfig getConfig()
    {
        return config;
    }

    @Override
    public boolean isInstanceNative(Object beanInstance) {
        return false;
    }

    @Override
    public void mapHEP(EndPointsManager endPointsManager, HTTPEndPoint hep, MethodHolder mh, Object beanInstance) {

    }

    @Override
    public boolean isClosed() {
        return false;
    }

    @Override
    public void close() throws IOException {

    }
}