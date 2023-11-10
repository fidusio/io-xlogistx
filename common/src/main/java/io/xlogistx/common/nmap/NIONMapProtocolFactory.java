package io.xlogistx.common.nmap;

import org.zoxweb.server.net.ProtocolFactoryBase;

public class NIONMapProtocolFactory extends ProtocolFactoryBase<NIONMapHandler> {
    @Override
    public void init() {

    }

    @Override
    public String getName() {
        return null;
    }

    @Override
    public NIONMapHandler newInstance() {
        return new NIONMapHandler();
    }
}
