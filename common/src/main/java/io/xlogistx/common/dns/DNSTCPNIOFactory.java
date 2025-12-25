package io.xlogistx.common.dns;

import org.zoxweb.server.net.ProtocolFactoryBase;

public class DNSTCPNIOFactory
        extends ProtocolFactoryBase<DNSTCPNIOProtocol> {

    public static final DNSTCPNIOFactory SINGLETON = new DNSTCPNIOFactory();

    private DNSTCPNIOFactory() {
    }

    /**
     * Init the protocol factory
     */
    @Override
    public void init() {

    }

    /**
     * @return the name of the object
     */
    @Override
    public String getName() {
        return "DNSTCPNIOFactory";
    }

    /**
     * Create a new instance based on the type T
     *
     * @return new instance of T
     */
    @Override
    public DNSTCPNIOProtocol newInstance() {
        return new DNSTCPNIOProtocol();
    }
}
