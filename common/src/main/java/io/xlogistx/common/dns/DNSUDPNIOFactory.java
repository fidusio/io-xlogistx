package io.xlogistx.common.dns;

import org.zoxweb.server.net.ProtocolFactoryBase;

public class DNSUDPNIOFactory
        extends ProtocolFactoryBase<DNSUDPNIOProtocol> {

    public static final DNSUDPNIOFactory SINGLETON = new DNSUDPNIOFactory();

    private DNSUDPNIOFactory() {
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
        return "DNSUDPNIOFactory";
    }

    /**
     * Create a new instance based on the type T
     *
     * @return new instance of T
     */
    @Override
    public DNSUDPNIOProtocol newInstance() {
        return new DNSUDPNIOProtocol(getProperties().getValue("executor"));
    }
}
