package io.xlogistx.common.dns;

import org.zoxweb.server.net.ProtocolFactoryBase;

public class DNSNIOFactory
    extends ProtocolFactoryBase<DNSNIOProtocol>
{



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
        return "DNSNIOFactory";
    }

    /**
     * Create a new instance based on the type T
     *
     * @return new instance of T
     */
    @Override
    public DNSNIOProtocol newInstance() {
        return DNSNIOProtocol.SINGLETON;
    }
}
