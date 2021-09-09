package io.xlogistx.common.ssl;

import org.zoxweb.server.net.NIOChannelCleaner;
import org.zoxweb.server.net.ProtocolSessionFactoryBase;

import org.zoxweb.shared.data.ConfigDAO;
import org.zoxweb.shared.net.InetSocketAddressDAO;

import javax.net.ssl.SSLContext;

public class SSLNIOTunnelFactory
        extends ProtocolSessionFactoryBase<SSLNIOTunnel>
{

    private InetSocketAddressDAO remoteAddress;
    private SSLContext sslContext;

    public SSLNIOTunnelFactory()
    {

    }


    public SSLNIOTunnelFactory(SSLContext sslContext, InetSocketAddressDAO remoteAddress)
    {
        this.remoteAddress = remoteAddress;
        this.sslContext = sslContext;
    }

    public SSLContext getSSLContext()
    {
        return sslContext;
    }
    public void setRemoteAddress(InetSocketAddressDAO rAddress)
    {
        remoteAddress = rAddress;
    }

    public InetSocketAddressDAO getRemoteAddress()
    {
        return remoteAddress;
    }

    @Override
    public SSLNIOTunnel newInstance()
    {
        return new SSLNIOTunnel(sslContext, remoteAddress);
    }

    @Override
    public String getName() {
        // TODO Auto-generated method stub
        return "NIOTunnelFactory";
    }

    public void init()
    {
        setRemoteAddress(new InetSocketAddressDAO(getProperties().getValue("remote_host")));
        sslContext = (SSLContext) ((ConfigDAO)getProperties().getValue("ssl_engine")).attachment();
    }


    @Override
    public NIOChannelCleaner getNIOChannelCleaner() {
        return NIOChannelCleaner.DEFAULT;
    }

}