package io.xlogistx.ssl;

import org.zoxweb.server.net.NIOChannelCleaner;
import org.zoxweb.server.net.ProtocolSessionFactoryBase;
import org.zoxweb.shared.data.ConfigDAO;
import org.zoxweb.shared.net.InetSocketAddressDAO;

import javax.net.ssl.SSLContext;

public class SSLNIOSocketFactory
        extends ProtocolSessionFactoryBase<SSLNIOSocket>
{

    private InetSocketAddressDAO remoteAddress;
    private SSLContext sslContext;
    private Class<SessionCallback> scClass;

    public SSLNIOSocketFactory()
    {

    }


    public SSLNIOSocketFactory(SSLContext sslContext, InetSocketAddressDAO ra)
    {
        this.sslContext = sslContext;
        remoteAddress = ra;
    }

    public SSLContext getSSLContext()
    {
        return sslContext;
    }


    @Override
    public SSLNIOSocket newInstance()
    {
        SessionCallback sc = null;
        try
        {
            if(scClass != null)
                sc = scClass.getDeclaredConstructor().newInstance();
        }
        catch(Exception e)
        {
            e.printStackTrace();
        }
        return new SSLNIOSocket(sslContext, remoteAddress, sc);
    }

    @Override
    public String getName() {
        // TODO Auto-generated method stub
        return "SSLNIOSocketFactory";
    }

    public void init()
    {
        if(getProperties().getValue("remote_host") != null)
            setRemoteAddress(new InetSocketAddressDAO(getProperties().getValue("remote_host")));
        sslContext = (SSLContext) ((ConfigDAO)getProperties().getValue("ssl_engine")).attachment();
        try
        {
            if(getProperties().getValue("session_callback") != null)
            {
                scClass = (Class<SessionCallback>) Class.forName(getProperties().getValue("session_callback"));
            }
        }
        catch(Exception e)
        {
            e.printStackTrace();
        }

    }

    public void setRemoteAddress(InetSocketAddressDAO rAddress)
    {
        remoteAddress = rAddress;
    }

    public InetSocketAddressDAO getRemoteAddress(){ return remoteAddress; }


    @Override
    public NIOChannelCleaner getNIOChannelCleaner() {
        return NIOChannelCleaner.DEFAULT;
    }

}