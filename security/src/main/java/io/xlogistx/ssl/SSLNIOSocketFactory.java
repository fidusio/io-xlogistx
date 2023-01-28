package io.xlogistx.ssl;


import org.zoxweb.server.net.BaseSessionCallback;
import org.zoxweb.server.net.ProtocolFactoryBase;
import org.zoxweb.server.security.SSLContextInfo;
import org.zoxweb.shared.data.ConfigDAO;
import org.zoxweb.shared.net.InetSocketAddressDAO;
import org.zoxweb.shared.util.InstanceCreator;

public class SSLNIOSocketFactory
        extends ProtocolFactoryBase<SSLNIOSocket>
{

    private InetSocketAddressDAO remoteAddress;
    private SSLContextInfo sslContext;
    private Class<? extends BaseSessionCallback> scClass;
    private InstanceCreator<SSLSessionCallback> instanceCreator;

    public SSLNIOSocketFactory()
    {
        complexSetup = true;
    }
    public SSLNIOSocketFactory(SSLContextInfo sslContext, InstanceCreator<SSLSessionCallback> instanceCreator)
    {
        this();
        this.sslContext = sslContext;
        this.instanceCreator = instanceCreator;
    }

    public SSLNIOSocketFactory(SSLContextInfo sslContext,  Class<? extends BaseSessionCallback> scClass)
    {
        this();
        this.sslContext = sslContext;
        this.scClass = scClass;
    }


    public SSLNIOSocketFactory(SSLContextInfo sslContext, InetSocketAddressDAO ra)
    {
        this();
        this.sslContext = sslContext;
        remoteAddress = ra;
    }

    public SSLContextInfo getSSLContext()
    {
        return sslContext;
    }


    @Override
    public SSLNIOSocket newInstance()
    {
        SSLSessionCallback sc = null;
        try
        {
            if(instanceCreator != null)
            {
                sc = instanceCreator.newInstance();;
            }
            else if(scClass != null)
                sc = (SSLSessionCallback) scClass.getDeclaredConstructor().newInstance();
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
        sslContext = (SSLContextInfo) ((ConfigDAO)getProperties().getValue("ssl_engine")).attachment();
        try
        {
            if(getProperties().getValue("session_callback") != null)
            {
                scClass = (Class<SSLSessionCallback>) Class.forName(getProperties().getValue("session_callback"));
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


//    @Override
//    public NIOChannelCleaner getNIOChannelCleaner() {
//        return NIOChannelCleaner.DEFAULT;
//    }

}