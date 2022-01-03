package io.xlogistx.common.net;

import org.zoxweb.server.net.NIOChannelCleaner;
import org.zoxweb.server.net.ProtocolSessionFactoryBase;

public class NIOPlainSocketFactory
        extends ProtocolSessionFactoryBase<NIOPlainSocket>
{

    private Class<? extends PlainSessionCallback> cbClass;

    public NIOPlainSocketFactory()
    {

    }


    public NIOPlainSocketFactory(Class<? extends PlainSessionCallback> cbClass)
    {
        this.cbClass = cbClass;
    }



    @Override
    public NIOPlainSocket newInstance()
    {
        PlainSessionCallback sc = null;
        try
        {
            if(cbClass != null)
                sc = cbClass.getDeclaredConstructor().newInstance();
        }
        catch(Exception e)
        {
            e.printStackTrace();
        }
        return new NIOPlainSocket(sc);
    }

    @Override
    public String getName() {
        // TODO Auto-generated method stub
        return "NIOPlainSocketFactory";
    }
    public void init()
    {
        try
        {
            if(getProperties().getValue("session_callback") != null)
            {
                cbClass = (Class<PlainSessionCallback>) Class.forName(getProperties().getValue("session_callback"));
            }
        }
        catch(Exception e)
        {
            e.printStackTrace();
        }

    }

    @Override
    public NIOChannelCleaner getNIOChannelCleaner() {
        return NIOChannelCleaner.DEFAULT;
    }

}