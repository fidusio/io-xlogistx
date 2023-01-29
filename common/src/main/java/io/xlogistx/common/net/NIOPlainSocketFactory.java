package io.xlogistx.common.net;


import org.zoxweb.server.net.BaseSessionCallback;
import org.zoxweb.server.net.ProtocolFactoryBase;
import org.zoxweb.shared.util.InstanceCreator;

public class NIOPlainSocketFactory
        extends ProtocolFactoryBase<NIOPlainSocket>
{

    private  Class<? extends BaseSessionCallback> cbClass;
    private InstanceCreator<PlainSessionCallback> instanceCreator;

    public NIOPlainSocketFactory(){}


    public NIOPlainSocketFactory(Class<? extends BaseSessionCallback> cbClass)
    {
        this.cbClass = cbClass;

    }
    public NIOPlainSocketFactory(InstanceCreator<PlainSessionCallback> instanceCreator)
    {
        this.instanceCreator = instanceCreator;
    }



    @Override
    public NIOPlainSocket newInstance()
    {
        PlainSessionCallback sc = null;
        try
        {
            if (instanceCreator != null)
                sc = instanceCreator.newInstance();
            else if(cbClass != null)
                sc = (PlainSessionCallback) cbClass.getDeclaredConstructor().newInstance();
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

//    @Override
//    public NIOChannelCleaner getNIOChannelCleaner() {
//        return NIOChannelCleaner.DEFAULT;
//    }

}