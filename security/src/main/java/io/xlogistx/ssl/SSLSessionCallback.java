package io.xlogistx.ssl;




import org.zoxweb.server.net.SessionCallback;


import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.logging.Logger;

public abstract class SSLSessionCallback extends SessionCallback<SSLSessionConfig, ByteBuffer, OutputStream>
{
    protected  static final transient Logger log = Logger.getLogger(SSLSessionCallback.class.getName());



    @Override
    public void exception(Exception e) {
        // exception handling

        log.info( e + "");
    }
    final public OutputStream get()
    {
        return getConfig().sslos;
    }
//    @Override
//    public void accept(ByteBuffer inBuffer)
//    {
//        // data handling
//        if(inBuffer != null)
//        {
//            try{
//
//                //ByteBufferUtil.write(buffer, ubaos, true);
//                //log.info("incoming data\n" + SharedStringUtil.toString(ubaos.getInternalBuffer(), 0, ubaos.size()));
//
//                ByteBufferUtil.write(dummyData, config.outAppData);
//
//                //log.info("data to be sent" + bb + "\n" + SharedStringUtil.toString(dummyData.getInternalBuffer(), 0, dummyData.size()));
//                get().write(config.outAppData);
//
//            }
//            catch(Exception e)
//            {
//                //e.printStackTrace();
//                log.info(""+e);
//                // we should close
//
//            }
//            finally {
//                IOUtil.close(get());
//            }
//
//        }
//    }
}
