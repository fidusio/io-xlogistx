package io.xlogistx.ssl;

import io.xlogistx.common.task.CallbackTask;


import java.nio.ByteBuffer;
import java.util.logging.Logger;

public abstract class SessionCallback implements CallbackTask<ByteBuffer, SSLOutputStream>
{
    protected  static final transient Logger log = Logger.getLogger(SessionCallback.class.getName());
    protected SSLSessionConfig config;
    final void setConfig(SSLSessionConfig config)
    {
        this.config = config;
    }

    @Override
    public void exception(Exception e) {
        // exception handling

        log.info( e + "");
    }
    final public SSLOutputStream get()
    {
        return config.sslos;
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
