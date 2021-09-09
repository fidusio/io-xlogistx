package io.xlogistx.common.ssl;


import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.net.SelectorController;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import java.io.Closeable;
import java.nio.ByteBuffer;

import java.nio.channels.SelectableChannel;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Logger;

class SSLSessionConfig
implements AutoCloseable
{
    private static final transient Logger log = Logger.getLogger(SSLSessionConfig.class.getName());
    SSLContext sslContext;
    SSLEngine sslEngine; // the crypto engine
    ByteBuffer inNetData; // encrypted data
    ByteBuffer outNetData; // encrypted data
    ByteBuffer inAppData; // clear text application data
    //ByteBuffer outAppData; // data used during the handshake process
    SelectableChannel sslChannel; // the encrypted channel
    SelectorController selectorController;

    Closeable otherCloseable = null;



    //boolean sslChannelReadState = false;
    private AtomicBoolean isClosed = new AtomicBoolean(false);

    @Override
    public void close() {
        boolean stat = isClosed.getAndSet(true);
        if (!stat) {
            log.info("SSLSessionConfig-NOT-CLOSED-YET " +Thread.currentThread() + " " + sslChannel);
            if(sslEngine != null)
            {
//                while((!sslEngine.isOutboundDone() || !sslEngine.isInboundDone()) )
//                {
//                    TaskUtil.sleep(50);
//                }
                IOUtil.close(() -> sslEngine.closeInbound(), () -> sslEngine.closeOutbound());
            }
            IOUtil.close(sslChannel);
            IOUtil.close(otherCloseable);
            selectorController.cancelSelectionKey(sslChannel);
            selectorController.cancelSelectionKey((SelectableChannel)otherCloseable);
            log.info("SSLSessionConfig-CLOSED " +Thread.currentThread() + " " + sslChannel);


        }
    }

    public boolean isClosed()
    {
        return isClosed.get();
    }
}
