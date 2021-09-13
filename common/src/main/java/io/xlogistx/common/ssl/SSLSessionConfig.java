package io.xlogistx.common.ssl;


import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.net.SelectorController;


import org.zoxweb.shared.util.SharedUtil;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import java.nio.ByteBuffer;

import java.nio.channels.SelectableChannel;
import java.nio.channels.SocketChannel;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Logger;

class SSLSessionConfig
implements AutoCloseable
{
    private static final transient Logger log = Logger.getLogger(SSLSessionConfig.class.getName());
    private SSLContext sslContext;
    private volatile SSLEngine sslEngine; // the crypto engine
    volatile ByteBuffer inNetData; // encrypted data
    volatile ByteBuffer outNetData; // encrypted data
    volatile ByteBuffer inAppData; // clear text application data
    //ByteBuffer outAppData; // data used during the handshake process
    volatile SocketChannel sslChannel; // the encrypted channel
    volatile SelectorController selectorController;

    volatile SocketChannel destinationChannel = null;
    volatile ByteBuffer destinationBB = null;



    //boolean sslChannelReadState = false;
    volatile private AtomicBoolean isClosed = new AtomicBoolean(false);
    public SSLSessionConfig(SSLContext sslContext)
    {
        SharedUtil.checkIfNulls("sslContext null", sslContext);
        this.sslContext = sslContext;
        this.sslEngine = sslContext.createSSLEngine();
    }
    @Override
    public void close() {
        boolean stat = isClosed.getAndSet(true);
        if (!stat) {
            log.info("SSLSessionConfig-NOT-CLOSED-YET " +Thread.currentThread() + " " + sslChannel);
            if(sslEngine != null)
            {
//                sslEngine.closeOutbound();
//                while(!sslEngine.isOutboundDone() && sslChannel.isOpen())
//                {
//                    TaskUtil.sleep(50);
//                    log.info(Thread.currentThread() + " !@$#%$#^%%^&%&^%*&^*^&*&*^&&*^&*^&*^&^*");
//                }
                IOUtil.close(() -> sslEngine.closeOutbound());
            }
            IOUtil.close(sslChannel);
            IOUtil.close(destinationChannel);
            selectorController.cancelSelectionKey(sslChannel);
            selectorController.cancelSelectionKey((SelectableChannel) destinationChannel);
            log.info("SSLSessionConfig-CLOSED " +Thread.currentThread() + " " + sslChannel);
        }

    }

    public boolean isClosed()
    {
        return isClosed.get();
    }


//    public SSLEngine getSSLEngine(){
//        return sslEngine;
//    }

    public synchronized SSLEngineResult wrap(ByteBuffer source, ByteBuffer destination) throws SSLException {
        return sslEngine.wrap(source, destination);
    }

    public synchronized SSLEngineResult unwrap(ByteBuffer source, ByteBuffer destination) throws SSLException {
        return sslEngine.unwrap(source, destination);
    }

    public void beginHandshake() throws SSLException {
        sslEngine.beginHandshake();
    }


    public void setUseClientMode(boolean clientMode)
    {
        sslEngine.setUseClientMode(clientMode);
    }

    public int getPacketBufferSize()
    {
        return sslEngine.getSession().getPacketBufferSize();
    }

    public int getApplicationBufferSize()
    {
        return sslEngine.getSession().getApplicationBufferSize();
    }
    public SSLEngineResult.HandshakeStatus getHandshakeStatus()
    {
        return sslEngine.getHandshakeStatus();
    }


    public Runnable getDelegatedTask()
    {
        return sslEngine.getDelegatedTask();
    }


}
