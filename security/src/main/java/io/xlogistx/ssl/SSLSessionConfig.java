package io.xlogistx.ssl;


import org.zoxweb.server.io.ByteBufferUtil;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.net.SKController;
import org.zoxweb.server.net.SelectorController;
import org.zoxweb.shared.util.SharedUtil;

import javax.net.ssl.*;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.logging.Logger;

class SSLSessionConfig
implements AutoCloseable, SKController
{
    private static final transient Logger log = Logger.getLogger(SSLSessionConfig.class.getName());
    private SSLContext sslContext;
    private volatile SSLEngine sslEngine; // the crypto engine
    volatile AtomicBoolean firstHandshake = new AtomicBoolean(false);
    volatile ByteBuffer inNetData; // encrypted data
    volatile ByteBuffer outNetData; // encrypted data
    volatile ByteBuffer inAppData; // clear text application data
    //volatile ByteBuffer outAppData; // data used during the handshake process
    volatile SocketChannel sslChannel; // the encrypted channel
    volatile boolean sslRead = true;
    volatile SelectorController selectorController;

    volatile SocketChannel destinationChannel = null;
    volatile boolean dcRead = true;
    volatile ByteBuffer destinationBB = null;

    //volatile AtomicBoolean sslChannelSelectableStatus = new AtomicBoolean(false);
    volatile AtomicBoolean handshakeStarted = new AtomicBoolean(false);
    final  Lock ioLock =null;// new ReentrantLock();



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
            selectorController.cancelSelectionKey(destinationChannel);
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

//    public synchronized SSLEngineResult wrap(ByteBuffer source, ByteBuffer destination) throws SSLException {
//        return sslEngine.wrap(source, destination);
//    }

    public synchronized SSLEngineResult smartWrap(ByteBuffer source, ByteBuffer destination) throws SSLException {
        source.flip();
        SSLEngineResult ret = sslEngine.wrap(source, destination);
        //if(ret.getStatus() == SSLEngineResult.Status.OK)
            source.compact();
        return ret;
    }



    public synchronized SSLEngineResult smartUnwrap(ByteBuffer source, ByteBuffer destination) throws SSLException {

        source.flip();
        SSLEngineResult ret = sslEngine.unwrap(source, destination);
        //if(ret.getStatus() == SSLEngineResult.Status.OK)
            source.compact();
        return ret;
    }

    public SSLSession getSession()
    {
        return sslEngine.getSession();
    }

    public SSLSession getHandshakeSession()
    {
        return sslEngine.getHandshakeSession();
    }

//    public synchronized SSLEngineResult unwrap(ByteBuffer source, ByteBuffer destination) throws SSLException {
//        return sslEngine.unwrap(source, destination);
//    }

    public synchronized void beginHandshake() throws SSLException {
        sslEngine.setUseClientMode(false);
        sslEngine.beginHandshake();
        inNetData = ByteBufferUtil.allocateByteBuffer(getPacketBufferSize());
        outNetData = ByteBufferUtil.allocateByteBuffer(getPacketBufferSize());
        inAppData = ByteBufferUtil.allocateByteBuffer(getApplicationBufferSize());
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


    @Override
    public void setSelectable(SelectionKey sk, boolean stat) {
        log.info("stat:" + stat + " sk: " + sk);
        if(sk.channel() == sslChannel)
             sslRead = stat;
        if(sk.channel() == destinationChannel)
            dcRead = stat;
    }
    public boolean isSelectable(SelectionKey sk)
    {
        if(sk.channel() == sslChannel)
            return sslRead;
        if(sk.channel() == destinationChannel)
            return dcRead;
        //log.info("false " + sk);
        return true;
    }
}
