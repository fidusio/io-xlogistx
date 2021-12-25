package io.xlogistx.ssl;


import io.xlogistx.common.fsm.Trigger;
import io.xlogistx.common.task.CallbackTask;
import org.zoxweb.server.io.ByteBufferUtil;
import org.zoxweb.server.io.IOUtil;

import org.zoxweb.server.net.SelectorController;
import org.zoxweb.shared.util.SharedUtil;

import javax.net.ssl.*;
import java.io.IOException;
import java.nio.ByteBuffer;

import java.nio.channels.SocketChannel;
import java.util.concurrent.atomic.AtomicBoolean;

import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.logging.Logger;

class SSLSessionConfig
implements AutoCloseable
//        , SKController
{
    private static final transient Logger log = Logger.getLogger(SSLSessionConfig.class.getName());
    public static boolean debug = true;

    //private final SSLContext sslContext;
    private final SSLEngine sslEngine; // the crypto engine

    volatile ByteBuffer inSSLNetData; // encrypted data
    volatile ByteBuffer outSSLNetData; // encrypted data
    volatile ByteBuffer inAppData; // clear text application data
    //volatile ByteBuffer outAppData; // data used during the handshake process
    volatile SocketChannel sslChannel; // the encrypted channel
    //volatile AtomicBoolean sslRead = new AtomicBoolean(true);
    volatile SelectorController selectorController;

    volatile SocketChannel remoteChannel = null;
    //volatile AtomicBoolean remoteRead = new AtomicBoolean(true);
    volatile ByteBuffer inRemoteData = null;
    volatile SSLStateMachine stateMachine;
    boolean forcedClose = false;

    //volatile AtomicBoolean sslChannelSelectableStatus = new AtomicBoolean(false);
    //volatile AtomicBoolean handshakeStarted = new AtomicBoolean(false);
    final Lock ioLock = new ReentrantLock();



    //boolean sslChannelReadState = false;
    private final AtomicBoolean isClosed = new AtomicBoolean(false);
    public SSLSessionConfig(SSLContext sslContext)
    {
        SharedUtil.checkIfNulls("sslContext null", sslContext);
        this.sslEngine = sslContext.createSSLEngine();
    }
    @Override
    public void close() {
        boolean stat = isClosed.getAndSet(true);
        String msg = "";
        if (!stat) {
            //log.info("SSLSessionConfig-NOT-CLOSED-YET " +Thread.currentThread() + " " + sslChannel);
            try
            {
                msg +=sslChannel.getRemoteAddress();
            }
            catch (Exception e){}

            if(sslEngine != null)
            {
                sslEngine.closeOutbound();
                try
                {


                    //outSSLNetData.clear();
                    if (forcedClose)
                    {
                        IOUtil.close(sslChannel);
                    }
                    else
                    {
                        while (!sslEngine.isOutboundDone() && sslChannel.isOpen()) {
                          SSLEngineResult.HandshakeStatus hs = getHandshakeStatus();
                          // log.info("CLOSING-SSL-CONNECTION: "  + hs + " sslChannel: " + sslChannel);
                          switch (hs) {
                            case NEED_WRAP:
                            case NEED_UNWRAP:
                              stateMachine.publishSync(
                                  new Trigger<CallbackTask<ByteBuffer>>(
                                      this,
                                      hs,
                                      null,
                                      new CallbackTask<ByteBuffer>() {
                                        @Override
                                        public void exception(Exception e) {
                                          e.printStackTrace();
                                        }

                                        @Override
                                        public void callback(ByteBuffer buffer) {
                                          if (buffer != null) {
                                            try {
                                              if (debug) log.info("Writing data back: " + buffer);
                                              ByteBufferUtil.smartWrite(ioLock, sslChannel, buffer);
                                            } catch (IOException e) {
                                              e.printStackTrace();
                                            }
                                          }
                                        }
                                      }));
                              break;
                            default:
                              IOUtil.close(sslChannel);
                          }
                        }
                    }
                }
                catch (Exception e)
                {
                    e.printStackTrace();
                }
                //IOUtil.close(() -> sslEngine.closeOutbound());
            }

                //ioLock.lock();
            IOUtil.close(sslChannel);
            IOUtil.close(remoteChannel);
            selectorController.cancelSelectionKey(sslChannel);
            selectorController.cancelSelectionKey(remoteChannel);
            stateMachine.close();
            ByteBufferUtil.cache(inSSLNetData, inAppData, outSSLNetData, inRemoteData);

            if(debug) log.info("SSLSessionConfig-CLOSED " +Thread.currentThread() + " " + sslChannel + " Address: " + msg);
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


//    public synchronized SSLEngineResult wrap(ByteBuffer source, ByteBuffer destination) throws SSLException{
//        return sslEngine.wrap(source, destination);
//    }



    public synchronized SSLEngineResult smartUnwrap(ByteBuffer source, ByteBuffer destination) throws SSLException
    {
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


    public synchronized void beginHandshake() throws SSLException {
        sslEngine.beginHandshake();
        inSSLNetData = ByteBufferUtil.allocateByteBuffer(ByteBufferUtil.BufferType.HEAP, getPacketBufferSize());
        outSSLNetData = ByteBufferUtil.allocateByteBuffer(ByteBufferUtil.BufferType.HEAP, getPacketBufferSize());
        inAppData = ByteBufferUtil.allocateByteBuffer(ByteBufferUtil.BufferType.HEAP, getApplicationBufferSize());
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


//    @Override
//    public void setSelectable(SelectionKey sk, boolean stat) {
//        //log.info("stat:" + stat + " sk: " + sk);
//        if (!stat)
//        {
//          if (sk.channel() == sslChannel) sslRead.set(stat);
//          if (sk.channel() == remoteChannel) remoteRead.set(stat);
//        }
//    }
//    public boolean isSelectable(SelectionKey sk)
//    {
//        if(sk.channel() == sslChannel)
//            return sslRead.get();
//        if(sk.channel() == remoteChannel)
//            return remoteRead.get();
//        //log.info("false " + sk);
//        return true;
//    }
}
