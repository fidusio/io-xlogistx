package io.xlogistx.http.websocket;

import io.xlogistx.common.http.HTTPProtocolHandler;
import org.zoxweb.server.io.ByteBufferUtil;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.shared.http.HTTPWSProto;
import org.zoxweb.shared.util.BytesArray;
import org.zoxweb.shared.util.NotSupportedException;

import javax.websocket.EncodeException;
import javax.websocket.RemoteEndpoint;
import javax.websocket.SendHandler;
import java.io.IOException;
import java.io.OutputStream;
import java.io.Writer;
import java.nio.ByteBuffer;
import java.util.concurrent.Future;

public abstract class WSRemoteEndPoint
implements RemoteEndpoint
{

    public static final LogWrapper log = new LogWrapper(WSRemoteEndPoint.class).setEnabled(false);


    public final HTTPProtocolHandler hph;
    //protected UByteArrayOutputStream baos = new UByteArrayOutputStream();
    protected WSRemoteEndPoint(HTTPProtocolHandler hph)
    {
        this.hph = hph;
    }


    public static class WSBasic
    extends WSRemoteEndPoint
    implements Basic
    {

        protected WSBasic(HTTPProtocolHandler hph)
        {
            super(hph);
        }

        /**
         * @param s
         * @throws IOException
         */
        @Override
        public synchronized void sendText(String s) throws IOException
        {
            sendText(s, true);
        }

        /**
         * @param byteBuffer
         * @throws IOException
         */
        @Override
        public synchronized void sendBinary(ByteBuffer byteBuffer) throws IOException {
            sendBinary(byteBuffer, true);

        }

        /**
         * @param message
         * @param isLast
         * @throws IOException
         */
        @Override
        public synchronized void sendText(String message, boolean isLast) throws IOException {
            HTTPWSProto.formatFrame(hph.getResponseStream(true), isLast, HTTPWSProto.OpCode.TEXT, null, message)
                    .writeTo(getSendStream(), true);

        }

        /**
         * @param byteBuffer
         * @param isLast
         * @throws IOException
         */
        @Override
        public synchronized void sendBinary(ByteBuffer byteBuffer, boolean isLast) throws IOException {
            byte[] data = ByteBufferUtil.toBytes(byteBuffer, false);
            if (log.isEnabled()) log.getLogger().info( new String(data));
            HTTPWSProto.formatFrame(hph.getResponseStream(true), isLast, HTTPWSProto.OpCode.BINARY, null, data)
                    .writeTo(getSendStream(), true);
        }


        public synchronized void sendBinary(BytesArray bytesArray, boolean isLast) throws IOException {
            if (log.isEnabled()) log.getLogger().info(bytesArray.asString());
            HTTPWSProto.formatFrame(hph.getResponseStream(true), isLast, HTTPWSProto.OpCode.BINARY, null, bytesArray)
                    .writeTo(getSendStream(), true);
        }

        /**
         * @return
         * @throws IOException
         */
        @Override
        public OutputStream getSendStream() throws IOException {
            return hph.getOutputStream();
        }

        /**
         * @return
         * @throws IOException
         */
        @Override
        public Writer getSendWriter() throws IOException {
            return null;
        }

        /**
         * @param o
         * @throws IOException
         * @throws EncodeException
         */
        @Override
        public void sendObject(Object o) throws IOException, EncodeException {
            throw new NotSupportedException("sendObject");

        }
    }

    /******************************************************************************************************/

    public static class WSAsync
    extends WSRemoteEndPoint
    implements Async
    {

        protected WSAsync(HTTPProtocolHandler hph)
        {
            super(hph);
        }

        /**
         * @return
         */
        @Override
        public long getSendTimeout() {
            return 0;
        }

        /**
         * @param l
         */
        @Override
        public void setSendTimeout(long l) {

        }

        /**
         * @param s
         * @param sendHandler
         */
        @Override
        public void sendText(String s, SendHandler sendHandler) {

        }

        /**
         * @param s
         * @return
         */
        @Override
        public Future<Void> sendText(String s) {
            return null;
        }

        /**
         * @param byteBuffer
         * @return
         */
        @Override
        public Future<Void> sendBinary(ByteBuffer byteBuffer) {
            return null;
        }

        /**
         * @param byteBuffer
         * @param sendHandler
         */
        @Override
        public void sendBinary(ByteBuffer byteBuffer, SendHandler sendHandler) {

        }

        /**
         * @param o
         * @return
         */
        @Override
        public Future<Void> sendObject(Object o) {
            return null;
        }

        /**
         * @param o
         * @param sendHandler
         */
        @Override
        public void sendObject(Object o, SendHandler sendHandler) {

        }
    }

    /**
     * @param b
     * @throws IOException
     */
    @Override
    public void setBatchingAllowed(boolean b) throws IOException {

    }

    /**
     * @return
     */
    @Override
    public boolean getBatchingAllowed() {
        return false;
    }

    /**
     * @throws IOException
     */
    @Override
    public void flushBatch() throws IOException {

    }

    /**
     * @param byteBuffer
     * @throws IOException
     * @throws IllegalArgumentException
     */
    @Override
    public void sendPing(ByteBuffer byteBuffer) throws IOException, IllegalArgumentException
    {
        if (log.isEnabled()) log.getLogger().info("sending " + byteBuffer);
        HTTPWSProto.formatFrame(hph.getResponseStream(true), true, HTTPWSProto.OpCode.PING, null, byteBuffer != null ?  ByteBufferUtil.toBytes(byteBuffer, true) : null)
                .writeTo(hph.getOutputStream(), true);

    }

    /**
     * @param byteBuffer
     * @throws IOException
     * @throws IllegalArgumentException
     */
    @Override
    public void sendPong(ByteBuffer byteBuffer) throws IOException, IllegalArgumentException
    {
        if (log.isEnabled()) log.getLogger().info("sending " + byteBuffer);
        HTTPWSProto.formatFrame(hph.getResponseStream(true), true, HTTPWSProto.OpCode.PONG, null,  byteBuffer != null ?  ByteBufferUtil.toBytes(byteBuffer, true) : null)
                .writeTo(hph.getOutputStream(), true);
    }



}
