package io.xlogistx.http.websocket;

import io.xlogistx.common.http.HTTPProtocolHandler;
import org.apache.shiro.subject.Subject;
import org.zoxweb.server.net.BaseChannelOutputStream;
import org.zoxweb.shared.util.SharedStringUtil;

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


    public final HTTPProtocolHandler<Subject> hph;
    protected WSRemoteEndPoint(HTTPProtocolHandler<Subject> hph)
    {
        this.hph = hph;
    }


    public static class WSBasic
    extends WSRemoteEndPoint
    implements Basic
    {
        protected WSBasic(HTTPProtocolHandler<Subject> hph)
        {
            super(hph);
        }

        /**
         * @param s
         * @throws IOException
         */
        @Override
        public void sendText(String s) throws IOException {
            getSendStream().write(SharedStringUtil.toBytes(s));
        }

        /**
         * @param byteBuffer
         * @throws IOException
         */
        @Override
        public void sendBinary(ByteBuffer byteBuffer) throws IOException {
            ((BaseChannelOutputStream)hph.getOutputStream()).write(byteBuffer);
        }

        /**
         * @param s
         * @param b
         * @throws IOException
         */
        @Override
        public void sendText(String s, boolean b) throws IOException {
            sendText(s);
        }

        /**
         * @param byteBuffer
         * @param b
         * @throws IOException
         */
        @Override
        public void sendBinary(ByteBuffer byteBuffer, boolean b) throws IOException {
            sendBinary(byteBuffer);
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

        }
    }

    /******************************************************************************************************/

    public static class WSAsync
    extends WSRemoteEndPoint
    implements Async
    {

        protected WSAsync(HTTPProtocolHandler<Subject> hph)
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
    public void sendPing(ByteBuffer byteBuffer) throws IOException, IllegalArgumentException {

    }

    /**
     * @param byteBuffer
     * @throws IOException
     * @throws IllegalArgumentException
     */
    @Override
    public void sendPong(ByteBuffer byteBuffer) throws IOException, IllegalArgumentException
    {
    }

}
