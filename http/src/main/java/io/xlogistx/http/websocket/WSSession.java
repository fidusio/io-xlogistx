package io.xlogistx.http.websocket;

import io.xlogistx.common.http.HTTPProtocolHandler;
import io.xlogistx.shiro.ShiroPrincipal;
import org.apache.shiro.subject.Subject;
import org.zoxweb.shared.http.URIScheme;
import org.zoxweb.shared.util.Const;

import javax.websocket.*;
import java.io.IOException;
import java.net.URI;
import java.security.Principal;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class WSSession implements Session
{
    //private final HTTPProtocolHandler<Subject> hph;
    private volatile long maxIdleTime;
    private volatile ShiroPrincipal principal = null;
    private final WSRE wsre;

    public static final int MAX_MESSAGE_BUFFER_SIZE = (int)Const.SizeInBytes.K.SIZE*64;
    public WSSession(HTTPProtocolHandler<Subject> protocolHandler)
    {
        wsre = WSRE.create(protocolHandler);
    }

    /**
     * @return
     */
    @Override
    public WebSocketContainer getContainer() {
        return null;
    }

    /**
     * @param messageHandler
     * @throws IllegalStateException
     */
    @Override
    public void addMessageHandler(MessageHandler messageHandler) throws IllegalStateException {

    }

    /**
     * @param aClass
     * @param whole
     * @param <T>
     */
    @Override
    public <T> void addMessageHandler(Class<T> aClass, MessageHandler.Whole<T> whole) {

    }

    /**
     * @param aClass
     * @param partial
     * @param <T>
     */
    @Override
    public <T> void addMessageHandler(Class<T> aClass, MessageHandler.Partial<T> partial) {

    }

    /**
     * @return
     */
    @Override
    public Set<MessageHandler> getMessageHandlers() {
        return null;
    }

    /**
     * @param messageHandler
     */
    @Override
    public void removeMessageHandler(MessageHandler messageHandler) {

    }

    /**
     * @return
     */
    @Override
    public String getProtocolVersion() {
        return "";
    }

    /**
     * @return
     */
    @Override
    public String getNegotiatedSubprotocol() {
        return "";
    }

    /**
     * @return
     */
    @Override
    public List<Extension> getNegotiatedExtensions() {
        return null;
    }

    /**
     * @return
     */
    @Override
    public boolean isSecure() {
        return wsre.basic.hph.getProtocol() == URIScheme.WSS;
    }

    /**
     * @return
     */
    @Override
    public boolean isOpen() {
        return !wsre.basic.hph.isClosed();
    }

    /**
     * @return
     */
    @Override
    public long getMaxIdleTimeout() {
        return maxIdleTime;
    }

    /**
     * @param l in millis
     */
    @Override
    public void setMaxIdleTimeout(long l) {
        if(l < Const.TimeInMillis.MINUTE.MILLIS)
            throw new IllegalArgumentException("Idle timeout too short " + l + " < minute (in millis)");
        this.maxIdleTime = l;
    }

    /**
     * @param i
     */
    @Override
    public void setMaxBinaryMessageBufferSize(int i) {

    }

    /**
     * @return
     */
    @Override
    public int getMaxBinaryMessageBufferSize() {
        return MAX_MESSAGE_BUFFER_SIZE;
    }

    /**
     * @param i
     */
    @Override
    public void setMaxTextMessageBufferSize(int i) {

    }

    /**
     * @return
     */
    @Override
    public int getMaxTextMessageBufferSize() {
        return MAX_MESSAGE_BUFFER_SIZE;
    }

    /**
     * @return
     */
    @Override
    public RemoteEndpoint.Async getAsyncRemote() {
        return wsre.async;
    }

    /**
     * @return
     */
    @Override
    public RemoteEndpoint.Basic getBasicRemote() {
        return wsre.basic;
    }

    /**
     * @return
     */
    @Override
    public String getId() {
        return wsre.basic.hph.getSubject().getSession().getId().toString();
    }

    /**
     * @throws IOException
     */
    @Override
    public void close() throws IOException {
        wsre.basic.hph.close();
    }

    /**
     * @param closeReason
     * @throws IOException
     */
    @Override
    public void close(CloseReason closeReason) throws IOException {
        close();
    }

    /**
     * @return
     */
    @Override
    public URI getRequestURI() {
        return null;
    }

    /**
     * @return
     */
    @Override
    public Map<String, List<String>> getRequestParameterMap() {
        return null;
    }

    /**
     * @return
     */
    @Override
    public String getQueryString() {
        return "";
    }

    /**
     * @return
     */
    @Override
    public Map<String, String> getPathParameters() {
        return null;
    }

    /**
     * @return
     */
    @Override
    public Map<String, Object> getUserProperties() {
        return null;
    }

    /**
     * @return
     */
    @Override
    public Principal getUserPrincipal()
    {
        if(wsre.basic.hph.getSubject() != null && principal == null)
        {
            synchronized (this)
            {

                if (principal == null)
                {
                    principal = new ShiroPrincipal(wsre.basic.hph.getSubject());
                }
            }
        }
        return principal;
    }

    /**
     * @return
     */
    @Override
    public Set<Session> getOpenSessions() {
        return null;
    }
}
