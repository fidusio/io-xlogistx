package io.xlogistx.http.websocket;

import io.xlogistx.common.http.HTTPProtocolHandler;
import io.xlogistx.shiro.ShiroPrincipal;
import org.apache.shiro.subject.Subject;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.shared.http.URIScheme;
import org.zoxweb.shared.protocol.ProtoSession;
import org.zoxweb.shared.util.Const;
import org.zoxweb.shared.util.NVGenericMap;

import javax.websocket.*;
import java.io.IOException;
import java.net.URI;
import java.security.Principal;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

public class WSSession implements Session, ProtoSession<Session, Subject> {

    public static LogWrapper log = new LogWrapper(WSSession.class).setEnabled(true);
    //private final HTTPProtocolHandler<Subject> hph;
    private volatile long maxIdleTime;
    private final ShiroPrincipal principal;
    private volatile Subject subject;
    private final WSRE wsre;

    private final AtomicBoolean closed = new AtomicBoolean(false);

    public static final int MAX_MESSAGE_BUFFER_SIZE = (int) Const.SizeInBytes.K.SIZE * 64;
    private volatile Set<Session> sessionsSet;

    //private final Subject subject;
    public WSSession(HTTPProtocolHandler protocolHandler, Subject subject, Set<Session> sessionsSet) {
        wsre = WSRE.create(protocolHandler);
        this.sessionsSet = sessionsSet;
        this.sessionsSet.add(this);
        this.principal = new ShiroPrincipal(subject);
        this.subject = subject;
        setSubjectID(subject);
        log.getLogger().info("Current Sessions: " + sessionsSet.size());
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

//    public Subject getSubject() {
//        return principal.getSubject();
//    }

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
        if (l < Const.TimeInMillis.MINUTE.MILLIS)
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
        return getSubjectID().
                getSession().
                getId().
                toString();
    }

    /**
     * @throws IOException
     */
    @Override
    public void close() throws IOException {
        close(null);
    }

    /**
     * @param closeReason
     * @throws IOException
     */
    @Override
    public void close(CloseReason closeReason) throws IOException {

        if (!closed.getAndSet(true)) {
            sessionsSet.remove(this);
            log.getLogger().info("Pending WebSocket Sessions: " + sessionsSet.size());
            try {

                Subject subject = getSubjectID();

                if (subject != null) {
                    Object subjectID = subject.getPrincipal();
                    subject.logout();
                    if (log.isEnabled())
                        log.getLogger().info(subjectID + " is authenticated " + subject.isAuthenticated());
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
            IOUtil.close(wsre.basic.hph);

        }

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
    public Principal getUserPrincipal() {
        return principal;
    }

    /**
     * @return
     */
    @Override
    public Set<Session> getOpenSessions() {
        return sessionsSet;
    }

    /**
     * @return the actual session associated with the implementation
     */
    @Override
    public Session getSession() {
        return this;
    }

    /**
     * @return true is the session is closed or the implementation allows it, it is not mandatory to obied by the response the caller can invoke close regardless
     */
    @Override
    public boolean canClose() {
        return !subject.isAuthenticated();
    }

    @Override
    public NVGenericMap getProperties() {
        return null;
    }

    /**
     * Checks if closed.
     *
     * @return true if closed
     */
    @Override
    public boolean isClosed() {
        return closed.get();
    }

    /**
     * Sets the subject ID.
     *
     * @param id
     */
    @Override
    public void setSubjectID(Subject id) {
        this.subject = id;
        //throw new IllegalArgumentException("Operation not allowed");
    }

    /**
     * Returns the subject ID.
     *
     * @return
     */
    @Override
    public Subject getSubjectID() {
        return subject;
    }
}
