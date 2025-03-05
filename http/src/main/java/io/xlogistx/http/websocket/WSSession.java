package io.xlogistx.http.websocket;

import javax.websocket.*;
import java.io.IOException;
import java.net.URI;
import java.security.Principal;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class WSSession implements Session
{
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
        return false;
    }

    /**
     * @return
     */
    @Override
    public boolean isOpen() {
        return false;
    }

    /**
     * @return
     */
    @Override
    public long getMaxIdleTimeout() {
        return 0;
    }

    /**
     * @param l
     */
    @Override
    public void setMaxIdleTimeout(long l) {

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
        return 0;
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
        return 0;
    }

    /**
     * @return
     */
    @Override
    public RemoteEndpoint.Async getAsyncRemote() {
        return null;
    }

    /**
     * @return
     */
    @Override
    public RemoteEndpoint.Basic getBasicRemote() {
        return null;
    }

    /**
     * @return
     */
    @Override
    public String getId() {
        return "";
    }

    /**
     * @throws IOException
     */
    @Override
    public void close() throws IOException {

    }

    /**
     * @param closeReason
     * @throws IOException
     */
    @Override
    public void close(CloseReason closeReason) throws IOException {

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
        return null;
    }

    /**
     * @return
     */
    @Override
    public Set<Session> getOpenSessions() {
        return null;
    }
}
