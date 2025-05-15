package io.xlogistx.http.services;

import io.xlogistx.http.websocket.WSPongMessage;
import io.xlogistx.http.websocket.WSRemoteEndPoint;
import io.xlogistx.shiro.ShiroUtil;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.shared.util.BytesArray;
import org.zoxweb.shared.util.SUS;

import javax.websocket.*;
import javax.websocket.server.ServerEndpoint;
import java.io.IOException;
import java.util.concurrent.atomic.AtomicLong;

@ServerEndpoint("/echo-chat-test")
//@SecurityProp(authentications = {CryptoConst.AuthenticationType.ALL}, permissions = "chat")
public class EchoChatTest {

    public static final LogWrapper log = new LogWrapper(EchoChatTest.class).setEnabled(false);

    private final AtomicLong index = new AtomicLong(0);

    @OnOpen
    public void onOpen(Session session) {
        System.out.println("New session opened: " + SUS.toCanonicalID('.', ShiroUtil.subject().getPrincipal(), session.getId()));
    }

    @OnMessage
    public void onMessage(String message, Session session, boolean isLast) throws IOException {
        if (log.isEnabled()) log.getLogger().info("Received message: " + message);
        // Process or broadcast the message
        session.getBasicRemote().sendText(index.incrementAndGet() + " reply " + message);
    }

    @OnMessage
    public void onMessage(BytesArray message, Session session) throws IOException {
        ((WSRemoteEndPoint.WSBasic) session.getBasicRemote()).sendBinary(message, true);
    }

    @OnMessage
    public void pong(PongMessage message) {
        System.out.println("Pong: " + ((WSPongMessage) message).data.asString());
    }

    @OnClose
    public void onClose(Session session) {
        log.getLogger().info("Connection closed: " + session.getId() + " " + session.isSecure());
    }

    @OnError
    public void onError(Throwable throwable, Session session) {
        System.err.println("Error on connection " + session.getId() + ": " + throwable.getMessage());
    }

}
