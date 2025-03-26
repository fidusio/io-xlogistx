package io.xlogistx.http.services;

import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.shared.util.BytesArray;

import javax.websocket.OnClose;
import javax.websocket.OnError;
import javax.websocket.OnMessage;
import javax.websocket.Session;
import javax.websocket.server.ServerEndpoint;
import java.io.IOException;
import java.util.concurrent.atomic.AtomicLong;

@ServerEndpoint("/echo-chat-test")
//@SecurityProp(authentications = {CryptoConst.AuthenticationType.ALL}, permissions = "chat")
public class EchoChatTest
{

    public static final LogWrapper log = new LogWrapper(EchoChatTest.class).setEnabled(true);

    private AtomicLong index = new AtomicLong(0);
    public void onOpen(Session session) {
        System.out.println("New connection opened: " + session.getId());
    }

    @OnMessage
    public void onMessage(String message, Session session) throws IOException {
        if(log.isEnabled()) log.getLogger().info("Received message: " + message);
        // Process or broadcast the message
        session.getBasicRemote().sendText( index.incrementAndGet() + " reply " + message);
    }

    @OnMessage
    public void onMessage(BytesArray message, Session session) {
        System.out.println("Received message: " + message);
        // Process or broadcast the message
    }


    @OnClose
    public void onClose(Session session) {
        System.out.println("Connection closed: " + session.getId());
    }

    @OnError
    public void onError(Throwable throwable, Session session) {
        System.err.println("Error on connection " + session.getId() + ": " + throwable.getMessage());
    }

}
