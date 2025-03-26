package io.xlogistx.http.services;

import org.zoxweb.shared.annotation.SecurityProp;
import org.zoxweb.shared.crypto.CryptoConst;
import org.zoxweb.shared.util.BytesArray;

import javax.websocket.OnClose;
import javax.websocket.OnError;
import javax.websocket.OnMessage;
import javax.websocket.Session;
import javax.websocket.server.ServerEndpoint;
import java.io.IOException;
import java.util.concurrent.atomic.AtomicLong;

@ServerEndpoint("/echo-chat")
@SecurityProp(authentications = {CryptoConst.AuthenticationType.ALL}, permissions = "chat")
public class EchoChat
{

    private AtomicLong index = new AtomicLong(0);
    public void onOpen(Session session) {
        System.out.println("New connection opened: " + session.getId());
    }

    @OnMessage
    public void onMessage(String message, Session session) throws IOException {
        //System.out.println("Received message: " + message);
        // Process or broadcast the message
        session.getBasicRemote().sendText( index.incrementAndGet() + "echo reply: " + message);
    }

    @OnMessage
    public void onMessage(BytesArray message, Session session) {
        System.out.println("Received message: " + message);
        // Process or broadcast the message
    }

    @OnMessage
    public void onMessage(BytesArray message, boolean isLast, Session session) {
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
