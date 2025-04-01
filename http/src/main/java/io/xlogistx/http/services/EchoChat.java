package io.xlogistx.http.services;

import io.xlogistx.http.websocket.WSRemoteEndPoint;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.shared.annotation.SecurityProp;
import org.zoxweb.shared.crypto.CryptoConst;
import org.zoxweb.shared.util.BytesArray;

import javax.websocket.*;
import javax.websocket.server.ServerEndpoint;
import java.io.IOException;
import java.util.concurrent.atomic.AtomicLong;

@ServerEndpoint("/echo-chat")
@SecurityProp(authentications = {CryptoConst.AuthenticationType.ALL}, permissions = "chat:secure")
public class EchoChat
{
    public static final LogWrapper log = new LogWrapper(EchoChat.class).setEnabled(false);

    private AtomicLong index = new AtomicLong(0);
    public void onOpen(Session session) {
        System.out.println("New connection opened: " + session.getId());
    }

    @OnMessage
    public void onMessage(Session session, String message) throws IOException {
        //System.out.println("Received message: " + message);
        // Process or broadcast the message
        session.getBasicRemote().sendText( index.incrementAndGet() + "echo reply: " + message);
    }



    @OnMessage
    public void onMessage(BytesArray message, boolean isLast, Session session) throws IOException {
        if(log.isEnabled()) log.getLogger().info( isLast + " " + message.asString());

        ((WSRemoteEndPoint.WSBasic)session.getBasicRemote()).sendBinary(message, isLast);
        // Process or broadcast the message
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
