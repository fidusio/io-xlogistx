package io.xlogistx.http.services;

import javax.websocket.OnClose;
import javax.websocket.OnError;
import javax.websocket.OnMessage;
import javax.websocket.Session;
import javax.websocket.server.ServerEndpoint;

@ServerEndpoint("/echo-chat")
//@SecurityProp(authentications = {CryptoConst.AuthenticationType.ALL}, permissions = "chat")
public class EchoChat
{
    public void onOpen(Session session) {
        System.out.println("New connection opened: " + session.getId());
    }

    @OnMessage
    public void onMessage(String message, Session session) {
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
