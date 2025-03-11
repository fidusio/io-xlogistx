package io.xlogistx.http;

import okhttp3.*;
import okio.ByteString;
import org.zoxweb.server.http.OkHTTPCall;
import org.zoxweb.shared.http.HTTPMessageConfigInterface;
import org.zoxweb.shared.util.Const;
import org.zoxweb.shared.util.ParamUtil;
import org.zoxweb.shared.util.RateCounter;

import java.util.concurrent.atomic.AtomicInteger;

public class WebSocketClientTest {

    public static void main(String[] args) {
        OkHttpClient client = OkHTTPCall.createOkHttpBuilder(null, null, HTTPMessageConfigInterface.DEFAULT_TIMEOUT_20_SECOND,false, 10, HTTPMessageConfigInterface.DEFAULT_TIMEOUT_20_SECOND).build();
        ParamUtil.ParamMap params = ParamUtil.parse("=", args);
        System.out.println(params);
        String url = params.stringValue("url", false);
        String username = params.stringValue("user", false);
        String password = params.stringValue("password", false);
        int repeat = params.intValue("repeat", 1000);

        // Generate the Basic Authorization header value
        String credential = Credentials.basic(username, password);


        Request request = new Request.Builder()
                .url(url)
                .header("Authorization", credential)
                .build();

        RateCounter rc = new RateCounter();
        long ts = System.currentTimeMillis();
        AtomicInteger ai = new AtomicInteger();

        WebSocketListener listener = new WebSocketListener() {
            @Override
            public void onOpen(WebSocket webSocket, Response response) {
                System.out.println("WebSocket opened: " + response);
                webSocket.send("Hello, WebSocket!");
            }

            @Override
            public void onMessage(WebSocket webSocket, String text) {
//                synchronized (this)
                {
                    int count = ai.incrementAndGet();
                    if (count == repeat) {
                        long delta = System.currentTimeMillis() - ts;
                        rc.register(delta, ai.get());

                        System.out.println(ai.get() + "  " + Const.TimeInMillis.toString(delta) + " " + rc.rate(1000));
                    }
                }
            }

            @Override
            public void onMessage(WebSocket webSocket, ByteString bytes) {
                System.out.println("Received bytes: " + bytes.hex());
            }

            @Override
            public void onClosing(WebSocket webSocket, int code, String reason) {
                System.out.println("WebSocket is closing: " + code + " / " + reason);
                webSocket.close(code, reason);
            }

            @Override
            public void onClosed(WebSocket webSocket, int code, String reason) {
                System.out.println("WebSocket closed: " + code + " / " + reason);
            }

            @Override
            public void onFailure(WebSocket webSocket, Throwable t, Response response) {
                System.err.println("WebSocket error: " + t.getMessage());
            }
        };

        // Establish the WebSocket connection
        WebSocket ws = client.newWebSocket(request, listener);
        for (int i=0; i < repeat; i++)
        {
            int id = i;
            //TaskUtil.defaultTaskScheduler().execute( ()->ws.send("hello " + id));
            ws.send("hello " + id);
        }

        // The client will continue to run; you can shut it down when you're done:
        // client.dispatcher().executorService().shutdown();
    }
}

