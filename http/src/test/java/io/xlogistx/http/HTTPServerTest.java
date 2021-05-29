package io.xlogistx.http;

import com.sun.net.httpserver.HttpServer;

import java.net.InetSocketAddress;

public class HTTPServerTest {

    public static void main(String ...args)
    {
        try
        {
            HttpServer server = HttpServer.create(new InetSocketAddress("localhost", 8001), 0);
            System.out.println(server.getClass().getName());
            sun.net.httpserver.HttpServerImpl toto;
        }
        catch(Exception e)
        {
            e.printStackTrace();
        }
    }
}
