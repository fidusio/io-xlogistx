package io.xlogistx.http.security;


import com.sun.net.httpserver.Authenticator;
import com.sun.net.httpserver.HttpExchange;

public class HTTPAuthenticator
extends Authenticator
{
    @Override
    public Result authenticate(HttpExchange exch) {
        return null;
    }
}
