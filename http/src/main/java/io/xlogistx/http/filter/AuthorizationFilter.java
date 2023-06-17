package io.xlogistx.http.filter;

import com.sun.net.httpserver.Filter;
import com.sun.net.httpserver.HttpExchange;

import java.io.IOException;

public class AuthorizationFilter
    extends Filter
{
    @Override
    public void doFilter(HttpExchange exchange, Chain chain) throws IOException {
        chain.doFilter(exchange);
    }

    @Override
    public String description() {
        return "Authorization filter";
    }
}
