package io.xlogistx.http.services;

import com.sun.net.httpserver.HttpExchange;
import io.xlogistx.http.handler.BaseEndPointHandler;

import java.io.IOException;
import java.util.logging.Logger;

public class HTTPFileUpload
        extends BaseEndPointHandler
{
    private final static Logger log = Logger.getLogger(HTTPFileUpload.class.getName());

    @Override
    public void handle(HttpExchange exchange) throws IOException {

    }

    @Override
    protected void init() {

    }
}
