package io.xlogistx.common.http;

import java.io.IOException;

public interface HTTPSessionHandler {
    void handle(HTTPProtocolHandler protocolHandler) throws IOException;
}
