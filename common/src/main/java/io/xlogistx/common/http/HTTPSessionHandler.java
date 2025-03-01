package io.xlogistx.common.http;

import java.io.IOException;

public interface HTTPSessionHandler<V> {
    void handle(HTTPProtocolHandler<V> protocolHandler) throws IOException;
}
