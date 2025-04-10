package io.xlogistx.common.http;

import java.io.IOException;

public interface HTTPRawHandler {
    void handle(HTTPProtocolHandler protocolHandler) throws IOException;
}
