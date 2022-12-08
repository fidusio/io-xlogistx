package io.xlogistx.common.http;

import java.io.IOException;

public interface HTTPSessionHandler {
    void handle(HTTPSessionData sessionData) throws IOException;
}
