package io.xlogistx.common.http;

import java.io.IOException;

public interface HTTPRawHandler {

    /**
     * This method must be used with diligence it requires the call to process the content of the response,
     * if it returns false caller must write the response,
     * if it returns true the server will write the response for the protocol handler
     * @param protocolHandler object that will be used to for the request and response processing
     * @return true the server with will write the response, false the caller process the response writing
     * @throws IOException in case of errors
     */
    boolean handle(HTTPProtocolHandler protocolHandler) throws IOException;
}
