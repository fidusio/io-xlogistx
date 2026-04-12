package io.xlogistx.http.services;

import io.xlogistx.common.http.HTTPProtocolHandler;
import org.zoxweb.server.http.HTTPRawMessage;
import org.zoxweb.shared.http.HTTPHandler;
import org.zoxweb.shared.http.HTTPMessageConfigInterface;

import java.io.IOException;
import java.util.Arrays;

public class TestHTTPFilter
    implements HTTPHandler<HTTPProtocolHandler>
{
    @Override
    public boolean handle(HTTPProtocolHandler data) throws IOException {
        HTTPRawMessage hrm = data.getRawRequest();
        HTTPMessageConfigInterface requestHMCI = hrm.getHTTPMessageConfig();
        System.out.println("uri: " + requestHMCI.getURI());
        System.out.println("paramas: " + requestHMCI.getParameters());
        System.out.println("requestHMCI: " + requestHMCI.getHeaders());
        System.out.println("raw body: " + hrm.getDataStream());

        System.out.println("content: " + Arrays.toString(requestHMCI.getContent()));
        return true;
    }
}
