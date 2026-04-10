package io.xlogistx.http.services;

import io.xlogistx.common.data.PropertyContainer;
import io.xlogistx.common.http.HTTPProtocolHandler;
import io.xlogistx.common.http.HTTPRawHandler;
import org.zoxweb.shared.util.NVGenericMap;

import java.io.IOException;

public class HTTPWebHook
        extends PropertyContainer<NVGenericMap>
        implements HTTPRawHandler {

    public boolean handle(HTTPProtocolHandler protocolHandler) throws IOException {
        boolean stat = false;
        return stat;
    }


    protected void refreshProperties() {

    }

}
