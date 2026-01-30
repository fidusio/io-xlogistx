package io.xlogistx.nosneak.services;

import io.xlogistx.http.NIOHTTPServer;
import org.zoxweb.server.net.NIOSocket;
import org.zoxweb.shared.annotation.EndPointProp;
import org.zoxweb.shared.annotation.ParamProp;
import org.zoxweb.shared.http.HTTPMethod;
import org.zoxweb.shared.util.NVGenericMap;
import org.zoxweb.shared.util.ResourceManager;

public class PQCChecker {

    @EndPointProp(methods = {HTTPMethod.GET}, name = "pqc-checker", uris = "/pqc-checker/{domain}/{port}/{timeout}")
    public NVGenericMap pqcCheck(@ParamProp(name = "domain") String domain, @ParamProp(name = "port")int port, @ParamProp(name = "timeout", optional = true) int timeout) {
        NVGenericMap response = new NVGenericMap();




        return response;
    }

    private NIOSocket getSocket() {
        NIOHTTPServer niohttpServer = ResourceManager.lookupResource(ResourceManager.Resource.HTTP_SERVER);
        return niohttpServer.getNIOSocket();
    }
}
