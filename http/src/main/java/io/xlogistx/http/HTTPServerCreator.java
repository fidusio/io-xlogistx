package io.xlogistx.http;

import org.zoxweb.shared.app.AppCreatorDefault;
import org.zoxweb.shared.http.HTTPServerConfig;
import org.zoxweb.shared.security.AccessSecurityException;
;

import java.io.IOException;
import java.security.GeneralSecurityException;

public class HTTPServerCreator
extends AppCreatorDefault<HTTPBasicServer, HTTPServerConfig>
{
    public static final String RESOURCE_NAME = "WebServer";



    @Override
    public HTTPBasicServer createApp() throws NullPointerException, IllegalArgumentException, IOException {
        HTTPBasicServer server = new HTTPBasicServer(getAppConfig());
        try {
            server.start();
        } catch (GeneralSecurityException e) {

            e.printStackTrace();
            throw new AccessSecurityException(e.getMessage());
        }
        return server;
    }

    @Override
    public String getName() {
        return RESOURCE_NAME;
    }


    @Override
    public void close() {

    }
}
