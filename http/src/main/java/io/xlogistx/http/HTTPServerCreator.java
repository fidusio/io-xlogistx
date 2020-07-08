package io.xlogistx.http;

import org.zoxweb.shared.http.HTTPServerConfig;
import org.zoxweb.shared.security.AccessSecurityException;
import org.zoxweb.shared.util.AppCreator;

import java.io.IOException;
import java.security.GeneralSecurityException;

public class HTTPServerCreator
implements AppCreator<HTTPBasicServer, HTTPServerConfig>
{
    public static final String RESOURCE_NAME = "WebServer";
    private HTTPServerConfig config;
    @Override
    public void setAppConfig(HTTPServerConfig appConfig) {
        this.config = appConfig;
    }

    @Override
    public HTTPServerConfig getAppConfig() {
        return config;
    }

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
}
