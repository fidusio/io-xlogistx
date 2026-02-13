package io.xlogistx.http;

import org.zoxweb.shared.io.SharedIOUtil;
import org.zoxweb.server.net.NIOSocket;
import org.zoxweb.shared.app.AppCreatorDefault;
import org.zoxweb.shared.http.HTTPServerConfig;
import org.zoxweb.shared.security.AccessSecurityException;

import java.io.IOException;
import java.security.GeneralSecurityException;

public class NIOHTTPServerCreator
        extends AppCreatorDefault<NIOHTTPServer, HTTPServerConfig> {
    public static final String RESOURCE_NAME = "WebServer";


    private NIOHTTPServer server = null;

    @Override
    public synchronized NIOHTTPServer createApp() throws NullPointerException, IllegalArgumentException, IOException {
        if (server == null) {
            server = new NIOHTTPServer(getAppConfig());
            try {
                server.start();
            } catch (GeneralSecurityException e) {

                e.printStackTrace();
                throw new AccessSecurityException(e.getMessage());
            }
        }
        return server;
    }

    @Override
    public String getName() {
        return RESOURCE_NAME;
    }


    @Override
    public void close() {
        SharedIOUtil.close(server);
    }

    public NIOSocket getNIOSocket() {

        return server != null ? server.getNIOSocket() : null;
    }
}
