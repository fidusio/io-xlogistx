package io.xlogistx.http;

import org.zoxweb.server.http.OkHTTPCall;
import org.zoxweb.shared.http.HTTPMessageConfig;
import org.zoxweb.shared.http.HTTPMessageConfigInterface;

public class TestServerRedirect {

    public static void main(String[] args) {
        try {

            HTTPMessageConfigInterface hmci = HTTPMessageConfig.createAndInit(args[0], null, "GET");

            System.out.println(OkHTTPCall.send(hmci));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
