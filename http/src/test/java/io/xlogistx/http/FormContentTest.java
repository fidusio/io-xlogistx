package io.xlogistx.http;

import org.zoxweb.server.http.OkHTTPCall;
import org.zoxweb.shared.http.HTTPMessageConfig;
import org.zoxweb.shared.http.HTTPMessageConfigInterface;

public class FormContentTest {

    public static void main(String[] args) {
        try {
            String url = args[0];
            String method = args[1];
            HTTPMessageConfigInterface hmci = HTTPMessageConfig.createAndInit(url, "form-content", method, false);
            hmci.getParameters().build("name", "toto")
                    .build("email", "dontbother@nodomain.com");
            System.out.println(OkHTTPCall.send(hmci));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
