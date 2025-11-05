package io.xlogistx.http;

import org.junit.jupiter.api.Test;
import org.zoxweb.server.http.OkHTTPCall;
import org.zoxweb.shared.http.HTTPMessageConfig;
import org.zoxweb.shared.http.HTTPMessageConfigInterface;
import org.zoxweb.shared.http.HTTPMethod;
import org.zoxweb.shared.http.HTTPResponseData;


public class WebMailerTester {

    @Test
    public void webMailer() {
        String url = "https://localhost:6443";
        String uri = "/form/generic-mailer/xlogistx.io/web";
        HTTPMessageConfigInterface hmci = HTTPMessageConfig.createAndInit(url, uri, HTTPMethod.POST, false);
        hmci.getParameters()
                .build("name", "Mario")
                .build("captcha", "543342")
                .build("captcha-id", "id")
                .build("email", "marion@robin.hood");

        try {

            HTTPResponseData hrd = OkHTTPCall.send(hmci);
            System.out.println(hrd);
        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}
