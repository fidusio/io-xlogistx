package io.xlogistx.http;

import org.junit.jupiter.api.Test;
import org.zoxweb.server.http.OkHTTPCall;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.shared.http.HTTPMessageConfig;
import org.zoxweb.shared.http.HTTPMessageConfigInterface;
import org.zoxweb.shared.http.HTTPMethod;
import org.zoxweb.shared.http.HTTPResponseData;
import org.zoxweb.shared.util.NVGenericMap;

import java.io.IOException;
import java.util.Date;

public class WebServerTest {
    public static String BASE_URL = "https://localhost:6443";

    @Test
    public void testDataPost() throws IOException {
        HTTPMessageConfigInterface hmci = HTTPMessageConfig.createAndInit(BASE_URL, "/testdate", HTTPMethod.POST, false);

        hmci.getParameters().build("batata", "fried")
                .build("shawarma", "chicken")
                .build("sender-time", "" + new Date().getTime());

        HTTPResponseData hrd = OkHTTPCall.send(hmci);
        System.out.println(hrd);
    }

    @Test
    public void testWebHooks() throws IOException {
        HTTPMessageConfigInterface hmci = HTTPMessageConfig.createAndInit(BASE_URL, "/web-hooks/square/xlogistx", HTTPMethod.POST, false);

        NVGenericMap payload = new NVGenericMap().build("batata", "fried")
                .build("shawarma", "chicken")
                .build("sender-time", "" + new Date().getTime());
        hmci.setContent(GSONUtil.toJSONDefault(payload, true));
        hmci.setContentType("application/json");
        System.out.println(hmci);

        HTTPResponseData hrd = OkHTTPCall.send(hmci);
        System.out.println(hrd);
    }
}
