package io.xlogistx.http;

import org.zoxweb.server.http.OkHTTPCall;
import org.zoxweb.shared.http.HTTPMessageConfig;
import org.zoxweb.shared.http.HTTPMessageConfigInterface;
import org.zoxweb.shared.http.HTTPResponseData;

public class TestServerRedirect {

    public static void main(String[] args) {
        for (String url : args) {
            try {
                System.out.println(url);
                //OkHttpClient client = OkHTTPCall.createOkHttpBuilder(null, false, null, HTTPMessageConfigInterface.DEFAULT_TIMEOUT_20_SECOND, false, 20, HTTPMessageConfigInterface.DEFAULT_TIMEOUT_40_SECOND).build();
                HTTPMessageConfigInterface hmci = HTTPMessageConfig.createAndInit(url, null, "GET");
                hmci.setHTTPErrorAsException(false);
                hmci.setSecureCheckEnabled(false);
                hmci.setRedirectEnabled(false);
                OkHTTPCall okHTTPCall = new OkHTTPCall(hmci);
                HTTPResponseData hrd = okHTTPCall.sendRequest();
                System.out.println(hrd);

            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}
