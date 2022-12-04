package iot.xlogistx.okta;

import org.zoxweb.server.http.HTTPCall;
import org.zoxweb.shared.http.*;
import org.zoxweb.shared.util.Const;

import java.util.Date;

public class HTTPOktaTest
{
    public static void main(String ...args)
    {
        try
        {

            int index = 0;
            String url = args[index++];
            String token = args[index++];
            HTTPMessageConfigInterface hmci = HTTPMessageConfig.createAndInit(url, "/api/v1/users", HTTPMethod.GET);
            hmci.setAuthorization(new HTTPAuthorizationToken(HTTPAuthScheme.SSWS, token));
            long start = System.currentTimeMillis();
            HTTPCall hc = new HTTPCall(hmci);
            long end = System.currentTimeMillis();
            HTTPResponseData hrd = hc.sendRequest();
            System.out.println(new String(hrd.getData()));
            System.out.println(hrd);
            System.out.println(hrd.getHeaders().get("x-rate-limit-reset"));
            long rateLimitReset = Long.parseLong(hrd.getHeaders().get("x-rate-limit-reset").get(0))*1000;
            System.out.println(new Date()  + " "  + new Date(rateLimitReset) +
                    " start delta:" + Const.TimeInMillis.toString(rateLimitReset - start) +
                    " end delta:" + Const.TimeInMillis.toString(rateLimitReset - end)  + " delta " + (end - start));

        }
        catch(Exception e)
        {
            e.printStackTrace();
        }
    }
}
