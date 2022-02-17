package io.xlogistx.common.net;

import org.zoxweb.server.http.HTTPCall;
import org.zoxweb.shared.http.HTTPMessageConfig;
import org.zoxweb.shared.http.HTTPMessageConfigInterface;
import org.zoxweb.shared.http.HTTPMethod;
import org.zoxweb.shared.http.HTTPMimeType;
import org.zoxweb.shared.util.NVPair;

public class HTTPCallTest {
    public static void main(String ...args)
    {
        try
        {
            HTTPMessageConfigInterface hmci = HTTPMessageConfig.createAndInit("http://localhost:8080/batata", null, HTTPMethod.POST);
            hmci.getParameters().add(new NVPair("username","admin@blueseacare.com"));
            hmci.getParameters().add(new NVPair("password","BlueC209!"));
            hmci.getParameters().add(new NVPair("return_to",""));
            hmci.getParameters().add(new NVPair("RelayState","/"));
            hmci.setContentType(HTTPMimeType.MULTIPART_FORM_DATA);
            HTTPCall hc = new HTTPCall(hmci);
            System.out.println(hc.sendRequest());
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
    }
}
