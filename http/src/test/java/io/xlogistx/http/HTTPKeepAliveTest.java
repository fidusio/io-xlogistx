package io.xlogistx.http;

import org.junit.jupiter.api.Test;
import org.zoxweb.server.http.HTTPHeaderParser;
import org.zoxweb.server.http.OkHTTPCall;
import org.zoxweb.shared.http.*;
import org.zoxweb.shared.util.NVGenericMap;
import org.zoxweb.shared.util.NamedValue;

import java.io.IOException;
import java.util.List;

public class HTTPKeepAliveTest {

    @Test
    public void testKeepAlive() throws IOException
    {
        HTTPMessageConfigInterface hmci = HTTPMessageConfig.createAndInit("https://localhost:6443/timestamp", null, HTTPMethod.GET, false);
        hmci.getHeaders().build(HTTPConst.CommonHeader.CONNECTION_KEEP_ALIVE);
        int max;
        do
        {
            HTTPResponseData hrd = OkHTTPCall.send(hmci);
            List<String> kaVals = hrd.headerValues("Keep-Alive");
            if(kaVals != null)
            {
                NVGenericMap nvgm = null;

                for (String str : kaVals){
                    nvgm = HTTPHeaderParser.parseHeaderValue(nvgm, str);
                    NamedValue nv = HTTPHeaderParser.parseHeader("Keep-Alive: " + str);
                    System.out.println("NamedValue: " + nv);

                }
                max = (int) nvgm.getValueAsLong("max");

            }
            else
            {
                max = 0;


            }

            System.out.println("max = " + max +", " + hrd.headerValues("Connection"));




        }while (max > 0 );

        System.out.println(OkHTTPCall.OK_HTTP_CALLS);
    }
}
