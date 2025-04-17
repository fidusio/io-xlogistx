package io.xlogistx.http;

import org.junit.jupiter.api.Test;
import org.zoxweb.server.http.HTTPHeaderParser;
import org.zoxweb.server.http.OkHTTPCall;
import org.zoxweb.shared.http.*;
import org.zoxweb.shared.util.NVGenericMap;

import java.io.IOException;
import java.util.List;

public class HTTPKeepAliveTest {

    @Test
    public void testKeepAlive() throws IOException
    {
        HTTPMessageConfigInterface hmci = HTTPMessageConfig.createAndInit("https://localhost:6443/timestamp", null, HTTPMethod.GET, false);
        hmci.getHeaders().build(HTTPConst.CommonHeader.CONNECTION_KEEP_ALIVE);
        int max = 0;
        int count = 0;
        do
        {
            HTTPResponseData hrd = OkHTTPCall.send(hmci);
            List<String> kaVals = hrd.headerValues(HTTPHeader.KEEP_ALIVE);
            if(kaVals != null)
            {

                if(kaVals.size() == 1)
                {
                    NVGenericMap nvgm  = HTTPHeaderParser.parseHeader(HTTPHeader.KEEP_ALIVE, kaVals.get(0));
                    System.out.println("NamedValue: " + nvgm);
                    max = (int)nvgm.getValueAsLong("max");
                }
            }

            System.out.println("max = " + max +", " + hrd.headerValues("Connection"));


            count++;

        }while (max > 1 );

        System.out.println(OkHTTPCall.OK_HTTP_CALLS);
        System.out.println("count " + count);
    }

    @Test
    public void testNoKeepAlive() throws IOException
    {
        HTTPMessageConfigInterface hmci = HTTPMessageConfig.createAndInit("https://localhost:6443/timestamp", null, HTTPMethod.GET, false);
        hmci.getHeaders().build(HTTPConst.CommonHeader.CONNECTION_CLOSE);
        int max = 0;
        do
        {
            HTTPResponseData hrd = OkHTTPCall.send(hmci);
            List<String> kaVals = hrd.headerValues("Connection");
            if(kaVals != null)
            {


                    NVGenericMap nvm  = HTTPHeaderParser.parseHeader(HTTPHeader.KEEP_ALIVE, kaVals.get(0));
                    System.out.println("NamedValue: " + nvm);



            }


            System.out.println("max = " + max +", " + hrd.headerValues("Connection"));




        }while (max > 0 );

        System.out.println(OkHTTPCall.OK_HTTP_CALLS);
    }
}
