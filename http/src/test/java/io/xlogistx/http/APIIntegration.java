package io.xlogistx.http;

import org.zoxweb.server.http.HTTPCall;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.shared.http.*;
import org.zoxweb.shared.util.NVGenericMap;
import org.zoxweb.shared.util.ParamUtil;

public class APIIntegration {

    public static void main(String ...args)
    {
        try {


            ParamUtil.ParamMap params = ParamUtil.parse("=", args);

            String apiKeyID = params.stringValue("api-key-id");
            String apiKey = params.stringValue("api-key");
            String apiURL = params.stringValue("url");
            String apiURI = params.stringValue("uri");
            String httpMethod = params.stringValue("request");


            HTTPMessageConfigInterface hmci = HTTPMessageConfig.createAndInit(apiURL, apiURI, httpMethod);
            hmci.setAccept(HTTPMediaType.APPLICATION_JSON);
            hmci.setContentType(HTTPMediaType.APPLICATION_JSON);
            hmci.setURLEncodingEnabled(false);
            hmci.getHeaders().add("revision", "2023-07-15");
            hmci.setAuthorization(new HTTPAuthorizationToken(HTTPAuthScheme.GENERIC, apiKeyID, apiKey));

            NVGenericMap content = new NVGenericMap();
            NVGenericMap data = new NVGenericMap("data");
            content.add(data);
            NVGenericMap attributes = new NVGenericMap("attributes");
            data.add("type", "profile");
            data.add(attributes);
            attributes.add(params.asNVPair("email"));
            attributes.add(params.asNVPair("first_name"));

            if (params.nameExists("last_name"))
                attributes.add(params.asNVPair("last_name"));


            hmci.setContent(GSONUtil.toJSONDefault(content));


            System.out.println(GSONUtil.toJSONDefault(hmci, true));

            System.out.println(GSONUtil.toJSONDefault(content, true));
            System.out.println(HTTPCall.send(hmci));
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }


    }
}
