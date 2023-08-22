package io.xlogistx.http;

import org.zoxweb.server.http.HTTPCall;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.shared.http.HTTPAuthorization;
import org.zoxweb.shared.http.HTTPMediaType;
import org.zoxweb.shared.http.HTTPMessageConfig;
import org.zoxweb.shared.http.HTTPMessageConfigInterface;
import org.zoxweb.shared.util.GetValue;
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
            hmci.setAuthorization(new HTTPAuthorization(apiKeyID, apiKey));

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

            String contentJson = GSONUtil.toJSONDefault(content, true);


            String  json = GSONUtil.toJSONDefault(hmci, true);
            System.out.println(json);
            hmci = GSONUtil.fromJSONDefault(json, HTTPMessageConfig.class, true);
            System.out.println(GSONUtil.toJSONDefault(content, true));
            GetValue<?> rev = hmci.getHeaders().get("revision");
            System.out.println(rev);
            //hmci.getHeaders().add("revision", "2023-07-15");

            System.out.println(contentJson);

            hmci.setContent(GSONUtil.toJSONDefault(content));

            System.out.println(hmci.getAuthorization().toHTTPHeader());
            System.out.println(HTTPCall.send(hmci));

        }
        catch (Exception e)
        {
            e.printStackTrace();
        }


    }
}
