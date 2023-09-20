package io.xlogistx.http;

import org.zoxweb.server.http.HTTPAPIEndPoint;
import org.zoxweb.server.http.HTTPUtil;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.shared.http.*;
import org.zoxweb.shared.util.*;

import java.util.ArrayList;

public class APIIntegration
{

    public static void main(String ...args)
    {
        try {


            ParamUtil.ParamMap params = ParamUtil.parse("=", args);

            String apiKeyID = params.stringValue("api-key-id");
            String apiKey = params.stringValue("api-key");
            String apiURL = params.stringValue("url");
            String apiURI = params.stringValue("uri");
            String httpMethod = params.stringValue("request");


            HTTPMessageConfigInterface config = HTTPMessageConfig.createAndInit(apiURL, apiURI, httpMethod);
            config.setAccept(HTTPMediaType.APPLICATION_JSON);
            config.setContentType(HTTPMediaType.APPLICATION_JSON);
            config.setURLEncodingEnabled(false);
            config.getHeaders().add("revision", "2023-07-15");
            config.setAuthorization(new HTTPAuthorization(apiKeyID, apiKey));







            BiDataEncoder<HTTPMessageConfigInterface, NVPairList, HTTPMessageConfigInterface> encoder = new BiDataEncoder<HTTPMessageConfigInterface, NVPairList, HTTPMessageConfigInterface>() {
                @Override
                public HTTPMessageConfigInterface encode(HTTPMessageConfigInterface hmci, NVPairList nvPairList) {
                    NVGenericMap content = new NVGenericMap();
                    NVGenericMap data = new NVGenericMap("data");
                    content.add(data);
                    NVGenericMap attributes = new NVGenericMap("attributes");
                    data.add("type", "profile");
                    data.add(attributes);

                    for (NVPair nvp : nvPairList.values()) {
                        attributes.add(nvp);
                    }

                    hmci.setContent(GSONUtil.toJSONDefault(content));


                    return hmci;
                }

            };

            NVPairList parameters = new NVPairList("Paramaters", new ArrayList<>());

            parameters.add(params.asNVPair("email"));
            parameters.add(params.asNVPair("first_name"));

            if (params.nameExists("last_name"))
                parameters.add(params.asNVPair("last_name"));


            HTTPAPIEndPoint<NVPairList, NVGenericMap> userAPI = new HTTPAPIEndPoint<NVPairList, NVGenericMap>(config)
                    .setName("UserCollection")
                    .setDescription("Sending user info to klaviyo")
                    .setDataEncoder(encoder)
                    .setDataDecoder(HTTPUtil.NVGM_DECODER)
                    .setRateController(new RateController("klaviyo", "75/min"))
                    .setScheduler(TaskUtil.getDefaultTaskScheduler());

            HTTPCallBack<NVPairList, NVGenericMap> callback = new HTTPCallBack<NVPairList, NVGenericMap>(parameters) {
                @Override
                public void exception(Exception e)
                {
                    if (e instanceof HTTPCallException)
                    {
                        HTTPCallException exception = (HTTPCallException) e;
                        if (exception.getStatusCode().CODE == 409)
                        {
                            System.out.println("Duplicate user " + get());
                            System.out.println(e);
                        }
                    }
                }
                @Override
                public void accept(HTTPAPIResult<NVGenericMap> apiResult)
                {
                    System.out.println(apiResult.getData());
                }
            };



            userAPI.syncCall(callback, null);
            //System.out.println(userAPI.syncCall(parameters));







            //hmci.getHeaders().add("revision", "2023-07-15");



//            System.out.println(config.getAuthorization().toHTTPHeader());
//            System.out.println(HTTPCall.send(config));



        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
        TaskUtil.waitIfBusyThenClose(50);

    }
}
