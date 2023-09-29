package io.xlogistx.http;


import org.zoxweb.server.http.HTTPAPIEndPoint;
import org.zoxweb.server.http.HTTPAPIManager;
import org.zoxweb.server.http.HTTPNVGMBiEncoder;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.shared.http.*;
import org.zoxweb.shared.util.*;

public class APIIntegration
{
    public static void main(String ...args)
    {
        try {


            ParamUtil.ParamMap params = ParamUtil.parse("=", args);
            HTTPMessageConfigInterface config = null;
            if (params.nameExists("config"))
            {
                config = GSONUtil.fromJSONDefault(IOUtil.inputStreamToString(params.stringValue("config")), HTTPMessageConfig.class, true);
            }
            else
            {
                String apiKeyID = params.stringValue("api-key-id");
                String apiKey = params.stringValue("api-key");
                String apiURL = params.stringValue("url");
                String apiURI = params.stringValue("uri");
                String httpMethod = params.stringValue("request");


                config = HTTPMessageConfig.createAndInit(apiURL, apiURI, httpMethod);
                config.setAccept(HTTPMediaType.APPLICATION_JSON);
                config.setContentType(HTTPMediaType.APPLICATION_JSON);
                config.setURLEncodingEnabled(false);
                config.getHeaders().add("revision", "2023-09-15");
                config.setAuthorization(new HTTPAuthorization(apiKeyID, apiKey));
                config.setName("klaviyo.profile");
                config.setDescription("Profile API configuration");
            }



            System.out.println(GSONUtil.toJSONDefault(config, true ));
            NVGenericMap contentConfig = new NVGenericMap();
            NVGenericMap data = new NVGenericMap("data");
            contentConfig.add(data);
            NVGenericMap attributes = new NVGenericMap("attributes");
            data.add("type", "profile");
            data.add(attributes);




//            BiDataEncoder<HTTPMessageConfigInterface, NVGenericMap, HTTPMessageConfigInterface> encoder = new BiDataEncoder<HTTPMessageConfigInterface, NVGenericMap, HTTPMessageConfigInterface>() {
//                @Override
//                public HTTPMessageConfigInterface encode(HTTPMessageConfigInterface hmci, NVGenericMap nvgmParams) {
//                    NVGenericMap content = new NVGenericMap();
//                    NVGenericMap data = new NVGenericMap("data");
//                    content.add(data);
//                    NVGenericMap attributes = new NVGenericMap("attributes");
//                    data.add("type", "profile");
//                    data.add(attributes);
//
//                    for (GetNameValue<?> nvp : nvgmParams.values()) {
//                        attributes.add(nvp);
//                    }
//
//                    String json = GSONUtil.toJSONDefault(content, true);
//                    System.out.println(json);
//
//                    System.out.println(content.lookup("data"));
//                    hmci.setContent(json);
//
//
//                    return hmci;
//                }
//
//            };

            NVGenericMap parameters = new NVGenericMap("Parameters");

            parameters.add(params.asNVPair("email"));
            parameters.add(params.asNVPair("first_name"));

            if (params.nameExists("last_name"))
                parameters.add(params.asNVPair("last_name"));



            HTTPAPIEndPoint<NVGenericMap, NVGenericMap> userAPI = HTTPAPIManager.SINGLETON.buildEndPoint(config, new HTTPNVGMBiEncoder(contentConfig, "data.attributes"), HTTPAPIManager.NVGM_DECODER)
                    .setRateController(new RateController("klaviyo", "75/min"))
                    .setScheduler(TaskUtil.getDefaultTaskScheduler());

            HTTPCallBack<NVGenericMap, NVGenericMap> callback = new HTTPCallBack<NVGenericMap, NVGenericMap>(parameters) {
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
