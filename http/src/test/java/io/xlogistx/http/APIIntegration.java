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

            HTTPNVGMBiEncoder encoder = null;
            DataDecoder<HTTPResponseData, NVGenericMap> decoder = null;
            ParamUtil.ParamMap params = ParamUtil.parse("=", args);
            HTTPMessageConfigInterface config = null;
            String domain = null;
            HTTPAPIEndPoint<NVGenericMap, NVGenericMap> userAPI = null;

            if (params.nameExists("config"))
            {




                NVGenericMap nvgm = GSONUtil.fromJSONDefault(IOUtil.inputStreamToString(params.stringValue("config")), NVGenericMap.class, true);
                userAPI = HTTPAPIManager.SINGLETON.buildEndPoint(nvgm);
//                System.out.println(nvgm);
//                config = nvgm.getValue("hmci_config");
//                System.out.println(config);
//                domain = nvgm.getValue("domain");
//                NVGenericMap encoderMeta = nvgm.lookup("data_encoder");
//                String metaType = encoderMeta.getValue("meta_type");
//                String json = encoderMeta.getValue("content");
//                encoder = HTTPAPIManager.SINGLETON.buildCodec(encoderMeta);//(HTTPNVGMBiEncoder) GSONUtil.fromJSONDefault(json, Class.forName(metaType));
//                decoder = HTTPAPIManager.SINGLETON.buildCodec(nvgm.lookup("data_decoder"));
//                NVGenericMap nvgmRateController = nvgm.lookup("rate_controller");
//                RateController rateController = null;
//                if (nvgmRateController != null)
//                {
//                    rateController = new RateController(nvgmRateController.getValue("name"), nvgmRateController.getValue("rate"));
//                }
//
//                System.out.println(""+nvgm.lookup("data_encoder.content").getClass());
//                HTTPAPIManager.SINGLETON.buildEndPoint(config, encoder, decoder)
//                        .setRateController(rateController)
//                        .setScheduler(TaskUtil.getDefaultTaskScheduler())
//                        .setDomain(domain);

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
            System.out.println(GSONUtil.toJSONDefault(contentConfig));





            NVGenericMap parameters = new NVGenericMap("Parameters");

            parameters.add(params.asNVPair("email"));
            parameters.add(params.asNVPair("first_name"));

            if (params.nameExists("last_name"))
                parameters.add(params.asNVPair("last_name"));


            if ( encoder == null) {
                encoder = new HTTPNVGMBiEncoder(contentConfig, "data.attributes");
                String json = GSONUtil.toJSONDefault(encoder);
                System.out.println(json);
                encoder = GSONUtil.fromJSONDefault(json, HTTPNVGMBiEncoder.class);
            }

            if (userAPI == null)
                userAPI = HTTPAPIManager.SINGLETON.buildEndPoint(config, encoder, decoder)
                    .setRateController(new RateController("klaviyo", "75/min"))
                    .setScheduler(TaskUtil.getDefaultTaskScheduler())
                    .setDomain(domain);
            System.out.println(GSONUtil.toJSONDefault(new RateController("klavio", "75/min")));
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
