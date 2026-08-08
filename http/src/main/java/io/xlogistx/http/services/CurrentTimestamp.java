package io.xlogistx.http.services;

import org.zoxweb.server.util.DateUtil;
import org.zoxweb.shared.annotation.EndPointProp;
import org.zoxweb.shared.annotation.SecurityProp;
import org.zoxweb.shared.http.*;
import org.zoxweb.shared.security.SecConst;
import org.zoxweb.shared.util.NVGenericMap;
import org.zoxweb.shared.util.SharedStringUtil;

import java.util.Date;


public class CurrentTimestamp {
    private static final byte[] START_DATE = SharedStringUtil.getBytes("{\"start-date\": \"" + DateUtil.DEFAULT_GMT_MILLIS.format(new Date())+ "\"}");

    @EndPointProp(methods = {HTTPMethod.GET}, name = "timestamp", uris = "/timestamp")
    public NVGenericMap timestamp() {
        return new NVGenericMap().build("current_time", DateUtil.DEFAULT_GMT_MILLIS.format(new Date()));
    }

    @EndPointProp(methods = {HTTPMethod.GET}, name = "startDate", uris = "/start-date")
    @SecurityProp(authentications = {SecConst.AuthenticationType.ALL}, permissions = "system:read:start-date")
    public HTTPMessageConfigInterface startDate() {
        HTTPMessageConfigInterface hmci = new HTTPMessageConfig();
        hmci.setContentType(HTTPMediaType.APPLICATION_JSON);
        hmci.setHTTPStatusCode(HTTPStatusCode.OK);
        hmci.setContent(START_DATE);

        return hmci;
    }


}
