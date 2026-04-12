package io.xlogistx.http.services;

import io.xlogistx.common.data.PropertyContainer;
import io.xlogistx.common.http.HTTPProtocolHandler;
import io.xlogistx.shiro.ShiroUtil;
import org.zoxweb.server.io.UByteArrayOutputStream;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.shared.annotation.EndPointProp;
import org.zoxweb.shared.annotation.ParamProp;
import org.zoxweb.shared.http.HTTPMethod;
import org.zoxweb.shared.http.HTTPStatusCode;
import org.zoxweb.shared.util.*;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public class HTTPWebHooks
        extends PropertyContainer<NVGenericMap>
{

    public final static LogWrapper log = new LogWrapper(HTTPWebHooks.class).setEnabled(true);
    private String signatureKey = null;
    private String baseURL = null;
    private String headerSigName= null;

    @EndPointProp(methods = {HTTPMethod.POST}, name = "web-hooks", uris = "/web-hooks/{service-provider}/{cust-id}")
    public HTTPStatusCode webHook(@ParamProp(name = "service-provider") String provider,
                                  @ParamProp(name = "cust-id") String custId,
                                  @ParamProp(name = "", source = Const.ParamSource.PAYLOAD, optional = false) NVGenericMap payload)
            throws IOException {

        HTTPProtocolHandler hph = ShiroUtil.getFromThreadContext(HTTPProtocolHandler.SESSION_CONTEXT);
        boolean stat = false;
        if (hph != null) {
            if (log.isEnabled()) {
                log.getLogger().info(hph.getRawRequest().getHTTPMessageConfig().getURI());
                log.getLogger().info(hph.getRawRequest().getHTTPMessageConfig().getHeaders().toString());
                log.getLogger().info("raw-content:\n" + hph.getRawRequest().getDataStream().toString());
            }
        }
        if(log.isEnabled()) log.getLogger().info("provider:" + provider + " cust-id:" + custId);
        if(log.isEnabled()) log.getLogger().info("payload: " + payload);

        boolean signValidation = isValid(hph.getRawRequest().getHTTPMessageConfig().getURI(),
                hph.getRawRequest().getDataStream(),
                hph.getRawRequest().getHTTPMessageConfig().getHeaders().getValue(headerSigName));

        if(log.isEnabled()) log.getLogger().info("signValidation: " + signValidation);

        return signValidation ? HTTPStatusCode.OK : HTTPStatusCode.FORBIDDEN;
    }


    public boolean isValid(String notificationUrl, UByteArrayOutputStream rawBody, String headerSignature) {
        if (SUS.isEmpty(headerSignature)) {
            return false;
        }
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(
                    signatureKey.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));

            // IMPORTANT: the signed payload is URL + body concatenated
            //String payload = notificationUrl + rawBody;
            mac.update(baseURL.getBytes(StandardCharsets.UTF_8));
            mac.update(notificationUrl.getBytes(StandardCharsets.UTF_8));
            mac.update(rawBody.getInternalBuffer(), 0, rawBody.size());
            byte[] hash = mac.doFinal();

            //String computed = Base64.getEncoder().encodeToString(hash);
            byte[] computedSignature = SharedBase64.encode(hash);
            if(log.isEnabled()) log.getLogger().info("computedSignature: " + SharedStringUtil.toString(computedSignature) + " " + headerSigName + ": " + headerSignature);
            return MessageDigest.isEqual(
                    computedSignature,
                    headerSignature.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            return false;
        }
    }

    protected void refreshProperties() {
        NVGenericMap nvgm = getProperties();
        if(nvgm != null){
            signatureKey = nvgm.getValue("signature-key");
            baseURL = nvgm.getValue("base-url");
            headerSigName = nvgm.getValue("header-signature");
            log.getLogger().info("signature-key:" + signatureKey);
            log.getLogger().info("base-url:" + baseURL);
            log.getLogger().info("header-signature:" + headerSigName);

        }

    }

}
