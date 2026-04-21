package io.xlogistx.http.services;

import io.xlogistx.common.http.HTTPProtocolHandler;
import io.xlogistx.shiro.ShiroUtil;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.shared.annotation.EndPointProp;
import org.zoxweb.shared.annotation.ParamProp;
import org.zoxweb.shared.annotation.SecurityProp;
import org.zoxweb.shared.api.APIException;
import org.zoxweb.shared.crypto.CryptoConst;
import org.zoxweb.shared.http.HTTPHeader;
import org.zoxweb.shared.http.HTTPMethod;
import org.zoxweb.shared.util.*;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashContent {

    public final static LogWrapper log = new LogWrapper(HashContent.class).setEnabled(true);

    /**
     * @param hashType
     * @throws IOException
     */
    @EndPointProp(methods = {HTTPMethod.POST, HTTPMethod.GET}, name = "hash-content", uris = "/hash-content/{hash-type}/{format}")
    @SecurityProp(authentications = {CryptoConst.AuthenticationType.ALL}, permissions = "system:hash:content")
    public NVGenericMap hashContent(@ParamProp(name = "hash-type") CryptoConst.HashType hashType,
                                    @ParamProp(name = "format", optional = true) String format)
            throws IOException, NoSuchAlgorithmException {
        log.getLogger().info("hash type: " + hashType);
        HTTPProtocolHandler hph = ShiroUtil.getFromThreadContext(HTTPProtocolHandler.SESSION_CONTEXT);
        byte[] content = hph.getRawRequest().getHTTPMessageConfig().getContent();
        if (content == null)
            content = Const.EMPTY_BYTE_ARRAY;
        MessageDigest md = MessageDigest.getInstance(hashType.getName());
        byte[] digest = md.digest(content);
        if (SUS.isEmpty(format))
            format = "hex";
        String hash;
        switch (format.toLowerCase()) {
            case "base64":
                hash = SharedBase64.encodeAsString(SharedBase64.Base64Type.DEFAULT, digest);
                break;
            case "base64url":
                hash = SharedBase64.encodeAsString(SharedBase64.Base64Type.URL, digest);
                break;
            case "hex":
                hash = SUS.fastBytesToHex(digest);
                break;

                default:
                    throw new APIException("Invalid format: " + format + " expected base64 or base64url or hex/default");

        }

        log.getLogger().info(hashType + " digest: " + SUS.fastBytesToHex(digest) + " total: " + content.length);
        NVGenericMap response = new NVGenericMap();
        GetNameValue<String> id = hph.getRawRequest().getHTTPMessageConfig().getHeaders().getNV(HTTPHeader.X_REQUEST_ID);
        if (id != null)
            response.add(id);

        response.build(new NVInt("length", content.length))
                .build("hash-type", hashType.getName())
                .build("format", format)
                .build("hash", hash);



        return response;
    }
}
