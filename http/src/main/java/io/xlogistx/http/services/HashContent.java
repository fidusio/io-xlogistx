package io.xlogistx.http.services;

import io.xlogistx.common.http.HTTPProtocolHandler;
import io.xlogistx.http.EndpointsUtil;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.shared.annotation.EndPointProp;
import org.zoxweb.shared.annotation.ParamProp;
import org.zoxweb.shared.annotation.SecurityProp;
import org.zoxweb.shared.crypto.CryptoConst;
import org.zoxweb.shared.crypto.HashResult;
import org.zoxweb.shared.http.*;
import org.zoxweb.shared.security.SecConst;
import org.zoxweb.shared.util.*;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashContent {

    public final static LogWrapper log = new LogWrapper(HashContent.class).setEnabled(false);

    /**
     * @param hashType
     * @throws IOException
     */
    @EndPointProp(methods = {HTTPMethod.POST, HTTPMethod.GET}, name = "hash-content", uris = "/hash-content/{hash-type}/{format}", partialRequest = true)
    @SecurityProp(authentications = {SecConst.AuthenticationType.ALL}, permissions = "system:hash:content")
    public NVGenericMap hashContent(@ParamProp(name = "hash-type") CryptoConst.HashType hashType,
                                    @ParamProp(name = "format", optional = true) String format)
            throws IOException, NoSuchAlgorithmException {
        if (log.isEnabled()) log.getLogger().info("hash type: " + hashType);
        HTTPProtocolHandler hph = EndpointsUtil.SINGLETON.getProtocolHandler();
        HTTPMessageConfigInterface request = hph.getRequest();


        if (request != null) {
            if (log.isEnabled()) log.getLogger().info("headers: " + request.getHeaders());
            if (SharedStringUtil.contains(request.getContentType(), HTTPMediaType.APPLICATION_OCTET_STREAM, true)) {
                NVGenericMap attachment = hph.getRequest(true).attachment();
                if (log.isEnabled()) log.getLogger().info("attachment: " + attachment);

                byte[] digest = null;
                NamedValue<InputStream> contentAsIS = attachment.getNV(HTTPConst.Token.CONTENT);
                if (log.isEnabled()) log.getLogger().info("NamedValue: " + contentAsIS);
                if (contentAsIS != null) {
                    MessageDigest md = attachment.getValue(hashType.getName());
                    if (md == null) {
                        md = MessageDigest.getInstance(hashType.getName());
                        attachment.build(new NamedValue<>(hashType, md));
                    }
                    if (log.isEnabled()) log.getLogger().info("MessageDigest: " + md);
                    long totalCount = attachment.getValueAsLong("total-hashed", 0);
                    long countProcessed = IOUtil.hashInputStream(md, contentAsIS.getValue(), true);
                    totalCount += countProcessed;
                    attachment.build(new NVLong("total-hashed", totalCount));
                    if(log.isEnabled()) log.getLogger().info("countProcessed: " + countProcessed);

                    if (contentAsIS.getProperties().getValue(HTTPConst.Token.IS_COMPLETED)) {
                        digest = md.digest();

                        if (SUS.isEmpty(format))
                            format = "hex";

                        HashResult hashResult = new HashResult(hashType, digest, totalCount, format);

                        if (log.isEnabled())
                            log.getLogger().info(hashType + " digest: " + SUS.fastBytesToHex(digest) + " total: " + hph.getRequest().getContentLength());
                        NVGenericMap response = new NVGenericMap();
                        GetNameValue<String> id = hph.getRawRequest().getHTTPMessageConfig().getHeaders().getNV(HTTPHeader.X_REQUEST_ID);
                        if (id != null)
                            response.add(id);

                        response.build(hashResult.getProperties());
                        return response;
                    }
                } else if (SharedStringUtil.contains(request.getContentType(), HTTPMediaType.MULTIPART_FORM_DATA, true)) {
                    if (log.isEnabled()) log.getLogger().info("length: " + request.getContent().length);
                }
            }

        }


        return null;
    }
}
