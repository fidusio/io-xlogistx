package io.xlogistx.http.services;

import io.xlogistx.common.data.PropertyContainer;
import io.xlogistx.common.http.HTTPProtocolHandler;
import io.xlogistx.shiro.ShiroUtil;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.util.DateUtil;
import org.zoxweb.shared.annotation.EndPointProp;
import org.zoxweb.shared.annotation.ParamProp;
import org.zoxweb.shared.annotation.SecurityProp;
import org.zoxweb.shared.crypto.CryptoConst;
import org.zoxweb.shared.http.*;
import org.zoxweb.shared.io.SharedIOUtil;
import org.zoxweb.shared.util.*;

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Date;

public class BinFileUpload
        extends PropertyContainer<NVGenericMap> {


    private File baseFolder;

    public final static LogWrapper log = new LogWrapper(BinFileUpload.class).setEnabled(true);

    /**
     * @param filename of the binary file
     * @throws IOException in case of errors
     */
    @EndPointProp(methods = {HTTPMethod.POST, HTTPMethod.PUT}, name = "bin-file-upload", uris = "/bin-upload/{filename}")
    @SecurityProp(authentications = {CryptoConst.AuthenticationType.ALL}, permissions = "system:upload:files")
    public NVGenericMap fileUpload(@ParamProp(name = "filename") String filename)
            throws IOException {
        try {
            if (log.isEnabled()) log.getLogger().info("filename: " + filename);
            HTTPProtocolHandler hph = ShiroUtil.getFromThreadContext(HTTPProtocolHandler.SESSION_CONTEXT);
            HTTPMessageConfigInterface request = hph.getRequest();
            if (log.isEnabled())log.getLogger().info(""+request.getHeaders());

            if (request != null) {
                if (log.isEnabled()) log.getLogger().info("headers: " + request.getHeaders());
                if (SharedStringUtil.contains(request.getContentType(), HTTPMediaType.APPLICATION_OCTET_STREAM, true)) {
                    NVGenericMap attachment = hph.getRequest(true).attachment();
                    if (log.isEnabled()) log.getLogger().info("attachment: " + attachment);


                    NamedValue<InputStream> contentAsIS = attachment.getNV(HTTPConst.Token.CONTENT);
                    if (log.isEnabled()) log.getLogger().info("NamedValue: " + contentAsIS);
                    if (contentAsIS != null) {


                        OutputStream fos = attachment.getValue("fos");
                        if (fos == null) {
                            fos = new FileOutputStream(new File(getBaseFolder(), filename));
//                            ProtoSession<?, ?> ps = hph.getConnectionSession();
//                            ps.getAutoCloseables().add(fos);
                            attachment.build(new NamedValue<>("fos", fos));

                            //attachment.build(new NamedValue<>("file", file));
                            attachment.build(new NVLong("start-ts", System.currentTimeMillis()));


                        }
                        if (log.isEnabled()) log.getLogger().info("fos: " + fos);


                        MessageDigest md = attachment.getValue("md");
                        CryptoConst.HashType hashType = CryptoConst.HashType.SHA_256;
                        if (md == null) {
                            try {
                                md = MessageDigest.getInstance(hashType.getName());
                                attachment.build(new NamedValue<>("md", md));
                            } catch (NoSuchAlgorithmException e) {
                                throw new RuntimeException(e);
                            }
                        }

                        if (log.isEnabled()) log.getLogger().info("md: " + fos);

                        long totalCopied = attachment.getValue("total-copied", (long) 0);
                        totalCopied += IOUtil.relayStreams(md, contentAsIS.getValue(), fos, true, false);
                        attachment.build(new NVLong("total-copied", totalCopied));
                        if (log.isEnabled()) log.getLogger().info("total-copied: " + totalCopied);


                        if (contentAsIS.getProperties().getValue(HTTPConst.Token.IS_COMPLETED)) {
                            long delta = System.currentTimeMillis() - (long) attachment.getValue("start-ts");
                            SharedIOUtil.close(fos);
                            byte[] digest = md.digest();
                            String hash = SUS.fastBytesToHex(digest);


                            if (log.isEnabled())
                                log.getLogger().info(hashType + " digest: " + SUS.fastBytesToHex(digest) + " total: " + hph.getRequest().getContentLength());
                            NVGenericMap response = new NVGenericMap();
                            GetNameValue<String> id = hph.getRawRequest().getHTTPMessageConfig().getHeaders().getNV(HTTPHeader.X_REQUEST_ID);
                            if (id != null)
                                response.add(id);

                            response.build("filename", filename)
                                    .build(new NVPair("timestamp", DateUtil.DEFAULT_GMT_MILLIS.format(new Date())))
                                    .build("duration", Const.TimeInMillis.toString(delta))
                                    .build(new NVLong("data-length", totalCopied))
                                    .build(hashType.getName().toLowerCase(), hash);
                            // ex
                            hph.expire();
                            return response;
                        }

                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }

        return null;
    }

    @Override
    protected void refreshProperties() {

        String baseFolderFilename = getProperties().getValue("base_folder");
        baseFolderFilename = SUS.trimOrNull(baseFolderFilename);
        if (baseFolderFilename != null) {
            File folder = new File(baseFolderFilename);
            if (folder.exists() && folder.isDirectory() && folder.canRead())
                this.baseFolder = folder;
        }
    }

    public File getBaseFolder() {
        return baseFolder;
    }
}
