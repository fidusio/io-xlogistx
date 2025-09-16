package io.xlogistx.http.services;

import io.xlogistx.common.data.PropertyContainer;
import io.xlogistx.common.http.HTTPProtocolHandler;
import io.xlogistx.http.NIOHTTPServer;
import io.xlogistx.shiro.ShiroUtil;
import org.zoxweb.server.io.ByteBufferUtil;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.server.util.DateUtil;
import org.zoxweb.server.util.RuntimeUtil;
import org.zoxweb.shared.annotation.EndPointProp;
import org.zoxweb.shared.annotation.MappedProp;
import org.zoxweb.shared.annotation.ParamProp;
import org.zoxweb.shared.annotation.SecurityProp;
import org.zoxweb.shared.crypto.CryptoConst.AuthenticationType;
import org.zoxweb.shared.http.HTTPMethod;
import org.zoxweb.shared.util.*;

import java.net.InetSocketAddress;
import java.nio.file.FileSystem;
import java.util.Date;

@MappedProp(name = "ping", id = "ping-class")
public class Ping
        extends PropertyContainer<NVGenericMap> {
    private Const.SizeInBytes sib = Const.SizeInBytes.M;

    @EndPointProp(methods = {HTTPMethod.GET}, name = "ping", uris = "/ping/{detailed}")
    @SecurityProp(authentications = {AuthenticationType.ALL}, permissions = "system:ping")
    public NVGenericMap ping(@ParamProp(name = "detailed", optional = true) boolean detailed) {
        NVGenericMap response = new NVGenericMap();
        response.add("message", "App server is up and running.");
        response.add("timestamp", DateUtil.DEFAULT_GMT_MILLIS.format(new Date()));
        FileSystem fs = ResourceManager.lookupResource(ResourceManager.Resource.FILE_SYSTEM);
        NIOHTTPServer niohttpServer = ResourceManager.lookupResource(ResourceManager.Resource.HTTP_SERVER);

        response.build("server-name", niohttpServer.getName()).build("version", niohttpServer.getVersion());

        if (detailed) {
            try {
                HTTPProtocolHandler hph = ShiroUtil.getFromThreadContext(HTTPProtocolHandler.SESSION_CONTEXT);
                InetSocketAddress callAddress = hph.getClientAddress();
                if (callAddress != null) {
                    response.build("caller-address", callAddress.getHostName());
                }
            } catch (Exception e) {

            }
            response.build("subject-id", ShiroUtil.subjectUserID())
                    .build("jdk-version", System.getProperty("java.version"))
                    .build("vm-name", System.getProperty("java.vm.name"))
                    .build("vm-vendor-version", System.getProperty("java.vendor.version"))
                    .build("uptime", Const.TimeInMillis.toString(RuntimeUtil.vmMXBean().getUptime()));
            try {
                response.build("os-uptime", Const.TimeInMillis.toString(RuntimeUtil.linuxUptime()));
            } catch (Exception e) {
                e.printStackTrace();
            }
            response.build("current-thread", Thread.currentThread().getName())
                    .build("os", System.getProperty("os.name") + "," + System.getProperty("os.version")
                            + "," + System.getProperty("os.arch"))
                    .build(new NVInt("byte-buffer-cache", ByteBufferUtil.cacheCount()))
                    .build(new NVInt("ubaos-cache", ByteBufferUtil.baosCount()))
                    .build(new NVLong("total-cached-byte-capacity-kb", Const.SizeInBytes.K.convertBytes(ByteBufferUtil.cacheCapacity())))
                    .build("file-system", fs != null ? fs.toString() : "UNKNOWN")
                    //response.getProperties().add("version", )
                    .build(TaskUtil.info())
                    .build(RuntimeUtil.vmSnapshot(sib))
                    .build((NVGenericMap) ResourceManager.lookupResource(ResourceManager.Resource.SYSTEM_INFO))
                    .build((NVGenericMap) ResourceManager.lookupResource("keep-alive-config"));

            if (niohttpServer != null)
                response.add(niohttpServer.getNIOSocket().getStats());
        }
        return response;
    }

    @Override
    protected void refreshProperties() {
        if (getProperties() != null) {
            String sizeInBytes = getProperties().getValue("size_in_bytes");
            if (sizeInBytes != null) {
                Const.SizeInBytes sibValue = SharedUtil.enumValue(Const.SizeInBytes.class, sizeInBytes);
                if (sibValue != null)
                    sib = sibValue;
            }
        }
    }
}
