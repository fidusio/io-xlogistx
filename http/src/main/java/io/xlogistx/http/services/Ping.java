package io.xlogistx.http.services;

import io.xlogistx.common.data.PropertyContainer;
import io.xlogistx.common.http.HTTPProtocolHandler;
import io.xlogistx.http.EndpointsUtil;
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
import org.zoxweb.shared.api.APIRegistrar;
import org.zoxweb.shared.security.SecConst.AuthenticationType;
import org.zoxweb.shared.http.HTTPMethod;
import org.zoxweb.shared.util.*;

import java.net.InetSocketAddress;
import java.nio.file.FileSystem;
import java.util.Date;
import java.util.concurrent.atomic.AtomicBoolean;

@MappedProp(name = "ping", id = "ping-class")
public class Ping
        extends PropertyContainer<NVGenericMap> {

    public static final Ping SINGLETON = new Ping();

    private Ping(){}
    private Const.SizeInBytes sib = Const.SizeInBytes.M;

    private final AtomicBoolean isLinux = new AtomicBoolean(true);


    private GetNVProperties extraData = null;

    @EndPointProp(methods = {HTTPMethod.GET}, name = "ping", uris = "/ping/{detailed}")
    @SecurityProp(authentications = {AuthenticationType.ALL}, permissions = "system:ping")
    public NVGenericMap ping(@ParamProp(name = "detailed", optional = true) boolean detailed) {
        NVGenericMap response = new NVGenericMap();
        response.add("message", "App server is up and running.");
        response.add("timestamp", DateUtil.DEFAULT_GMT_MILLIS.format(new Date()));
        FileSystem fs = ResourceManager.lookupResource(ResourceManager.Resource.FILE_SYSTEM);
        NIOHTTPServer niohttpServer = ResourceManager.lookupResource(ResourceManager.Resource.HTTP_SERVER);

        response.build("server-name", niohttpServer.getName()).build("version", niohttpServer.getVersion());

        NVGenericMap apiRegistrar = APIRegistrar.SINGLETON.stats(false);


        if (detailed) {
            try {
                HTTPProtocolHandler hph = EndpointsUtil.SINGLETON.getProtocolHandler();
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
                    .build("uptime", Const.TimeInMillis.toString(RuntimeUtil.vmMXBean().getUptime()))
                    .build(new NVLong("nvbase-count", SharedMetaUtil.SINGLETON.creationCount()));
            if (isLinux.get()) {
                try {
                    response.build("os-uptime", Const.TimeInMillis.toString(RuntimeUtil.linuxUptime()));
                } catch (Exception e) {
                    isLinux.set(false);
                }
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

            if(extraData != null)
                response.build(extraData.getProperties());


            response.add(niohttpServer.getNIOSocket().toProperties(true));
            if (apiRegistrar != null)
                response.add(apiRegistrar);
        }
        return response;
    }


    public void setExtraData(GetNVProperties extraData) {
        this.extraData = extraData;
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
