package io.xlogistx.http.services;

import io.xlogistx.common.data.PropertyContainer;
import io.xlogistx.common.dns.DNSNIOFactory;
import io.xlogistx.common.dns.DNSNIOProtocol;
import io.xlogistx.common.dns.DNSRegistrar;
import io.xlogistx.http.NIOHTTPServer;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.net.NIOSocket;
import org.zoxweb.shared.annotation.EndPointProp;
import org.zoxweb.shared.annotation.ParamProp;
import org.zoxweb.shared.annotation.SecurityProp;
import org.zoxweb.shared.crypto.CryptoConst;
import org.zoxweb.shared.http.HTTPMethod;
import org.zoxweb.shared.util.GetNameValue;
import org.zoxweb.shared.util.NVGenericMap;
import org.zoxweb.shared.util.ResourceManager;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.Map;

public class DNSCache
        extends PropertyContainer<NVGenericMap> {

    public static final LogWrapper log = new LogWrapper(DNSCache.class).setEnabled(false);


    @EndPointProp(methods = {HTTPMethod.GET, HTTPMethod.POST}, name = "dns-cache-add", uris = "/system/dns/cache/{domain}/{ipv4}")
    @SecurityProp(authentications = {CryptoConst.AuthenticationType.ALL}, permissions = "system:dns:add")
    public NVGenericMap addDomainToCache(@ParamProp(name = "domain") String domain, @ParamProp(name = "ipv4") String ipv4) throws UnknownHostException {
        DNSRegistrar.SINGLETON.register(domain, ipv4);
        if (log.isEnabled()) log.getLogger().info("Added " + domain + " " + ipv4);
        return new NVGenericMap().build("status", "Successful registration").build(domain, ipv4);
    }


    @EndPointProp(methods = {HTTPMethod.GET, HTTPMethod.DELETE}, name = "dns-cache-remove", uris = "/system/dns/remove/{domain}")
    @SecurityProp(authentications = {CryptoConst.AuthenticationType.ALL}, permissions = "system:dns:delete")
    public NVGenericMap deleteDomainFromCache(@ParamProp(name = "domain") String domain) {
        if (log.isEnabled()) log.getLogger().info("remove from cache " + domain);
        DNSRegistrar.SINGLETON.unregister(domain);
        return new NVGenericMap().build("message", "Domain " + domain + " removed");
    }


    @EndPointProp(methods = {HTTPMethod.GET, HTTPMethod.POST}, name = "dns-cache-list", uris = "/system/dns")
    @SecurityProp(authentications = {CryptoConst.AuthenticationType.ALL}, permissions = "system:dns:read")
    public NVGenericMap listCache() {
        NVGenericMap nvgm = new NVGenericMap();


        NVGenericMap values = new NVGenericMap("dns-registrar");
        nvgm.build(values);
        for (Map.Entry<String, InetAddress> entry : DNSRegistrar.SINGLETON.entrySet())
            values.build(DNSRegistrar.ToDomain.decode(entry.getKey()), entry.getValue().getHostAddress());

        return nvgm;
    }


    @Override
    protected void refreshProperties() {
        try {
            NIOHTTPServer server = ResourceManager.lookupResource(ResourceManager.Resource.HTTP_SERVER);
            NIOSocket nioSocket = server.getNIOSocket();
            int port = getProperties().getValue("port", 53);
            String resolver = getProperties().getValue("resolver");
            log.getLogger().info("port: " + port + " resolver: " + resolver);
            DNSRegistrar.SINGLETON.setResolver(resolver);

            boolean scheduled = getProperties().getValue("scheduled", false);
            if (scheduled) {
                if (nioSocket.getScheduler() != null) {
                    DNSNIOFactory.SINGLETON.getProperties().build(GetNameValue.create("scheduler", nioSocket.getScheduler()));
                    log.getLogger().info("We have to setup the scheduler " + DNSNIOFactory.SINGLETON.getProperties().getNV("scheduler"));
                }
            }
            DNSNIOProtocol.log.setEnabled(getProperties().getValue("log-enabled", false));
            nioSocket.addDatagramSocket(new InetSocketAddress(port), DNSNIOFactory.SINGLETON);
            NVGenericMap dnsCache = getProperties().getNV("cache");
            if (dnsCache != null)
                for (GetNameValue<?> gnv : dnsCache.values())
                    DNSRegistrar.SINGLETON.register(gnv.getName(), (String) gnv.getValue());


        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}
