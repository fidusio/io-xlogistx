package io.xlogistx.nosneak.services;

import io.xlogistx.common.dns.DNSRegistrar;
import io.xlogistx.http.NIOHTTPServer;
import io.xlogistx.nosneak.scanners.PQCNIOScanner;
import io.xlogistx.nosneak.scanners.PQCScanOptions;
import org.zoxweb.server.net.NIOSocket;
import org.zoxweb.shared.annotation.EndPointProp;
import org.zoxweb.shared.annotation.ParamProp;
import org.zoxweb.shared.api.APIException;
import org.zoxweb.shared.http.HTTPMethod;
import org.zoxweb.shared.http.HTTPStatusCode;
import org.zoxweb.shared.http.URIScheme;
import org.zoxweb.shared.net.IPAddress;
import org.zoxweb.shared.util.NVGenericMap;
import org.zoxweb.shared.util.ResourceManager;

import java.io.IOException;
import java.net.UnknownHostException;
import java.util.concurrent.CompletableFuture;

public class QDZChecker {



    public QDZChecker() {
        try {
            if(DNSRegistrar.SINGLETON.getResolver() == null) DNSRegistrar.SINGLETON.setResolver(DNSRegistrar.DEFAULT_RESOLVER);
        } catch (UnknownHostException e) {
            e.printStackTrace();
            throw new IllegalArgumentException(e);
        }
    }

    @EndPointProp(methods = {HTTPMethod.GET, HTTPMethod.POST}, name = "check-qdz", uris = "/check-qdz/{domain}/{detailed}")
    public NVGenericMap checkQDZ(@ParamProp(name = "domain") String domain, @ParamProp(name = "detailed", optional = true) boolean detailed) {


        CompletableFuture<NVGenericMap> future = new CompletableFuture<>();

        IPAddress ip = IPAddress.parse(domain);
        if (ip.isPrivateIP())
            throw new APIException("NoSneaking on my private ips: " + ip + " try https://api.xlogistx.io/domain.com[:443 if no port default 443]", HTTPStatusCode.UNAUTHORIZED.CODE);
        if (ip.getPort() == -1)
            ip.setPort(URIScheme.HTTPS.getValue());


        PQCScanOptions options = detailed ? PQCScanOptions.builder()
                .checkRevocation(true)
                .revocationTimeoutMs(10000)
                .enumerateCiphers(true)
                .testProtocolVersions(true)
                .testTLS10(true)
                .testTLS11(true)
                .testSSLv3(false)
                .build() : null;
        PQCNIOScanner scanner = new PQCNIOScanner(ip, result -> {
            //future.whenComplete(result.toNVGenericMap(false), null);
            future.complete(result.toNVGenericMap(true));
        }, options);
        scanner.dnsResolver(DNSRegistrar.SINGLETON);

        scanner.timeoutInSec(5);


        try {
            getNIOSocket().addClientSocket(scanner);
        } catch (IOException e) {
            //e.printStackTrace();
            throw new APIException("remote host error: " + ip + " try https://api.xlogistx.io/domain.com[:443 if no port default 443]", HTTPStatusCode.NOT_FOUND.CODE);
        }

        NVGenericMap response = future.join();


        return response;
    }

    private NIOSocket getNIOSocket() {
        NIOHTTPServer niohttpServer = ResourceManager.lookupResource(ResourceManager.Resource.HTTP_SERVER);
        return niohttpServer.getNIOSocket();
    }
}
