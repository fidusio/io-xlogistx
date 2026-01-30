package io.xlogistx.nosneak.services;

import io.xlogistx.common.dns.DNSRegistrar;
import io.xlogistx.http.NIOHTTPServer;
import io.xlogistx.nosneak.scanners.PQCNIOScanner;
import org.zoxweb.server.net.NIOSocket;
import org.zoxweb.shared.annotation.EndPointProp;
import org.zoxweb.shared.annotation.ParamProp;
import org.zoxweb.shared.api.APIException;
import org.zoxweb.shared.http.HTTPMethod;
import org.zoxweb.shared.http.HTTPStatusCode;
import org.zoxweb.shared.net.IPAddress;
import org.zoxweb.shared.util.NVGenericMap;
import org.zoxweb.shared.util.ResourceManager;

import java.io.IOException;
import java.net.UnknownHostException;
import java.util.concurrent.CompletableFuture;

public class QDZChecker {

    private DNSRegistrar dnsRegistrar;
    public QDZChecker()
    {
        try {
            dnsRegistrar = DNSRegistrar.SINGLETON.setResolver("8.8.8.8");
        } catch (UnknownHostException e) {
            e.printStackTrace();
            throw new IllegalArgumentException(e);
        }
    }

    @EndPointProp(methods = {HTTPMethod.GET}, name = "check-qdz", uris = "/check-qdz/{domain}/{port}/{timeout}")
    public NVGenericMap checkQDZ(@ParamProp(name = "domain") String domain, @ParamProp(name = "port")int port, @ParamProp(name = "timeout", optional = true) int timeout) {


        CompletableFuture<NVGenericMap> future = new CompletableFuture<>();

        IPAddress ip = new IPAddress(domain, port);
        PQCNIOScanner scanner = new PQCNIOScanner(ip, result -> {
            //future.whenComplete(result.toNVGenericMap(false), null);
            future.complete(result.toNVGenericMap(true));
        });
        scanner.dnsResolver(dnsRegistrar);

        scanner.timeoutInSec(5);
        try {
            getNIOSocket().addClientSocket(scanner);
        }
        catch (IOException e) {
            //e.printStackTrace();
            throw new APIException("remote host error: " + ip + " try https://api.xlogistx.io/domain.com/443", HTTPStatusCode.NOT_FOUND.CODE);
        }

        NVGenericMap response = future.join();


        return response;
    }

    private NIOSocket getNIOSocket() {
        NIOHTTPServer niohttpServer = ResourceManager.lookupResource(ResourceManager.Resource.HTTP_SERVER);
        return niohttpServer.getNIOSocket();
    }
}
