package io.xlogistx.common.dns;

import org.xbill.DNS.Message;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.SimpleResolver;
import org.zoxweb.shared.net.IPAddress;
import org.zoxweb.shared.util.*;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.LinkedHashMap;

public class DNSRegistrar
    extends RegistrarMap<String, InetAddress, DNSRegistrar>
{
    public static final DataEncoder<String, String> ToDNSEntry = (s) ->{
        s = DataEncoder.StringLower.encode(s);
        if(SUS.isNotEmpty(s))
            return s.endsWith(".") ? s : s + ".";

        return null;
    };


    public static final DataDecoder<String, String> ToDomain = (s) ->{
        s = DataEncoder.StringLower.encode(s);
        if(SUS.isNotEmpty(s))
            return s.endsWith(".") ? s.substring(0, s.length()-1) : s;

        return null;
    };


    public static final DNSRegistrar SINGLETON = new DNSRegistrar();



    private Resolver resolver = null;

    private DNSRegistrar() {
        super(new LinkedHashMap<>());
        keyFilter = ToDNSEntry;
    }


    public DNSRegistrar register(String domain, String ipAddress) throws UnknownHostException {
        return register(domain, InetAddress.getByName(ipAddress));
    }


    public DNSRegistrar register(GetNameValue<String> domainIP) throws UnknownHostException {
        return register(domainIP.getName(), domainIP.getValue());
    }

    public DNSRegistrar register(String domain, InetAddress inet)
    {
        super.register(keyFilter.encode(domain), inet);
        return this;
    }

    public Resolver getResolver() {
        return resolver;
    }

    public DNSRegistrar setResolver(SimpleResolver resolver) {
        this.resolver = resolver;
        return this;
    }

    public DNSRegistrar setResolver(String resolverIP) throws UnknownHostException {
        IPAddress resolverAddress = new IPAddress(resolverIP);
        if(resolverAddress.getPort() == -1)
            resolverAddress.setPort(53);
        this.resolver = new SimpleResolver(new InetSocketAddress(resolverAddress.getInetAddress(), resolverAddress.getPort()));
        return this;
    }


    public Message resolve(Message query) throws IOException {
        return resolver.send(query);
    }


}
