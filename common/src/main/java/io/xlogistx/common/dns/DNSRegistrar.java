package io.xlogistx.common.dns;

import org.xbill.DNS.*;
import org.xbill.DNS.Record;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.net.NetUtil;
import org.zoxweb.shared.net.DNSResolverInt;
import org.zoxweb.shared.net.DomainMatcher;
import org.zoxweb.shared.net.IPAddress;
import org.zoxweb.shared.util.*;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;

public class DNSRegistrar
        extends RegistrarMap<String, InetAddress, DNSRegistrar>
        implements DNSResolverInt {
    public static final LogWrapper log = new LogWrapper(DNSRegistrar.class).setEnabled(true);

    public static final String DEFAULT_RESOLVER = "8.8.8.8";
    public static final DataEncoder<String, String> ToDNSEntry = (s) -> {
        s = DataEncoder.StringLower.encode(s);
        if (SUS.isNotEmpty(s))
            return s.endsWith(".") ? s : s + ".";

        return null;
    };

    public static final DataDecoder<String, String> ToDomain = (s) -> {
        s = DataEncoder.StringLower.encode(s);
        if (SUS.isNotEmpty(s))
            return s.endsWith(".") ? s.substring(0, s.length() - 1) : s;

        return null;
    };

    //private final Set<String> sinkHoleDomains = ConcurrentHashMap.newKeySet();
    private final DomainMatcher sinkHoleDomains = new DomainMatcher();


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

    public DNSRegistrar register(String domain, InetAddress inet) {
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
        if (resolverAddress.getPort() == -1)
            resolverAddress.setPort(53);
        this.resolver = new SimpleResolver(new InetSocketAddress(resolverAddress.getInetAddress(), resolverAddress.getPort()));
        return this;
    }


    public Message resolveRemotely(Message query) throws IOException {
        if (resolver != null)
            return resolver.send(query);
        throw new NullPointerException("Resolver is null");
    }

    /**
     * Resolve a domain name to its first IP address.
     * Checks local cache first, then queries upstream resolver.
     *
     * @param domainName the domain to resolve (e.g., "google.com")
     * @return the first IP address, or null if not found
     * @throws IOException if DNS query fails
     */
    public InetAddress resolveRemotely(String domainName) throws IOException {
        return resolveRemotely(domainName, false);
    }


    /**
     * Resolve a domain name to its first IP address.
     * Checks local cache first, then queries upstream resolver.
     *
     * @param domainName the domain to resolve (e.g., "google.com")
     * @return the first IP address, or null if not found
     * @throws IOException if DNS query fails
     */
    @Override
    public IPAddress resolveIPAddress(String domainName) throws IOException {
        InetAddress ret = resolveRemotely(domainName, false);
        if (ret == null)
            throw new UnknownHostException(domainName);

        return new IPAddress(ret.getHostAddress());
    }

    /**
     * Resolve a domain name to its first IP address.
     *
     * @param domainName the domain to resolve
     * @param cacheResult if true, cache the result for future lookups
     * @return the first IP address, or null if not found
     * @throws IOException if DNS query fails
     */
    public InetAddress resolveRemotely(String domainName, boolean cacheResult) throws IOException {
        // Check if input is already a private IP address
        InetAddress privateIP = NetUtil.toPrivateIP(domainName);
        if (privateIP != null) {
            return privateIP;
        }

        // Check local cache first (fast path)
        InetAddress cached = lookup(domainName);
        if (cached != null) {
            return cached;
        }

        // Query upstream resolver
        InetAddress[] results = resolveAll(domainName, cacheResult);
        return results != null && results.length > 0 ? results[0] : null;
    }


    /**
     * Resolve a domain name to all its IP addresses (A records).
     *
     * @param domainName the domain to resolve
     * @return array of IP addresses, or null if not found
     * @throws IOException if DNS query fails
     */
    public InetAddress[] resolveAll(String domainName) throws IOException {
        return resolveAll(domainName, false);
    }

    /**
     * Resolve a domain name to all its IP addresses (A records).
     *
     * @param domainName the domain to resolve
     * @param cacheResult if true, cache the first result for future lookups
     * @return array of IP addresses, or null if not found
     * @throws IOException if DNS query fails
     */
    public InetAddress[] resolveAll(String domainName, boolean cacheResult) throws IOException {
        if (resolver == null) {
            throw new IOException("No DNS resolver configured");
        }

        // Normalize domain name
        String dnsName = ToDNSEntry.encode(domainName);
        if (dnsName == null) {
            return null;
        }

        // Build A record query
        Name name = Name.fromString(dnsName);
        Record question = Record.newRecord(name, Type.A, DClass.IN);
        Message query = Message.newQuery(question);

        // Send query
        Message response = resolver.send(query);
        if (response == null) {
            return null;
        }

        // Extract A records from answer section
        List<InetAddress> addresses = new ArrayList<>();
        List<Record> answers = response.getSection(Section.ANSWER);
        for (Record record : answers) {
            if (record instanceof ARecord) {
                ARecord aRecord = (ARecord) record;
                addresses.add(aRecord.getAddress());
            }
        }

        if (addresses.isEmpty()) {
            return null;
        }

        // Cache first result if requested
        if (cacheResult) {
            register(domainName, addresses.get(0));
        }

        return addresses.toArray(new InetAddress[0]);
    }

    public DNSRegistrar addDomainsToSinkHole(String... domains) {
        for (String domain : domains) {
            domain = ToDNSEntry.encode(domain);
            if (domain != null) {
                sinkHoleDomains.addPattern(domain);
                log.getLogger().info("ADDING " + domain + " in sink hole");
            }
        }
        return this;
    }

    public DNSRegistrar removeDomainsFromSinkHole(String... domains) {
        for (String domain : domains) {
            domain = ToDNSEntry.encode(domain);
            if (domain != null) {
                sinkHoleDomains.removePattern(domain);
            }
        }
        return this;
    }

    public boolean isDomainInSinkHole(String domain) {
        boolean result = false;
        if (SUS.isNotEmpty(domain)) {
            domain = ToDNSEntry.encode(domain);
            if (log.isEnabled()) log.getLogger().info("CHECKING if " + domain + " is in sink hole");
            result = sinkHoleDomains.matches(domain);
            if (result) {
                if (log.isEnabled()) log.getLogger().info(domain + " in sink hole");
            }
        }
        return result;
    }

    public Message sinkHoleResponse(Message query) throws IOException {
        if (query != null && query.getQuestion() != null && query.getQuestion().getName() != null) {
            if (isDomainInSinkHole(query.getQuestion().getName().toString())) {
                return buildSinkholeResponse(query);
            }
        }
        return null;
    }


    private Message buildSinkholeResponse(Message query) throws IOException {
        // Parse the incoming DNS query
        //if(query.getHeader() == null || query.getQuestion() == null || query.getQuestion().getName() == null)
           if(query.getHeader() == null)
            return null;

        // Create response from the query (copies ID, question section, sets QR flag)
        Message response = new Message(query.getHeader().getID());
        Header header = response.getHeader();
        header.setFlag(Flags.QR);  // This is a response
        header.setFlag(Flags.RA);  // Recursion available
        header.setRcode(Rcode.NOERROR);

        // Copy the question section
        Record question = query.getQuestion();
        response.addRecord(question, Section.QUESTION);

        // Add answer: 0.0.0.0 with a short TTL
        Record sinkhole = new ARecord(
                question.getName(),        // same domain they asked for
                DClass.IN,
                60,                       // TTL in seconds
                NetUtil.inetAddressZero(question.getType() == Type.AAAA)
        );
        response.addRecord(sinkhole, Section.ANSWER);

        return response;
    }

}
