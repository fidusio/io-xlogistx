package io.xlogistx.opsec.ssl;

import io.xlogistx.opsec.OPSecUtil;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Holds TLS server {@link Identity} objects loaded from heterogeneous sources
 * (existing keystores + PEM identities) with no alias concept. Identities are
 * matched by hostname at handshake time. Hot-reloadable: reload() builds a fresh
 * immutable identity list + token map and swaps them in under the write lock.
 *
 * PEM parsing (including PKCS#1/SEC1, encrypted, and PQC keys that the stock JDK 8
 * readers cannot handle) is delegated to {@link OPSecUtil}, which uses
 * BouncyCastle. JDK 8 compatible.
 */
public final class IdentityStore {

    // ------------------------------------------------------------------ sources

    /** Marker for an identity source. */
    public interface Source {}

    /** An existing keystore file (its key entries are imported). */
    public static final class KeyStoreSource implements Source {
        final Path path;
        final String type;
        final char[] password;

        public KeyStoreSource(Path path, char[] password) {
            this(path, "PKCS12", password);
        }

        public KeyStoreSource(Path path, String type, char[] password) {
            this.path = path;
            this.type = type;
            this.password = password != null ? password.clone() : new char[0];
        }
    }

    /** A PEM identity: leaf cert, private key (optionally encrypted), optional chain. */
    public static final class PemSource implements Source {
        final Path certPem;
        final Path keyPem;
        final Path chainPem;   // may be null
        final char[] keyPassword; // may be null for unencrypted keys

        public PemSource(Path certPem, Path keyPem) {
            this(certPem, keyPem, null, null);
        }

        public PemSource(Path certPem, Path keyPem, Path chainPem) {
            this(certPem, keyPem, chainPem, null);
        }

        public PemSource(Path certPem, Path keyPem, Path chainPem, char[] keyPassword) {
            this.certPem = certPem;
            this.keyPem = keyPem;
            this.chainPem = chainPem;
            this.keyPassword = keyPassword != null ? keyPassword.clone() : null;
        }
    }

    // ------------------------------------------------------------------ state

    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
    private final List<Source> sources = new ArrayList<Source>();

    private volatile List<Identity> identities = Collections.emptyList();
    private volatile Map<String, Identity> byToken = Collections.emptyMap();
    // Indexed host -> identity resolver, rebuilt and swapped together with the
    // identity list on each reload(). O(1) exact lookup + small wildcard pass.
    private volatile DomainIdentityMatcher matcher =
            new DomainIdentityMatcher(Collections.<Identity>emptyList());
    private final String defaultHost; // may be null -> first identity is default

    // When true, reload() rejects an expired or not-yet-valid leaf certificate
    // (throws CertificateValidityException) before swapping, leaving the live
    // identities untouched. Default true per the configured policy.
    private volatile boolean validateValidity = true;

    // Optional clock skew tolerance (millis) applied to notBefore/notAfter, to
    // avoid spurious rejections from minor host-clock differences. Default 0.
    private volatile long clockSkewMillis = 0L;

    // When true, and multiple identities cover the same host, the KeyManager
    // serves a PQC identity to clients that advertise a PQC signature scheme,
    // falling back to a classical identity otherwise. Default true.
    private volatile boolean preferPqc = true;

    public IdentityStore() {
        this(null);
    }

    /** @param defaultHost hostname whose identity answers when SNI is absent/unmatched */
    public IdentityStore(String defaultHost) {
        this.defaultHost = defaultHost == null ? null : defaultHost.toLowerCase(Locale.ROOT);
    }

    /**
     * Enable/disable rejection of expired or not-yet-valid leaf certificates on
     * reload(). When enabled (the default), a bad cert aborts the reload via
     * {@link CertificateValidityException} and the currently-serving identities are
     * left in place. Returns this for chaining.
     */
    public IdentityStore setValidateValidity(boolean validate) {
        this.validateValidity = validate;
        return this;
    }

    /** Clock-skew tolerance (millis) applied to validity checks. Default 0. */
    public IdentityStore setClockSkewMillis(long millis) {
        this.clockSkewMillis = Math.max(0L, millis);
        return this;
    }

    /**
     * When multiple identities cover the same hostname, prefer serving a PQC
     * (ML-DSA/SLH-DSA/Falcon) certificate to clients that advertise a PQC signature
     * scheme, falling back to a classical (RSA/EC) certificate for clients that do
     * not. Default true. Set false to always serve classical even when a PQC cert
     * and a PQC-capable client are both present.
     */
    public IdentityStore setPreferPqc(boolean prefer) {
        this.preferPqc = prefer;
        return this;
    }

    // ------------------------------------------------------------------ registration

    public IdentityStore addSource(Source src) {
        if (src == null) {
            throw new NullPointerException("src");
        }
        lock.writeLock().lock();
        try {
            sources.add(src);
        } finally {
            lock.writeLock().unlock();
        }
        return this;
    }

    public IdentityStore addKeyStore(Path path, char[] password) {
        return addSource(new KeyStoreSource(path, password));
    }

    public IdentityStore addKeyStore(Path path, String type, char[] password) {
        return addSource(new KeyStoreSource(path, type, password));
    }

    public IdentityStore addPem(Path certPem, Path keyPem) {
        return addSource(new PemSource(certPem, keyPem));
    }

    public IdentityStore addPem(Path certPem, Path keyPem, Path chainPem) {
        return addSource(new PemSource(certPem, keyPem, chainPem));
    }

    public IdentityStore addPem(Path certPem, Path keyPem, Path chainPem, char[] keyPassword) {
        return addSource(new PemSource(certPem, keyPem, chainPem, keyPassword));
    }

    // ------------------------------------------------------------------ load / reload

    /** (Re)build the identity list from all sources and swap it in atomically. */
    public void reload() throws GeneralSecurityException, IOException {
        List<Source> snapshot;
        lock.readLock().lock();
        try {
            snapshot = new ArrayList<Source>(sources);
        } finally {
            lock.readLock().unlock();
        }

        List<Identity> built = new ArrayList<Identity>();
        for (int i = 0; i < snapshot.size(); i++) {
            Source src = snapshot.get(i);
            if (src instanceof KeyStoreSource) {
                loadKeyStore((KeyStoreSource) src, built);
            } else if (src instanceof PemSource) {
                loadPem((PemSource) src, built);
            }
        }
        if (built.isEmpty()) {
            throw new KeyStoreException("no identities loaded from any source");
        }

        // Validate validity windows BEFORE swapping, so a bad cert aborts the
        // reload and leaves the currently-serving identities untouched.
        if (validateValidity) {
            long now = System.currentTimeMillis();
            for (int i = 0; i < built.size(); i++) {
                checkValidity(built.get(i), now);
            }
        }

        List<Identity> immutable = Collections.unmodifiableList(new ArrayList<Identity>(built));
        Map<String, Identity> tokenMap = new HashMap<String, Identity>(immutable.size() * 2);
        for (int i = 0; i < immutable.size(); i++) {
            Identity id = immutable.get(i);
            tokenMap.put(id.token(), id); // identical leaf from two sources -> last wins
        }
        Map<String, Identity> immutableTokens = Collections.unmodifiableMap(tokenMap);
        DomainIdentityMatcher newMatcher = new DomainIdentityMatcher(immutable);

        lock.writeLock().lock();
        try {
            this.identities = immutable;
            this.byToken = immutableTokens;
            this.matcher = newMatcher;
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Reject a leaf certificate that is expired or not yet valid, applying the
     * configured clock-skew tolerance. Only the leaf is checked here; full chain
     * path validation is the TLS stack's job at handshake time.
     */
    private void checkValidity(Identity id, long now) throws CertificateValidityException {
        X509Certificate leaf = id.leaf();
        long skew = clockSkewMillis;
        long notBefore = leaf.getNotBefore().getTime();
        long notAfter = leaf.getNotAfter().getTime();
        String subject = leaf.getSubjectX500Principal().getName();

        if (now + skew < notBefore) {
            throw new CertificateValidityException(
                    "certificate not yet valid (notBefore=" + leaf.getNotBefore()
                            + ", names=" + id.names() + ", subject=" + subject + ")");
        }
        if (now - skew > notAfter) {
            throw new CertificateValidityException(
                    "certificate expired (notAfter=" + leaf.getNotAfter()
                            + ", names=" + id.names() + ", subject=" + subject + ")");
        }
    }

    private void loadKeyStore(KeyStoreSource src, List<Identity> out)
            throws GeneralSecurityException, IOException {
        KeyStore in = KeyStore.getInstance(src.type);
        InputStream is = Files.newInputStream(src.path);
        try {
            in.load(is, src.password);
        } finally {
            is.close();
        }
        Enumeration<String> aliases = in.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement(); // source alias: read, then discarded
            if (!in.isKeyEntry(alias)) {
                continue;
            }
            Key key = in.getKey(alias, src.password);
            if (!(key instanceof PrivateKey)) {
                continue;
            }
            Certificate[] chain = in.getCertificateChain(alias);
            if (chain == null || chain.length == 0) {
                continue;
            }
            List<X509Certificate> x = new ArrayList<X509Certificate>(chain.length);
            for (int i = 0; i < chain.length; i++) {
                if (chain[i] instanceof X509Certificate) {
                    x.add((X509Certificate) chain[i]);
                }
            }
            if (!x.isEmpty()) {
                out.add(Identity.of((PrivateKey) key, x));
            }
        }
    }

    private void loadPem(PemSource src, List<Identity> out)
            throws GeneralSecurityException, IOException {
        List<X509Certificate> chain = new ArrayList<X509Certificate>(
                OPSecUtil.SINGLETON.readCertificates(src.certPem.toFile()));
        if (src.chainPem != null) {
            chain.addAll(OPSecUtil.SINGLETON.readCertificates(src.chainPem.toFile()));
        }
        if (chain.isEmpty()) {
            throw new KeyStoreException("no certificates in " + src.certPem);
        }
        PrivateKey priv = OPSecUtil.SINGLETON.readPrivateKey(src.keyPem.toFile(), src.keyPassword);
        out.add(Identity.of(priv, chain));
    }

    // ------------------------------------------------------------------ access / routing

    public List<Identity> identities() {
        return identities; // already immutable
    }

    /** Look up an identity by its stable token (leaf SHA-256). Null if not loaded. */
    public Identity byToken(String token) {
        return token == null ? null : byToken.get(token);
    }

    /** All current identity tokens. */
    public Set<String> tokens() {
        return byToken.keySet();
    }

    /** Resolve by SNI host; null/unmatched -> default identity. */
    public Identity resolve(String host) {
        Identity hit = host != null ? matcher.resolveFirst(host) : null;
        return hit != null ? hit : defaultIdentity(identities);
    }

    /**
     * All identities whose certificate covers {@code host}, in load order. Used by
     * the KeyManager to choose among same-host identities by the client's offered
     * signature algorithms (e.g. a PQC cert and a classical cert for one name).
     * Empty if none match.
     */
    public List<Identity> resolveAll(String host) {
        return matcher.resolveAll(host);
    }

    /** The configured default identity (SNI absent/unmatched). */
    public Identity defaultIdentityPublic() {
        return defaultIdentity(identities);
    }

    private Identity defaultIdentity(List<Identity> list) {
        if (list.isEmpty()) {
            throw new IllegalStateException("no identities loaded");
        }
        if (defaultHost != null) {
            Identity d = matcher.resolveFirst(defaultHost);
            if (d != null) {
                return d;
            }
        }
        return list.get(0);
    }

    /** A KeyManager that routes by SNI over this store's identities. */
    public IdentityKeyManager keyManager() {
        return new IdentityKeyManager(this, preferPqc);
    }

    /**
     * SSLContext wired to the routing KeyManager. Built from the BouncyCastle JSSE
     * provider (BCJSSE) when available — it supports TLS 1.3 on JDK 8 and PQC
     * signature schemes, neither of which the stock SunJSSE provider offers on
     * JDK 8 — falling back to the platform default provider otherwise. The BC
     * providers are ensured installed via {@link OPSecUtil#loadProviders()}.
     */
    public SSLContext newSSLContext() throws GeneralSecurityException {
        OPSecUtil.SINGLETON.loadProviders();
        SSLContext ctx;
        try {
            ctx = SSLContext.getInstance("TLS", OPSecUtil.BC_BCJSSE);
        } catch (GeneralSecurityException e) {
            ctx = SSLContext.getInstance("TLS"); // platform default
        }
        ctx.init(new KeyManager[]{ keyManager() }, null, null);
        return ctx;
    }

    /** Diagnostics: each identity's served names. */
    public List<List<String>> report() {
        List<List<String>> out = new ArrayList<List<String>>();
        List<Identity> list = identities;
        for (int i = 0; i < list.size(); i++) {
            out.add(list.get(i).names());
        }
        return out;
    }

    /**
     * The earliest notAfter across all currently-loaded leaf certificates, in epoch
     * millis, or Long.MAX_VALUE if no identities are loaded. The app can poll this
     * to decide when to fetch a renewed cert and call reload().
     */
    public long earliestExpiryMillis() {
        List<Identity> list = identities;
        long min = Long.MAX_VALUE;
        for (int i = 0; i < list.size(); i++) {
            long exp = list.get(i).leaf().getNotAfter().getTime();
            if (exp < min) {
                min = exp;
            }
        }
        return min;
    }

    /**
     * True if any currently-loaded leaf expires within the given number of millis
     * from now. Convenience for an app-driven "should I renew yet?" check.
     */
    public boolean expiresWithin(long millisFromNow) {
        return earliestExpiryMillis() - System.currentTimeMillis() <= millisFromNow;
    }
}
