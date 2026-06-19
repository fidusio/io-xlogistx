package io.xlogistx.opsec.ssl;

import io.xlogistx.opsec.OPSecUtil;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * A TLS server identity: a private key, its certificate chain (leaf first), the
 * hostnames the leaf certifies (SAN dNSName + CN fallback), and a stable token
 * (SHA-256 of the leaf's DER) used only at the KeyManager SPI boundary.
 *
 * No alias: identities are matched by {@code names}. Wildcard names
 * ("*.xlogistx.io") match one label deep plus the apex.
 *
 * Name extraction is delegated to {@link OPSecUtil} so the certificate-parsing
 * utilities live in one place. JDK 8 compatible (plain final class, no
 * record/var/pattern-instanceof).
 */
public final class Identity {

    private final PrivateKey key;
    private final X509Certificate[] chain;
    private final List<String> names;
    private final String token;

    public Identity(PrivateKey key, X509Certificate[] chain, List<String> names, String token) {
        if (key == null) {
            throw new IllegalArgumentException("key is null");
        }
        if (chain == null || chain.length == 0) {
            throw new IllegalArgumentException("chain is empty");
        }
        if (token == null || token.isEmpty()) {
            throw new IllegalArgumentException("token is empty");
        }
        this.key = key;
        this.chain = chain.clone();
        this.names = Collections.unmodifiableList(new ArrayList<String>(names));
        this.token = token;
    }

    public PrivateKey key() {
        return key;
    }

    public X509Certificate[] chain() {
        return chain.clone();
    }

    public List<String> names() {
        return names;
    }

    public String token() {
        return token;
    }

    public X509Certificate leaf() {
        return chain[0];
    }

    /** Raw key algorithm of the leaf's public key, e.g. "RSA", "EC", "ML-DSA", "EdDSA". */
    public String keyAlgorithm() {
        String a = leaf().getPublicKey().getAlgorithm();
        return a == null ? "" : a;
    }

    /**
     * Coarse classification used for selection preference:
     *   PQC      - post-quantum signature keys (ML-DSA/Dilithium, SLH-DSA/SPHINCS+, Falcon)
     *   CLASSICAL- RSA / EC / EdDSA / DSA
     *   UNKNOWN  - anything unrecognized
     * Matching is by prefix/substring so OID-derived or vendor-prefixed names
     * (e.g. "Dilithium3", "ML-DSA-65") still classify correctly.
     */
    public KeyClass keyClass() {
        String a = keyAlgorithm().toUpperCase(Locale.ROOT);
        if (a.contains("ML-DSA") || a.contains("DILITHIUM")
                || a.contains("SLH-DSA") || a.contains("SPHINCS")
                || a.contains("FALCON") || a.contains("ML-KEM") /* future */) {
            return KeyClass.PQC;
        }
        if (a.contains("RSA") || a.equals("EC") || a.contains("ECDSA")
                || a.contains("ED25519") || a.contains("ED448") || a.contains("EDDSA")
                || a.equals("DSA")) {
            return KeyClass.CLASSICAL;
        }
        return KeyClass.UNKNOWN;
    }

    /** Coarse key classification for selection preference. */
    public enum KeyClass { PQC, CLASSICAL, UNKNOWN }

    /** Does this identity certify the given SNI host? */
    public boolean matches(String host) {
        if (host == null) {
            return false;
        }
        host = host.toLowerCase(Locale.ROOT);
        for (int i = 0; i < names.size(); i++) {
            String name = names.get(i);
            if (name.startsWith("*.")) {
                String suffix = name.substring(1); // ".xlogistx.io"
                String apex = name.substring(2);   // "xlogistx.io"
                if (host.equals(apex)) {
                    return true;
                }
                // exactly one label deep
                if (host.endsWith(suffix)) {
                    String label = host.substring(0, host.length() - suffix.length());
                    if (label.length() > 0 && label.indexOf('.') < 0) {
                        return true;
                    }
                }
            } else if (host.equals(name)) {
                return true;
            }
        }
        return false;
    }

    /** Build an Identity from a leaf+chain, deriving names and a stable token. */
    public static Identity of(PrivateKey key, List<X509Certificate> chain) {
        if (chain.isEmpty()) {
            throw new IllegalArgumentException("empty chain");
        }
        X509Certificate leaf = chain.get(0);
        // Register every hostname the cert carries: all SAN dNSName entries plus
        // all Subject CNs (a subject may legitimately list more than one).
        List<String> names = new ArrayList<String>(OPSecUtil.SINGLETON.extractDNSNames(leaf));
        for (String cn : OPSecUtil.SINGLETON.extractCNs(leaf)) {
            if (!names.contains(cn)) {
                names.add(cn);
            }
        }
        X509Certificate[] arr = chain.toArray(new X509Certificate[chain.size()]);
        return new Identity(key, arr, names, fingerprint(leaf));
    }

    /** Stable, content-derived token: SHA-256 of the leaf cert's DER encoding. */
    private static String fingerprint(X509Certificate leaf) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return toHex(md.digest(leaf.getEncoded()));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        } catch (CertificateEncodingException e) {
            throw new IllegalStateException("cannot encode leaf certificate", e);
        }
    }

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private static String toHex(byte[] bytes) {
        char[] out = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            out[i * 2] = HEX[v >>> 4];
            out[i * 2 + 1] = HEX[v & 0x0F];
        }
        return new String(out);
    }
}
