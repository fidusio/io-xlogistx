package io.xlogistx.opsec.ssl;

import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509ExtendedKeyManager;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * An {@link X509ExtendedKeyManager} with no human-meaningful aliases that routes
 * each handshake to a certificate by SNI host, and — when more than one identity
 * covers the same host — chooses among them by the client's advertised signature
 * algorithms. This lets a single hostname be backed simultaneously by, say, a PQC
 * (ML-DSA) certificate and a classical (RSA/EC) certificate: PQC-capable clients
 * are served the PQC cert, everyone else the classical one, with no negotiation
 * failure for clients that can't verify PQC.
 *
 * Selection order for a host with multiple matches:
 *   1. If the client advertises any PQC signature scheme AND a PQC identity covers
 *      the host, serve the PQC identity (when preferPqc is true).
 *   2. Otherwise serve the first classical identity whose key type the client can
 *      verify given its advertised signature algorithms.
 *   3. Otherwise fall back to the first matching identity (best effort).
 *
 * The returned token is the chosen identity's stable leaf fingerprint, so the
 * follow-up getPrivateKey/getCertificateChain resolve to the same cert even across
 * a concurrent reload().
 *
 * JDK 8 compatible.
 */
public final class IdentityKeyManager extends X509ExtendedKeyManager {

    private final IdentityStore store;
    private final boolean preferPqc;

    IdentityKeyManager(IdentityStore store) {
        this(store, true);
    }

    IdentityKeyManager(IdentityStore store, boolean preferPqc) {
        this.store = store;
        this.preferPqc = preferPqc;
    }

    @Override
    public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
        List<Identity> all = store.identities();
        // Single identity in the store: serve it for every connection, regardless
        // of SNI (or its absence). No point matching when there's only one cert.
        if (all.size() == 1) {
            return all.get(0).token();
        }
        String host = sniHost(engine);
        List<Identity> matches = store.resolveAll(host);
        Identity chosen;
        if (matches.isEmpty()) {
            chosen = store.defaultIdentityPublic();
        } else if (matches.size() == 1) {
            chosen = matches.get(0);
        } else {
            chosen = select(matches, peerSigAlgs(engine));
        }
        return chosen == null ? null : chosen.token();
    }

    /**
     * Choose among multiple same-host identities using the client's advertised
     * signature algorithms. Package-private so the selection policy can be unit
     * tested directly (a real PQC TLS handshake is not yet possible on the JDK).
     */
    Identity select(List<Identity> matches, List<String> peerSigAlgs) {
        boolean clientDoesPqc = advertisesPqc(peerSigAlgs);

        // 1. Prefer PQC when enabled and the client can verify it.
        if (preferPqc && clientDoesPqc) {
            for (int i = 0; i < matches.size(); i++) {
                if (matches.get(i).keyClass() == Identity.KeyClass.PQC) {
                    return matches.get(i);
                }
            }
        }

        // 2. First classical identity the client can verify by key type.
        for (int i = 0; i < matches.size(); i++) {
            Identity id = matches.get(i);
            if (id.keyClass() == Identity.KeyClass.CLASSICAL
                    && clientCanVerify(id, peerSigAlgs)) {
                return id;
            }
        }

        // 3. Any classical match (client didn't advertise sig algs, e.g. older path).
        for (int i = 0; i < matches.size(); i++) {
            if (matches.get(i).keyClass() == Identity.KeyClass.CLASSICAL) {
                return matches.get(i);
            }
        }

        // 4. Last resort: first match (may be PQC even if not advertised).
        return matches.get(0);
    }

    /** Does the client advertise any PQC signature scheme? */
    private static boolean advertisesPqc(List<String> peerSigAlgs) {
        if (peerSigAlgs == null) {
            return false;
        }
        for (int i = 0; i < peerSigAlgs.size(); i++) {
            String s = peerSigAlgs.get(i).toUpperCase(Locale.ROOT);
            if (s.contains("ML-DSA") || s.contains("DILITHIUM")
                    || s.contains("SLH-DSA") || s.contains("SPHINCS")
                    || s.contains("FALCON")) {
                return true;
            }
        }
        return false;
    }

    /**
     * Can the client verify a classical identity's signature given its advertised
     * algorithms? If the client advertised nothing (empty/null), assume yes
     * (legacy behavior). Otherwise require a matching key family.
     */
    private static boolean clientCanVerify(Identity id, List<String> peerSigAlgs) {
        if (peerSigAlgs == null || peerSigAlgs.isEmpty()) {
            return true;
        }
        String alg = id.keyAlgorithm().toUpperCase(Locale.ROOT);
        boolean wantRsa = alg.contains("RSA");
        boolean wantEc = alg.equals("EC") || alg.contains("ECDSA");
        boolean wantEd = alg.contains("ED25519") || alg.contains("ED448") || alg.contains("EDDSA");
        for (int i = 0; i < peerSigAlgs.size(); i++) {
            String s = peerSigAlgs.get(i).toUpperCase(Locale.ROOT);
            if (wantRsa && s.contains("RSA")) {
                return true;
            }
            if (wantEc && (s.contains("ECDSA") || s.contains("EC_"))) {
                return true;
            }
            if (wantEd && (s.contains("ED25519") || s.contains("ED448") || s.contains("EDDSA"))) {
                return true;
            }
        }
        return false;
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        List<Identity> all = store.identities();
        if (all.size() == 1) {
            return all.get(0).token();
        }
        // Non-NIO path: SNI not available without raw-socket inspection -> default.
        Identity id = store.resolve(null);
        return id == null ? null : id.token();
    }

    @Override
    public PrivateKey getPrivateKey(String token) {
        Identity id = store.byToken(token);
        return id == null ? null : id.key();
    }

    @Override
    public X509Certificate[] getCertificateChain(String token) {
        Identity id = store.byToken(token);
        return id == null ? null : id.chain();
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        Set<String> tokens = store.tokens();
        return tokens.toArray(new String[tokens.size()]);
    }

    private static String sniHost(SSLEngine engine) {
        SSLSession hs = engine.getHandshakeSession();
        if (hs instanceof ExtendedSSLSession) {
            List<SNIServerName> names;
            try {
                names = ((ExtendedSSLSession) hs).getRequestedServerNames();
            } catch (UnsupportedOperationException e) {
                return null;
            }
            if (names != null) {
                for (int i = 0; i < names.size(); i++) {
                    SNIServerName sni = names.get(i);
                    if (sni instanceof SNIHostName) {
                        return ((SNIHostName) sni).getAsciiName();
                    }
                }
            }
        }
        return null;
    }

    /** The client's advertised signature algorithms, or null if unavailable. */
    private static List<String> peerSigAlgs(SSLEngine engine) {
        SSLSession hs = engine.getHandshakeSession();
        if (hs instanceof ExtendedSSLSession) {
            try {
                String[] algs = ((ExtendedSSLSession) hs).getPeerSupportedSignatureAlgorithms();
                if (algs != null) {
                    return java.util.Arrays.asList(algs);
                }
            } catch (UnsupportedOperationException e) {
                return null;
            }
        }
        return null;
    }

    // --- client-side unused for a TLS server ---
    @Override public String chooseEngineClientAlias(String[] keyType, Principal[] issuers, SSLEngine engine) { return null; }
    @Override public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) { return null; }
    @Override public String[] getClientAliases(String keyType, Principal[] issuers) { return new String[0]; }
}
