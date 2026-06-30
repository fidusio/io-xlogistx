package io.xlogistx.opsec.ssl;

import io.xlogistx.opsec.OPSecUtil;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.net.ssl.*;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import java.io.OutputStream;
import java.io.Writer;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests the SNI-routed, alias-free TLS identity layer end-to-end: self-generated
 * EC + RSA certificates are loaded into an {@link IdentityStore}, served through a
 * BCJSSE {@link SSLContext}, and exercised over a real in-memory SSLEngine TLS 1.2
 * handshake to verify SNI routing, the single-certificate shortcut, classical+
 * coexistence for one host, and validity-on-load enforcement.
 */
public class IdentityStoreTest {

    private static final String KS_PASS = "changeit";
    private static final char[] KS_PASS_CHARS = KS_PASS.toCharArray();

    @TempDir
    Path tmp;

    @BeforeAll
    static void providers() {
        OPSecUtil.SINGLETON.loadProviders(); // BC + BCJSSE + BCPQC
    }

    // ------------------------------------------------------------- the tests

    @Test
    void singleCert_isServedRegardlessOfSni() throws Exception {
        Gen ec = ecCert("alpha.test", validNow());
        IdentityStore store = new IdentityStore(null) // no default host configured
                .addKeyStore(p12("ec", ec.ecKey, ec.cert), "PKCS12", KS_PASS_CHARS);
        store.reload();

        // KeyManager shortcut: a single identity resolves without touching SNI.
        IdentityKeyManager km = store.keyManager();
        String token = km.chooseEngineServerAlias("EC", null, null);
        assertNotNull(token, "single identity must resolve with a null engine");
        assertEquals(store.identities().get(0).token(), token);

        // Over a real handshake, a non-matching SNI still gets the one cert.
        X509Certificate served = handshakeServerCert(store.newSSLContext(), "does-not-match.test");
        assertEquals(ec.cert.getSerialNumber(), served.getSerialNumber());
    }

    @Test
    void sniRouting_selectsCertByHostname() throws Exception {
        Gen ec = ecCert("alpha.test", validNow());
        Gen rsa = rsaCert("beta.test", validNow());
        IdentityStore store = new IdentityStore(null, "alpha.test")
                .addKeyStore(p12("ec", ec.ecKey, ec.cert), "PKCS12", KS_PASS_CHARS)
                .addKeyStore(p12("rsa", rsa.rsaKey, rsa.cert), "PKCS12", KS_PASS_CHARS);
        store.reload();
        SSLContext ctx = store.newSSLContext();

        // SNI beta.test -> RSA/beta cert
        assertEquals(rsa.cert.getSerialNumber(),
                handshakeServerCert(ctx, "beta.test").getSerialNumber());
        // SNI alpha.test -> EC/alpha cert
        assertEquals(ec.cert.getSerialNumber(),
                handshakeServerCert(ctx, "alpha.test").getSerialNumber());
        // No SNI -> configured default (alpha.test) -> EC cert
        assertEquals(ec.cert.getSerialNumber(),
                handshakeServerCert(ctx, null).getSerialNumber());
    }

    @Test
    void sameHost_classicalCoexistence_bothLoadedAndOneServed() throws Exception {
        Gen ec = ecCert("example.test", validNow());
        Gen rsa = rsaCert("example.test", validNow());
        IdentityStore store = new IdentityStore(null, "example.test")
                .addKeyStore(p12("ec", ec.ecKey, ec.cert), "PKCS12", KS_PASS_CHARS)
                .addKeyStore(p12("rsa", rsa.rsaKey, rsa.cert), "PKCS12", KS_PASS_CHARS);
        store.reload();

        assertEquals(2, store.resolveAll("example.test").size(),
                "both EC and RSA identities cover the host");

        X509Certificate served = handshakeServerCert(store.newSSLContext(), "example.test");
        assertTrue(OPSecUtil.SINGLETON.extractDNSNames(served).contains("example.test"),
                "served cert must certify the requested host");
    }

    @Test
    void reload_rejectsExpiredLeaf_andKeepsPreviousIdentities() throws Exception {
        // First load a valid identity.
        Gen good = ecCert("alpha.test", validNow());
        IdentityStore store = new IdentityStore(null, "alpha.test")
                .addKeyStore(p12("good", good.ecKey, good.cert), "PKCS12", KS_PASS_CHARS);
        store.reload();
        assertEquals(1, store.identities().size());
        String liveToken = store.identities().get(0).token();

        // Add an already-expired identity; reload must abort and keep the old set.
        Date[] expired = { new Date(0L), new Date(1000L) }; // 1970
        Gen bad = ecCert("beta.test", expired);
        store.addKeyStore(p12("bad", bad.ecKey, bad.cert), "PKCS12", KS_PASS_CHARS);

        assertThrows(CertificateValidityException.class, store::reload);
        // Previously-serving identity is untouched.
        assertEquals(1, store.identities().size());
        assertEquals(liveToken, store.identities().get(0).token());
    }

    @Test
    void selection_prefersPqcOnlyForPqcCapableClient() throws Exception {
        // One host backed by both a PQC (ML-DSA) and a classical (RSA) identity.
        Gen pqc = pqcCert("example.test", validNow());
        Gen rsa = rsaCert("example.test", validNow());
        Identity pqcId = Identity.of(pqc.pqcKey.getPrivate(), Arrays.asList(pqc.cert));
        Identity rsaId = Identity.of(rsa.rsaKey.getPrivate(), Arrays.asList(rsa.cert));
        List<Identity> matches = Arrays.asList(pqcId, rsaId);

        assertEquals(Identity.KeyClass.PQC, pqcId.keyClass(), "ML-DSA leaf classifies as PQC");
        assertEquals(Identity.KeyClass.CLASSICAL, rsaId.keyClass());

        IdentityKeyManager prefer = new IdentityStore(null).keyManager();              // preferPqc=true (default)
        IdentityKeyManager noPrefer = new IdentityStore(null).setPreferPqc(false).keyManager();

        // PQC-capable client (advertises an ML-DSA signature scheme) -> PQC cert.
        assertSame(pqcId, prefer.select(matches, Arrays.asList("ML-DSA-65", "rsa_pkcs1_sha256")),
                "PQC-capable client should be served the PQC certificate");
        // Classical-only client -> classical cert, no PQC negotiation failure.
        assertSame(rsaId, prefer.select(matches, Arrays.asList("rsa_pkcs1_sha256", "ecdsa_secp256r1_sha256")),
                "classical-only client should be served the classical certificate");
        // preferPqc disabled -> classical even for a PQC-capable client.
        assertSame(rsaId, noPrefer.select(matches, Arrays.asList("ML-DSA-65")),
                "preferPqc=false should serve classical even to a PQC-capable client");
    }

    @Test
    void pemSource_loadsCertAndKey() throws Exception {
        Gen ec = ecCert("pem.test", validNow());
        Path certPem = pem("cert.pem", ec.cert);
        Path keyPem = pem("key.pem", ec.ecKey.getPrivate());

        IdentityStore store = new IdentityStore(null, "pem.test").addPem(certPem, keyPem);
        store.reload();

        assertEquals(1, store.identities().size());
        assertTrue(store.identities().get(0).names().contains("pem.test"));
    }

    // ------------------------------------------------------------- fixtures

    /** Carries a generated cert plus whichever key pair produced it. */
    private static final class Gen {
        final X509Certificate cert;
        KeyPair ecKey;
        KeyPair rsaKey;
        KeyPair pqcKey;
        Gen(X509Certificate cert) { this.cert = cert; }
        BigInteger serial() { return cert.getSerialNumber(); }
    }

    private static Date[] validNow() {
        long now = System.currentTimeMillis();
        return new Date[]{ new Date(now - 3600_000L), new Date(now + 365L * 24 * 3600_000L) };
    }

    private static Gen ecCert(String host, Date[] window) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC", "BC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = g.generateKeyPair();
        Gen gen = new Gen(selfSigned(kp, host, "SHA256withECDSA", window));
        gen.ecKey = kp;
        return gen;
    }

    private static Gen rsaCert(String host, Date[] window) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA", "BC");
        g.initialize(2048);
        KeyPair kp = g.generateKeyPair();
        Gen gen = new Gen(selfSigned(kp, host, "SHA256withRSA", window));
        gen.rsaKey = kp;
        return gen;
    }

    private static Gen pqcCert(String host, Date[] window) throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("ML-DSA-65", "BC").generateKeyPair();
        Gen gen = new Gen(selfSigned(kp, host, "ML-DSA-65", window));
        gen.pqcKey = kp;
        return gen;
    }

    private static X509Certificate selfSigned(KeyPair kp, String host, String sigAlg, Date[] window)
            throws Exception {
        X500Name dn = new X500Name("CN=" + host);
        BigInteger serial = new BigInteger(64, new SecureRandom());
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
                dn, serial, window[0], window[1], dn, kp.getPublic());
        b.addExtension(Extension.subjectAlternativeName, false,
                new GeneralNames(new GeneralName(GeneralName.dNSName, host)));
        ContentSigner signer = new JcaContentSignerBuilder(sigAlg).setProvider("BC").build(kp.getPrivate());
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(b.build(signer));
    }

    /** Write a single-entry PKCS12 keystore to the temp dir and return its path. */
    private Path p12(String name, KeyPair kp, X509Certificate cert) throws Exception {
        KeyStore ks = OPSecUtil.SINGLETON.createKeyStore(name, KS_PASS, kp.getPrivate(), cert);
        Path path = tmp.resolve(name + ".p12");
        try (OutputStream os = Files.newOutputStream(path)) {
            ks.store(os, KS_PASS_CHARS);
        }
        return path;
    }

    private Path pem(String name, Object obj) throws Exception {
        Path path = tmp.resolve(name);
        try (Writer w = Files.newBufferedWriter(path); JcaPEMWriter pw = new JcaPEMWriter(w)) {
            pw.writeObject(obj);
        }
        return path;
    }

    // ------------------------------------------------------------- handshake harness

    private static final ByteBuffer EMPTY = ByteBuffer.allocate(0);

    /** Drive a full TLS 1.2 handshake in-memory and return the leaf the server served. */
    private static X509Certificate handshakeServerCert(SSLContext serverCtx, String clientSni)
            throws Exception {
        SSLEngine server = serverCtx.createSSLEngine();
        server.setUseClientMode(false);
        server.setEnabledProtocols(new String[]{ "TLSv1.2" });

        SSLEngine client = trustAllContext().createSSLEngine();
        client.setUseClientMode(true);
        client.setEnabledProtocols(new String[]{ "TLSv1.2" });
        if (clientSni != null) {
            SSLParameters p = client.getSSLParameters();
            List<SNIServerName> names = new ArrayList<SNIServerName>();
            names.add(new SNIHostName(clientSni));
            p.setServerNames(names);
            client.setSSLParameters(p);
        }

        doHandshake(client, server);

        Certificate[] peer = client.getSession().getPeerCertificates();
        assertTrue(peer != null && peer.length > 0, "server must present a certificate");
        return (X509Certificate) peer[0];
    }

    private static SSLContext trustAllContext() throws Exception {
        TrustManager[] tm = { new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] c, String a) {}
            public void checkServerTrusted(X509Certificate[] c, String a) {}
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        }};
        SSLContext ctx;
        try {
            ctx = SSLContext.getInstance("TLS", OPSecUtil.BC_BCJSSE);
        } catch (Exception e) {
            ctx = SSLContext.getInstance("TLS");
        }
        ctx.init(new KeyManager[0], tm, new SecureRandom());
        return ctx;
    }

    private static void doHandshake(SSLEngine client, SSLEngine server) throws Exception {
        client.beginHandshake();
        server.beginHandshake();
        int net = Math.max(client.getSession().getPacketBufferSize(),
                server.getSession().getPacketBufferSize());
        int app = Math.max(client.getSession().getApplicationBufferSize(),
                server.getSession().getApplicationBufferSize());
        ByteBuffer cNet = ByteBuffer.allocate(net);
        ByteBuffer sNet = ByteBuffer.allocate(net);
        ByteBuffer cApp = ByteBuffer.allocate(app);
        ByteBuffer sApp = ByteBuffer.allocate(app);

        int guard = 0;
        while ((client.getHandshakeStatus() != HandshakeStatus.NOT_HANDSHAKING
                || server.getHandshakeStatus() != HandshakeStatus.NOT_HANDSHAKING)
                && guard++ < 1000) {
            pump(client, server, cNet, sApp);
            pump(server, client, sNet, cApp);
        }
        if (guard >= 1000) {
            throw new IllegalStateException("handshake did not converge");
        }
    }

    /** If {@code from} has data to send, wrap it and feed it into {@code to}. */
    private static void pump(SSLEngine from, SSLEngine to, ByteBuffer net, ByteBuffer peerApp)
            throws Exception {
        runTasks(from);
        if (from.getHandshakeStatus() == HandshakeStatus.NEED_WRAP) {
            net.clear();
            from.wrap(EMPTY, net);
            runTasks(from);
            net.flip();
            while (net.hasRemaining()) {
                peerApp.clear();
                to.unwrap(net, peerApp);
                runTasks(to);
            }
        }
    }

    private static void runTasks(SSLEngine e) {
        Runnable t;
        while ((t = e.getDelegatedTask()) != null) {
            t.run();
        }
    }
}
