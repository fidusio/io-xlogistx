package io.xlogistx.nosneak.scanners;

import io.xlogistx.nosneak.scanners.PQCConnectionHelper.PQCHandshakeState;
import io.xlogistx.opsec.OPSecUtil;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.net.common.TCPSessionCallback;
import org.zoxweb.shared.net.IPAddress;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

/**
 * Non-blocking PQC Scanner using PQCSSLStateMachine.
 * Integrates with NIOSocket for fully async TLS handshake with PQC support.
 */
public class PQCNIOScanner extends TCPSessionCallback {

    public static final LogWrapper log = new LogWrapper(PQCNIOScanner.class).setEnabled(false);

    private final Consumer<PQCScanResult> resultCallback;
    private final long startTime;
    private final PQCScanOptions options;

    // State machine and config
    private PQCSessionConfig pqcConfig;
    private PQCSSLStateMachine stateMachine;

    // Revocation checker (uses NIO HTTP for CRL/OCSP)
    private NIORevocationChecker revocationChecker;

    // Blocking scanners for cipher/protocol testing (run in thread pool)
    private CipherSuiteEnumerator cipherEnumerator;
    private ProtocolVersionTester protocolTester;

    // State machine callback - processes state transitions
    private final Consumer<PQCSessionConfig> smCallback = this::onStateTransition;

    // State tracking
    private volatile boolean completed = false;


    /**
     * Create a PQC NIO scanner for the given target with default options.
     *
     * @param address        target address (host:port)
     * @param resultCallback callback to receive scan result
     */
    public PQCNIOScanner(IPAddress address, Consumer<PQCScanResult> resultCallback) {
        this(address, resultCallback, PQCScanOptions.defaults());
    }

    /**
     * Create a PQC NIO scanner for the given target with custom options.
     *
     * @param address        target address (host:port)
     * @param resultCallback callback to receive scan result
     * @param options        scan options controlling optional features
     */
    public PQCNIOScanner(IPAddress address, Consumer<PQCScanResult> resultCallback, PQCScanOptions options) {
        super(address);
        this.resultCallback = resultCallback;
        this.startTime = System.currentTimeMillis();
        this.options = options != null ? options : PQCScanOptions.defaults();
        initializeScanners();
    }

    /**
     * Initialize scanners based on options.
     */
    private void initializeScanners() {
        if (options.isCheckRevocation()) {
            revocationChecker = new NIORevocationChecker(options.getRevocationTimeoutMs());
        }

        if (options.isEnumerateCiphers()) {
            cipherEnumerator = new CipherSuiteEnumerator();
        }

        if (options.isTestProtocolVersions()) {
            protocolTester = new ProtocolVersionTester();
        }
    }

    /**
     * Called when TCP connection is established.
     * Initialize PQC state machine and start handshake.
     */
    @Override
    protected void connectedFinished() throws IOException {
        if (completed) return;

        SocketChannel channel = getChannel();
        String hostname = getRemoteAddress().getHostName();

        if (log.isEnabled()) {
            log.getLogger().info("Connected to " + hostname + ":" + getRemoteAddress().getPort() +
                    ", initializing PQC state machine");
        }

        // Initialize PQC session config and state machine
        pqcConfig = new PQCSessionConfig(getRemoteAddress());
        pqcConfig.channel = channel;
        stateMachine = new PQCSSLStateMachine(pqcConfig);

        // Start handshake via state machine
        stateMachine.publish(PQCHandshakeState.START, smCallback);
    }

    /**
     * Called by state machine on state transitions
     */
    private void onStateTransition(PQCSessionConfig config) {
        // Check if handshake completed
        if (config != null && config.handshakeComplete.get() && !completed) {
            processHandshakeResult();
        }
    }

    /**
     * Called when data is received from NIO.
     * Process through state machine.
     */
    @Override
    public void accept(ByteBuffer buffer) {
        if (completed || pqcConfig == null || stateMachine == null) {
            return;
        }

        if (log.isEnabled() && buffer != null) {
            log.getLogger().info("Received " + buffer.remaining() + " bytes");
        }

        // Process incoming data through state machine
        stateMachine.processIncomingData(buffer, smCallback);
    }

    /**
     * Called when SelectionKey is ready.
     * This handles both read readiness and connection completion.
     */
    @Override
    public void accept(SelectionKey key) {
        if (completed) return;

        try {
            if (key.isReadable() && stateMachine != null) {
                // Read data from channel
                SocketChannel channel = (SocketChannel) key.channel();
                pqcConfig.inNetData.clear();
                int bytesRead = channel.read(pqcConfig.inNetData);

                if (bytesRead == -1) {
                    // Channel closed
                    completeWithError("Connection closed by peer");
                    return;
                }

                if (bytesRead > 0) {
                    pqcConfig.inNetData.flip();
                    stateMachine.processIncomingData(pqcConfig.inNetData, smCallback);
                }
            }
        } catch (Exception e) {
            if (log.isEnabled()) {
                log.getLogger().info("Error processing SelectionKey: " + e.getMessage());
            }
            completeWithError(e.getMessage());
        }
    }

    /**
     * Called by state machine on handshake completion
     */
    private void processHandshakeResult() {
        if (completed) return;
        completed = true;

        long scanTime = System.currentTimeMillis() - startTime;

        try {
            PQCTlsClient tlsClient = pqcConfig.tlsClient;
            String hostname = pqcConfig.getHostname();
            int port = getRemoteAddress().getPort();

            PQCScanResult.Builder builder = PQCScanResult.builder(hostname, port, getID())
                    .scanTimeMs(scanTime)
                    .success(true);

            // TLS Version
            String tlsVersion = tlsClient.getNegotiatedVersionString();
            builder.tlsVersion(tlsVersion);

            // Cipher Suite
            String cipherSuite = tlsClient.getNegotiatedCipherSuiteName();
            builder.cipherSuite(cipherSuite);

            // Key Exchange
            String keyExchangeAlg = tlsClient.getNegotiatedKeyExchangeName();
            if ("UNKNOWN".equals(keyExchangeAlg) || keyExchangeAlg == null) {
                keyExchangeAlg = tlsClient.getKeyExchangeAlgorithm();
            }

            OPSecUtil opsec = OPSecUtil.singleton();
            String kexType = opsec.classifyKeyExchange(keyExchangeAlg);
            PQCScanResult.KeyExchangeType keyExchangeType = parseKeyExchangeType(kexType);
            builder.keyExchange(keyExchangeType, keyExchangeAlg);

            // Certificate analysis
            X509Certificate[] chain = null;
            Certificate serverCert = tlsClient.getServerCertificate();
            if (serverCert != null && serverCert.getLength() > 0) {
                chain = convertCertificateChain(serverCert);
                builder.certificateChain(chain);

                if (chain != null && chain.length > 0) {
                    X509Certificate leafCert = chain[0];
                    String[] certAnalysis = opsec.analyzeCertificatePQC(leafCert);

                    PQCScanResult.SignatureType sigType = parseSignatureType(certAnalysis[0]);
                    builder.certSignature(sigType, certAnalysis[1]);
                    builder.certPublicKey(certAnalysis[2], Integer.parseInt(certAnalysis[3]));

                    // Certificate validity information
                    builder.certValidity(leafCert);

                    // Verify certificate chain signature
                    boolean chainValid = verifyCertificateChain(chain);
                    builder.certChainValid(chainValid);
                }
            }

            // Run additional NIO scans in parallel based on options
            runAdditionalScans(builder, hostname, port, chain);

        } catch (Exception e) {
            if (log.isEnabled()) {
                log.getLogger().info("Error processing handshake result: " + e.getMessage());
            }
            completeWithError("Error processing result: " + e.getMessage());
        }
    }

    /**
     * Run additional scans (revocation, cipher enumeration, protocol testing) in parallel.
     */
    private void runAdditionalScans(PQCScanResult.Builder builder, String hostname, int port,
                                    X509Certificate[] chain) {
        List<CompletableFuture<?>> futures = new ArrayList<>();
        int timeout = options.getEnumerationTimeoutMs();

        // Certificate revocation check (uses NIO HTTP)
        CompletableFuture<OPSecUtil.RevocationResult> revocationFuture = null;
        if (options.isCheckRevocation() && revocationChecker != null && chain != null && chain.length > 0) {
            X509Certificate cert = chain[0];
            X509Certificate issuer = chain.length > 1 ? chain[1] : null;
            revocationFuture = revocationChecker.checkRevocationAsync(cert, issuer);
            futures.add(revocationFuture);
        }

        // Cipher enumeration (blocking, run in thread pool)
        CompletableFuture<CipherSuiteEnumerator.EnumerationResult> cipherFuture = null;
        if (options.isEnumerateCiphers() && cipherEnumerator != null) {
            cipherFuture = CompletableFuture.supplyAsync(() ->
                    cipherEnumerator.enumerate(hostname, port, timeout,
                            options.isIncludeWeakCiphers(),
                            options.isIncludeInsecureCiphers()));
            futures.add(cipherFuture);
        }

        // Protocol version testing (blocking, run in thread pool)
        CompletableFuture<ProtocolVersionTester.VersionTestResult> protocolFuture = null;
        if (options.isTestProtocolVersions() && protocolTester != null) {
            protocolFuture = CompletableFuture.supplyAsync(() ->
                    protocolTester.testAllVersions(hostname, port, timeout,
                            options.isTestSSLv3(),
                            options.isTestTLS10(),
                            options.isTestTLS11()));
            futures.add(protocolFuture);
        }

        // If no additional scans, complete immediately
        if (futures.isEmpty()) {
            completeWithResult(builder.build());
            return;
        }

        // Wait for all futures and combine results
        final CompletableFuture<OPSecUtil.RevocationResult> revFuture = revocationFuture;
        final CompletableFuture<CipherSuiteEnumerator.EnumerationResult> cipFuture = cipherFuture;
        final CompletableFuture<ProtocolVersionTester.VersionTestResult> protFuture = protocolFuture;

        CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
                .orTimeout(options.getConnectTimeoutMs() * 2L, TimeUnit.MILLISECONDS)
                .whenComplete((v, ex) -> {
                    // Apply revocation result
                    if (revFuture != null) {
                        try {
                            OPSecUtil.RevocationResult revResult = revFuture.getNow(null);
                            if (revResult != null) {
                                builder.revocationResult(revResult);
                            }
                        } catch (Exception e) {
                            if (log.isEnabled()) {
                                log.getLogger().info("Failed to get revocation result: " + e.getMessage());
                            }
                        }
                    }

                    // Apply cipher enumeration result
                    if (cipFuture != null) {
                        try {
                            CipherSuiteEnumerator.EnumerationResult cipResult = cipFuture.getNow(null);
                            if (cipResult != null) {
                                builder.supportedCipherSuites(cipResult.getSupportedCiphers());
                                builder.serverCipherPreference(cipResult.hasServerCipherPreference());
                            }
                        } catch (Exception e) {
                            if (log.isEnabled()) {
                                log.getLogger().info("Failed to get cipher result: " + e.getMessage());
                            }
                        }
                    }

                    // Apply protocol version result
                    if (protFuture != null) {
                        try {
                            ProtocolVersionTester.VersionTestResult protResult = protFuture.getNow(null);
                            if (protResult != null && protResult.isSuccess()) {
                                builder.supportedProtocolVersions(protResult.getSupportedVersions());
                                builder.sslv3Supported(protResult.isSslv3Supported());
                                builder.deprecatedProtocolsSupported(protResult.isDeprecatedProtocolsSupported());
                            }
                        } catch (Exception e) {
                            if (log.isEnabled()) {
                                log.getLogger().info("Failed to get protocol result: " + e.getMessage());
                            }
                        }
                    }

                    completeWithResult(builder.build());
                });
    }

    /**
     * Complete the scan with a result and cleanup.
     */
    private void completeWithResult(PQCScanResult result) {
        if (log.isEnabled()) {
            log.getLogger().info("NIO Scan complete: " + result);
        }
        result.scanTimeMs = System.currentTimeMillis() - startTime;
        resultCallback.accept(result);
        shutdownScanners();
        IOUtil.close(this);
    }

    /**
     * Shutdown scanners.
     */
    private void shutdownScanners() {
        if (revocationChecker != null) {
            revocationChecker.shutdown();
        }
        // CipherSuiteEnumerator and ProtocolVersionTester are stateless, no shutdown needed
    }

    /**
     * Convert BC Certificate to Java X509Certificate array
     */
    private X509Certificate[] convertCertificateChain(Certificate bcCert) {
        try {
            TlsCertificate[] tlsCerts = bcCert.getCertificateList();
            X509Certificate[] chain = new X509Certificate[tlsCerts.length];
            CertificateFactory cf = CertificateFactory.getInstance("X.509");

            for (int i = 0; i < tlsCerts.length; i++) {
                byte[] encoded = tlsCerts[i].getEncoded();
                chain[i] = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(encoded));
            }
            return chain;
        } catch (Exception e) {
            if (log.isEnabled()) {
                log.getLogger().info("Failed to convert certificate chain: " + e.getMessage());
            }
            return null;
        }
    }

    /**
     * Verify the certificate chain signatures.
     * Each certificate in the chain should be signed by the next certificate (its issuer).
     *
     * @param chain the certificate chain (leaf first, root last)
     * @return true if chain is valid, false otherwise
     */
    private boolean verifyCertificateChain(X509Certificate[] chain) {
        if (chain == null || chain.length == 0) {
            return false;
        }

        try {
            for (int i = 0; i < chain.length - 1; i++) {
                X509Certificate cert = chain[i];
                X509Certificate issuer = chain[i + 1];

                // Verify that cert was signed by issuer
                cert.verify(issuer.getPublicKey());
            }

            // For the last cert (root or intermediate), we just check it's self-signed
            // or trust it as an anchor (in production, you'd check against a trust store)
            X509Certificate lastCert = chain[chain.length - 1];
            if (lastCert.getSubjectX500Principal().equals(lastCert.getIssuerX500Principal())) {
                // Self-signed - verify signature
                lastCert.verify(lastCert.getPublicKey());
            }
            // If not self-signed, we assume it chains to a trusted root we don't have

            return true;
        } catch (Exception e) {
            if (log.isEnabled()) {
                log.getLogger().info("Certificate chain verification failed: " + e.getMessage());
            }
            return false;
        }
    }

    private PQCScanResult.KeyExchangeType parseKeyExchangeType(String type) {
        if (type == null) return PQCScanResult.KeyExchangeType.UNKNOWN;
        switch (type) {
            case "PQC_HYBRID":
                return PQCScanResult.KeyExchangeType.PQC_HYBRID;
            case "ECDHE":
                return PQCScanResult.KeyExchangeType.ECDHE;
            case "DHE":
                return PQCScanResult.KeyExchangeType.DHE;
            case "RSA":
                return PQCScanResult.KeyExchangeType.RSA;
            default:
                return PQCScanResult.KeyExchangeType.UNKNOWN;
        }
    }

    private PQCScanResult.SignatureType parseSignatureType(String type) {
        if (type == null) return PQCScanResult.SignatureType.UNKNOWN;
        switch (type) {
            case "PQC_SIGNATURE":
                return PQCScanResult.SignatureType.PQC_SIGNATURE;
            case "ECDSA":
                return PQCScanResult.SignatureType.ECDSA;
            case "RSA":
                return PQCScanResult.SignatureType.RSA;
            case "EDDSA":
                return PQCScanResult.SignatureType.EDDSA;
            default:
                return PQCScanResult.SignatureType.UNKNOWN;
        }
    }

    /**
     * Complete with error
     */
    private void completeWithError(String errorMessage) {
        if (completed) return;
        completed = true;

        long scanTime = System.currentTimeMillis() - startTime;

        PQCScanResult result = PQCScanResult.builder(
                        pqcConfig != null ? pqcConfig.getHostname() : getRemoteAddress().getHostName(),
                        getRemoteAddress().getPort(), getID())
                .scanTimeMs(scanTime)
                .errorMessage(errorMessage)
                .build();

        resultCallback.accept(result);
        shutdownScanners();
        IOUtil.close(this);
    }


    @Override
    public void exception(Throwable e) {
        if (completed) return;

        if (log.isEnabled()) {
            log.getLogger().info("Connection exception: " + e.getMessage());
        }

        completeWithError(e.getMessage());
    }

    @Override
    public void close() throws IOException {
        if (!isClosed.getAndSet(true)) {
            shutdownScanners();
            if (stateMachine != null) {
                try {
                    stateMachine.close();
                } catch (Exception ignored) {
                }
            }
            if (pqcConfig != null) {
                pqcConfig.close();
            }
            IOUtil.close(getChannel(), getOutputStream());
        }
    }

    public boolean isCompleted() {
        return completed;
    }

    public PQCSessionConfig getPQCConfig() {
        return pqcConfig;
    }
}
