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
import java.util.function.Consumer;

/**
 * Non-blocking PQC Scanner using PQCSSLStateMachine.
 * Integrates with NIOSocket for fully async TLS handshake with PQC support.
 */
public class PQCNIOScanner extends TCPSessionCallback {

    public static final LogWrapper log = new LogWrapper(PQCNIOScanner.class).setEnabled(false);

    private final Consumer<PQCScanResult> resultCallback;
    private final long startTime;

    // State machine and config
    private PQCSessionConfig pqcConfig;
    private PQCSSLStateMachine stateMachine;

    // State machine callback - processes state transitions
    private final Consumer<PQCSessionConfig> smCallback = this::onStateTransition;

    // State tracking
    private volatile boolean completed = false;

    /**
     * Create a PQC NIO scanner for the given target
     *
     * @param address        target address (host:port)
     * @param resultCallback callback to receive scan result
     */
    public PQCNIOScanner(IPAddress address, Consumer<PQCScanResult> resultCallback) {
        super(address);
        this.resultCallback = resultCallback;
        this.startTime = System.currentTimeMillis();
    }

    /**
     * Called when TCP connection is established.
     * Initialize PQC state machine and start handshake.
     */
    @Override
    protected void connectedFinished() throws IOException {
        if (completed) return;

        SocketChannel channel = (SocketChannel) getChannel();
        String hostname = getRemoteAddress().getHostName();

        if (log.isEnabled()) {
            log.getLogger().info("Connected to " + hostname + ":" + getRemoteAddress().getPort() +
                    ", initializing PQC state machine");
        }

        // Initialize PQC session config and state machine
        pqcConfig = new PQCSessionConfig(hostname);
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
            Certificate serverCert = tlsClient.getServerCertificate();
            if (serverCert != null && serverCert.getLength() > 0) {
                X509Certificate[] chain = convertCertificateChain(serverCert);
                builder.certificateChain(chain);

                if (chain != null && chain.length > 0) {
                    X509Certificate leafCert = chain[0];
                    String[] certAnalysis = opsec.analyzeCertificatePQC(leafCert);

                    PQCScanResult.SignatureType sigType = parseSignatureType(certAnalysis[0]);
                    builder.certSignature(sigType, certAnalysis[1]);
                    builder.certPublicKey(certAnalysis[2], Integer.parseInt(certAnalysis[3]));
                }
            }

            PQCScanResult result = builder.build();

            if (log.isEnabled()) {
                log.getLogger().info("NIO Scan complete: " + result);
            }

            resultCallback.accept(result);

        } catch (Exception e) {
            if (log.isEnabled()) {
                log.getLogger().info("Error processing handshake result: " + e.getMessage());
            }
            completeWithError("Error processing result: " + e.getMessage());
        } finally {
            IOUtil.close(this);
        }
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
        IOUtil.close(this);
    }


    @Override
    public void exception(Exception e) {
        if (completed) return;

//        if (log.isEnabled())
        {
            log.getLogger().info("Connection exception: " + e.getMessage());
        }

        completeWithError(e.getMessage());
    }

    @Override
    public void close() throws IOException {
        if (!isClosed.getAndSet(true)) {
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
