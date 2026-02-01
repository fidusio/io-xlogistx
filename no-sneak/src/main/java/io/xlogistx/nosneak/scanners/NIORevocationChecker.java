package io.xlogistx.nosneak.scanners;

import io.xlogistx.opsec.OPSecUtil;
import io.xlogistx.opsec.OPSecUtil.RevocationResult;
import io.xlogistx.opsec.OPSecUtil.RevocationStatus;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.zoxweb.server.logging.LogWrapper;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.CompletableFuture;

/**
 * NIO-based certificate revocation checker using async HTTP.
 * Performs CRL and OCSP checks without blocking.
 */
public class NIORevocationChecker {

    public static final LogWrapper log = new LogWrapper(NIORevocationChecker.class).setEnabled(false);

    private final NIOHttpClient httpClient;
    private final OPSecUtil opsecUtil;

    public NIORevocationChecker(int timeoutMs) {
        this.httpClient = new NIOHttpClient(timeoutMs);
        this.opsecUtil = OPSecUtil.singleton();
    }

    /**
     * Check certificate revocation asynchronously.
     * Tries OCSP first, falls back to CRL.
     *
     * @param cert the certificate to check
     * @param issuerCert the issuer certificate (needed for OCSP)
     * @return CompletableFuture with the revocation result
     */
    public CompletableFuture<RevocationResult> checkRevocationAsync(X509Certificate cert, X509Certificate issuerCert) {
        if (cert == null) {
            return CompletableFuture.completedFuture(
                    RevocationResult.error("NONE", "Certificate is null"));
        }

        // Try OCSP first if issuer cert is available
        List<String> ocspUrls = opsecUtil.extractOCSPResponderURLs(cert);
        if (issuerCert != null && !ocspUrls.isEmpty()) {
            return checkOCSPAsync(cert, issuerCert, ocspUrls.get(0))
                    .thenCompose(result -> {
                        if (result.getStatus() != RevocationStatus.ERROR) {
                            return CompletableFuture.completedFuture(result);
                        }
                        // OCSP failed, try CRL
                        return checkCRLAsync(cert);
                    });
        }

        // No OCSP, try CRL
        return checkCRLAsync(cert);
    }

    /**
     * Check certificate via OCSP asynchronously.
     */
    public CompletableFuture<RevocationResult> checkOCSPAsync(X509Certificate cert,
                                                               X509Certificate issuerCert,
                                                               String ocspUrl) {
        try {
            // Build OCSP request
            DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder()
                    .setProvider("BC").build();
            CertificateID certId = new CertificateID(
                    digCalcProv.get(CertificateID.HASH_SHA1),
                    new JcaX509CertificateHolder(issuerCert),
                    cert.getSerialNumber()
            );

            OCSPReqBuilder reqBuilder = new OCSPReqBuilder();
            reqBuilder.addRequest(certId);
            OCSPReq ocspReq = reqBuilder.build();
            byte[] ocspReqData = ocspReq.getEncoded();

            // Send async HTTP POST
            return httpClient.post(ocspUrl, "application/ocsp-request", ocspReqData)
                    .thenApply(response -> parseOCSPResponse(response));

        } catch (Exception e) {
            if (log.isEnabled()) {
                log.getLogger().info("OCSP request build failed: " + e.getMessage());
            }
            return CompletableFuture.completedFuture(
                    RevocationResult.error("OCSP", "Failed to build OCSP request: " + e.getMessage()));
        }
    }

    /**
     * Check certificate via CRL asynchronously.
     */
    public CompletableFuture<RevocationResult> checkCRLAsync(X509Certificate cert) {
        List<String> crlUrls = opsecUtil.extractCRLDistributionPoints(cert);
        if (crlUrls.isEmpty()) {
            return CompletableFuture.completedFuture(
                    RevocationResult.unknown("NONE", "No CRL distribution points in certificate"));
        }

        // Try first CRL URL
        return checkCRLAsync(cert, crlUrls.get(0));
    }

    /**
     * Check certificate against a specific CRL URL asynchronously.
     */
    public CompletableFuture<RevocationResult> checkCRLAsync(X509Certificate cert, String crlUrl) {
        return httpClient.get(crlUrl)
                .thenApply(response -> parseCRLResponse(cert, response));
    }

    private RevocationResult parseOCSPResponse(NIOHttpClient.HttpResponse response) {
        if (response.isError()) {
            return RevocationResult.error("OCSP", response.getErrorMessage());
        }

        if (!response.isSuccess()) {
            return RevocationResult.error("OCSP", "HTTP error: " + response.getStatusCode());
        }

        try {
            OCSPResp ocspResp = new OCSPResp(response.getBody());
            if (ocspResp.getStatus() != OCSPResp.SUCCESSFUL) {
                return RevocationResult.error("OCSP", "OCSP response status: " + ocspResp.getStatus());
            }

            BasicOCSPResp basicResp = (BasicOCSPResp) ocspResp.getResponseObject();
            if (basicResp == null) {
                return RevocationResult.error("OCSP", "No basic OCSP response");
            }

            for (SingleResp singleResp : basicResp.getResponses()) {
                CertificateStatus certStatus = singleResp.getCertStatus();
                if (certStatus == CertificateStatus.GOOD) {
                    return RevocationResult.good("OCSP");
                } else if (certStatus instanceof RevokedStatus) {
                    RevokedStatus revokedStatus = (RevokedStatus) certStatus;
                    Long revDate = revokedStatus.getRevocationTime() != null ?
                            revokedStatus.getRevocationTime().getTime() : null;
                    String reason = "UNSPECIFIED";
                    if (revokedStatus.hasRevocationReason()) {
                        reason = getRevocationReasonString(revokedStatus.getRevocationReason());
                    }
                    return RevocationResult.revoked("OCSP", revDate, reason);
                } else if (certStatus instanceof UnknownStatus) {
                    return RevocationResult.unknown("OCSP", "Certificate status unknown to OCSP responder");
                }
            }

            return RevocationResult.unknown("OCSP", "No matching response found");
        } catch (Exception e) {
            if (log.isEnabled()) {
                log.getLogger().info("OCSP response parse failed: " + e.getMessage());
            }
            return RevocationResult.error("OCSP", "Failed to parse OCSP response: " + e.getMessage());
        }
    }

    private RevocationResult parseCRLResponse(X509Certificate cert, NIOHttpClient.HttpResponse response) {
        if (response.isError()) {
            return RevocationResult.error("CRL", response.getErrorMessage());
        }

        if (!response.isSuccess()) {
            return RevocationResult.error("CRL", "HTTP error: " + response.getStatusCode());
        }

        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509CRL crl = (X509CRL) cf.generateCRL(new ByteArrayInputStream(response.getBody()));

            X509CRLEntry entry = crl.getRevokedCertificate(cert.getSerialNumber());
            if (entry != null) {
                Long revDate = entry.getRevocationDate() != null ? entry.getRevocationDate().getTime() : null;
                String reason = entry.getRevocationReason() != null ?
                        entry.getRevocationReason().name() : "UNSPECIFIED";
                return RevocationResult.revoked("CRL", revDate, reason);
            }

            return RevocationResult.good("CRL");
        } catch (Exception e) {
            if (log.isEnabled()) {
                log.getLogger().info("CRL parse failed: " + e.getMessage());
            }
            return RevocationResult.error("CRL", "Failed to parse CRL: " + e.getMessage());
        }
    }

    private String getRevocationReasonString(int reason) {
        switch (reason) {
            case 0: return "UNSPECIFIED";
            case 1: return "KEY_COMPROMISE";
            case 2: return "CA_COMPROMISE";
            case 3: return "AFFILIATION_CHANGED";
            case 4: return "SUPERSEDED";
            case 5: return "CESSATION_OF_OPERATION";
            case 6: return "CERTIFICATE_HOLD";
            case 8: return "REMOVE_FROM_CRL";
            case 9: return "PRIVILEGE_WITHDRAWN";
            case 10: return "AA_COMPROMISE";
            default: return "UNKNOWN(" + reason + ")";
        }
    }

    /**
     * Shutdown the checker and release resources.
     */
    public void shutdown() {
        httpClient.shutdown();
    }
}
