package io.xlogistx.nosneak.scanners;

import io.xlogistx.opsec.OPSecUtil;
import io.xlogistx.opsec.OPSecUtil.RevocationResult;
import io.xlogistx.opsec.OPSecUtil.RevocationStatus;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.zoxweb.server.http.HTTPNIOSocket;
import org.zoxweb.server.http.HTTPURLCallback;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.shared.http.*;
import org.zoxweb.shared.task.ConsumerCallback;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.function.Consumer;

/**
 * NIO-based certificate revocation checker using HTTPURLCallback + HTTPNIOSocket
 * for truly async, event-driven HTTP requests (CRL downloads and OCSP).
 */
public class NIORevocationChecker {

    public static final LogWrapper log = new LogWrapper(NIORevocationChecker.class).setEnabled(false);

    private final HTTPNIOSocket httpNioSocket;
    private final OPSecUtil opsecUtil;

    public NIORevocationChecker(HTTPNIOSocket httpNioSocket) {
        this.httpNioSocket = httpNioSocket;
        this.opsecUtil = OPSecUtil.singleton();
    }

    /**
     * Check certificate revocation using direct callbacks.
     * Tries OCSP first, falls back to CRL.
     *
     * @param cert     the certificate to check
     * @param issuer   the issuer certificate (may be null)
     * @param callback receives the revocation result
     */
    public void checkRevocation(X509Certificate cert, X509Certificate issuer,
                                Consumer<RevocationResult> callback) {
        if (cert == null) {
            callback.accept(RevocationResult.error("NONE", "Certificate is null"));
            return;
        }

        // Try OCSP first if issuer cert is available
        List<String> ocspUrls = opsecUtil.extractOCSPResponderURLs(cert);
        if (issuer != null && !ocspUrls.isEmpty()) {
            checkOCSP(cert, issuer, ocspUrls.get(0), ocspResult -> {
                if (ocspResult.getStatus() != RevocationStatus.ERROR) {
                    callback.accept(ocspResult);
                } else {
                    // OCSP failed, try CRL
                    checkCRL(cert, callback);
                }
            });
            return;
        }

        // No OCSP, try CRL
        checkCRL(cert, callback);
    }

    /**
     * Check certificate via OCSP.
     */
    private void checkOCSP(X509Certificate cert, X509Certificate issuerCert,
                           String ocspUrl, Consumer<RevocationResult> callback) {
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

            // Build POST request
            HTTPMessageConfigInterface hmci = HTTPMessageConfig.buildHMCI(ocspUrl, HTTPMethod.POST, false);
            hmci.setContentType("application/ocsp-request");
            hmci.setContent(ocspReqData);

            HTTPURLCallback huc = new HTTPURLCallback(hmci, new ConsumerCallback<HTTPResponse>() {
                @Override
                public void accept(HTTPResponse response) {
                    callback.accept(parseOCSPResponse(response));
                }

                @Override
                public void exception(Throwable e) {
                    if (log.isEnabled())
                        log.getLogger().info("OCSP request failed: " + e.getMessage());
                    callback.accept(RevocationResult.error("OCSP", "Request failed: " + e.getMessage()));
                }
            });

            httpNioSocket.send(huc);
        } catch (Exception e) {
            if (log.isEnabled())
                log.getLogger().info("OCSP request build failed: " + e.getMessage());
            callback.accept(RevocationResult.error("OCSP", "Failed to build OCSP request: " + e.getMessage()));
        }
    }

    /**
     * Check certificate via CRL.
     */
    private void checkCRL(X509Certificate cert, Consumer<RevocationResult> callback) {
        List<String> crlUrls = opsecUtil.extractCRLDistributionPoints(cert);
        if (crlUrls.isEmpty()) {
            callback.accept(RevocationResult.unknown("NONE", "No CRL distribution points in certificate"));
            return;
        }

        try {
            HTTPURLCallback huc = new HTTPURLCallback(crlUrls.get(0), new ConsumerCallback<HTTPResponse>() {
                @Override
                public void accept(HTTPResponse response) {
                    callback.accept(parseCRLResponse(cert, response));
                }

                @Override
                public void exception(Throwable e) {
                    if (log.isEnabled())
                        log.getLogger().info("CRL request failed: " + e.getMessage());
                    callback.accept(RevocationResult.error("CRL", "Request failed: " + e.getMessage()));
                }
            });

            httpNioSocket.send(huc);
        } catch (Exception e) {
            if (log.isEnabled())
                log.getLogger().info("CRL request failed: " + e.getMessage());
            callback.accept(RevocationResult.error("CRL", "Failed to send CRL request: " + e.getMessage()));
        }
    }

    private RevocationResult parseOCSPResponse(HTTPResponse response) {
        if (!response.isSuccess()) {
            return RevocationResult.error("OCSP", "HTTP error: " + response.getStatus());
        }

        try {
            byte[] body = ((HTTPResponseData) response).getData();
            OCSPResp ocspResp = new OCSPResp(body);
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
            if (log.isEnabled())
                log.getLogger().info("OCSP response parse failed: " + e.getMessage());
            return RevocationResult.error("OCSP", "Failed to parse OCSP response: " + e.getMessage());
        }
    }

    private RevocationResult parseCRLResponse(X509Certificate cert, HTTPResponse response) {
        if (!response.isSuccess()) {
            return RevocationResult.error("CRL", "HTTP error: " + response.getStatus());
        }

        try {
            byte[] body = ((HTTPResponseData) response).getData();
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509CRL crl = (X509CRL) cf.generateCRL(new ByteArrayInputStream(body));

            X509CRLEntry entry = crl.getRevokedCertificate(cert.getSerialNumber());
            if (entry != null) {
                Long revDate = entry.getRevocationDate() != null ? entry.getRevocationDate().getTime() : null;
                String reason = entry.getRevocationReason() != null ?
                        entry.getRevocationReason().name() : "UNSPECIFIED";
                return RevocationResult.revoked("CRL", revDate, reason);
            }

            return RevocationResult.good("CRL");
        } catch (Exception e) {
            if (log.isEnabled())
                log.getLogger().info("CRL parse failed: " + e.getMessage());
            return RevocationResult.error("CRL", "Failed to parse CRL: " + e.getMessage());
        }
    }

    private String getRevocationReasonString(int reason) {
        switch (reason) {
            case 0:
                return "UNSPECIFIED";
            case 1:
                return "KEY_COMPROMISE";
            case 2:
                return "CA_COMPROMISE";
            case 3:
                return "AFFILIATION_CHANGED";
            case 4:
                return "SUPERSEDED";
            case 5:
                return "CESSATION_OF_OPERATION";
            case 6:
                return "CERTIFICATE_HOLD";
            case 8:
                return "REMOVE_FROM_CRL";
            case 9:
                return "PRIVILEGE_WITHDRAWN";
            case 10:
                return "AA_COMPROMISE";
            default:
                return "UNKNOWN(" + reason + ")";
        }
    }

    /**
     * No-op - we don't own the NIOSocket.
     */
    public void shutdown() {
    }
}
