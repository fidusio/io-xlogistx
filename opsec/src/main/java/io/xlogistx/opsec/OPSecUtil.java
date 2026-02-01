package io.xlogistx.opsec;


import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.channel.ClientChannel;
import org.apache.sshd.client.channel.ClientChannelEvent;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.keyprovider.FileKeyPairProvider;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.util.io.pem.PemReader;
import org.zoxweb.server.io.UByteArrayOutputStream;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.security.CryptoUtil;
import org.zoxweb.server.security.SecUtil;
import org.zoxweb.shared.crypto.CryptoConst;
import org.zoxweb.shared.security.SShURI;
import org.zoxweb.shared.security.SecTag;
import org.zoxweb.shared.util.*;

import javax.crypto.*;
import java.io.*;
import java.math.BigInteger;
import java.net.URI;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;


public class OPSecUtil {
//    static {
//        java.util.logging.Logger.getLogger("org.bouncycastle.jsse")
//                .setLevel(java.util.logging.Level.SEVERE);
//    }

    public static final LogWrapper log = new LogWrapper(OPSecUtil.class).setEnabled(false);

    public static final String BC_PROVIDER = "BC";
    public static final String BC_CKD_PROVIDER = "BCPQC";
    public static final String BC_BCJSSE = "BCJSSE";
    public static final String CK_NAME = "KYBER";
    public static final String CD_NAME = "DILITHIUM";

    // OID Constants for certificate extensions
    public static final String OID_CRL_DISTRIBUTION_POINTS = "2.5.29.31";
    public static final String OID_AUTHORITY_INFO_ACCESS = "1.3.6.1.5.5.7.1.1";
    public static final String OID_OCSP = "1.3.6.1.5.5.7.48.1";
    public static final String OID_CA_ISSUERS = "1.3.6.1.5.5.7.48.2";
    // TLS 1.3 cipher suites (always AEAD)
    public static final int[] ALL_TLS13_CIPHERS = {
            CipherSuite.TLS_AES_256_GCM_SHA384,
            CipherSuite.TLS_AES_128_GCM_SHA256,
            CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
            CipherSuite.TLS_AES_128_CCM_SHA256,
            CipherSuite.TLS_AES_128_CCM_8_SHA256
    };

    // TLS 1.2 strong cipher suites (GCM, ChaCha20)
    public static final int[] ALL_TLS12_STRONG = {
            // ECDHE with ECDSA
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            // ECDHE with RSA
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            // DHE with RSA
            CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    };

    // TLS 1.2 weak cipher suites (CBC modes, older ciphers)
    public static final int[] ALL_TLS12_WEAK = {
            // ECDHE with CBC (acceptable but not ideal)
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            // DHE with CBC
            CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
            CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
            CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
            CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
            // RSA key exchange (no forward secrecy)
            CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256,
            CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
            CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
            CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
            // 3DES (weak)
            CipherSuite.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
            CipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
            CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
    };

    // Insecure cipher suites (should not be used)
    public static final int[] ALL_TLS12_INSECURE = {
            // NULL encryption
            CipherSuite.TLS_RSA_WITH_NULL_SHA256,
            CipherSuite.TLS_RSA_WITH_NULL_SHA,
            CipherSuite.TLS_RSA_WITH_NULL_MD5,
            // RC4
            CipherSuite.TLS_RSA_WITH_RC4_128_SHA,
            CipherSuite.TLS_RSA_WITH_RC4_128_MD5,
            // Anonymous (no authentication)
            CipherSuite.TLS_DH_anon_WITH_AES_256_GCM_SHA384,
            CipherSuite.TLS_DH_anon_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_DH_anon_WITH_AES_256_CBC_SHA256,
            CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA256,
    };

    /**
     * Certificate revocation status
     */
    public enum RevocationStatus {
        /** Certificate is not revoked */
        GOOD,
        /** Certificate is revoked */
        REVOKED,
        /** Revocation status could not be determined */
        UNKNOWN,
        /** Error occurred during revocation check */
        ERROR
    }

    /**
     * Result of a certificate revocation check
     */
    public static class RevocationResult {
        private final RevocationStatus status;
        private final String method;          // "OCSP", "CRL", or "NONE"
        private final String errorMessage;
        private final Long revocationDate;    // null if not revoked
        private final String revocationReason; // CRL reason code if revoked

        public RevocationResult(RevocationStatus status, String method, String errorMessage,
                               Long revocationDate, String revocationReason) {
            this.status = status;
            this.method = method;
            this.errorMessage = errorMessage;
            this.revocationDate = revocationDate;
            this.revocationReason = revocationReason;
        }

        public static RevocationResult good(String method) {
            return new RevocationResult(RevocationStatus.GOOD, method, null, null, null);
        }

        public static RevocationResult revoked(String method, Long revocationDate, String reason) {
            return new RevocationResult(RevocationStatus.REVOKED, method, null, revocationDate, reason);
        }

        public static RevocationResult unknown(String method, String message) {
            return new RevocationResult(RevocationStatus.UNKNOWN, method, message, null, null);
        }

        public static RevocationResult error(String method, String message) {
            return new RevocationResult(RevocationStatus.ERROR, method, message, null, null);
        }

        public RevocationStatus getStatus() { return status; }
        public String getMethod() { return method; }
        public String getErrorMessage() { return errorMessage; }
        public Long getRevocationDate() { return revocationDate; }
        public String getRevocationReason() { return revocationReason; }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder("RevocationResult{status=").append(status);
            sb.append(", method=").append(method);
            if (errorMessage != null) sb.append(", error=").append(errorMessage);
            if (revocationDate != null) sb.append(", date=").append(new java.util.Date(revocationDate));
            if (revocationReason != null) sb.append(", reason=").append(revocationReason);
            return sb.append("}").toString();
        }
    }

    public enum KeyUsageType
            implements GetNameValue<KeyUsage> {
        DIGITAL_SIGNATURE("digitalSignature", new KeyUsage(KeyUsage.digitalSignature)),
        NON_REPUDIATION("nonRepudiation", new KeyUsage(KeyUsage.nonRepudiation)),
        KEY_ENCIPHERMENT("keyEncipherment", new KeyUsage(KeyUsage.keyEncipherment)),
        DATA_ENCIPHERMENT("dataEncipherment", new KeyUsage(KeyUsage.dataEncipherment)),
        KEY_AGREEMENT("keyAgreement", new KeyUsage(KeyUsage.keyAgreement)),
        KEY_CERT_SIGN("keyCertSign", new KeyUsage(KeyUsage.keyCertSign)),
        CRL_SIGN("cRLSign", new KeyUsage(KeyUsage.cRLSign)),
        ENCIPHER_ONLY("encipherOnly", new KeyUsage(KeyUsage.encipherOnly)),
        DECIPHER_ONLY("decipherOnly", new KeyUsage(KeyUsage.decipherOnly)),
        ;

        private final String name;
        private final KeyUsage keyUsage;

        KeyUsageType(String name, KeyUsage keyUsage) {
            this.name = name;
            this.keyUsage = keyUsage;
        }

        /**
         * @return the name of the object
         */
        @Override
        public String getName() {
            return name;
        }

        /**
         * Returns the value.
         *
         * @return typed value
         */
        @Override
        public KeyUsage getValue() {
            return keyUsage;
        }

//        public int bitsPadUsage() {
//            return keyUsage.getPadBits();
//        }

        public static KeyUsageType lookup(String name) {
            return SharedUtil.lookupTypedEnum(KeyUsageType.values(), name);
        }
    }


//    private final static Provider BC_PROVIDER = new BouncyCastleProvider();
//    private static Provider BC_CHRYSTAL_PROVIDER = new BouncyCastlePQCProvider();

    public final static OPSecUtil SINGLETON = new OPSecUtil();


    //private final static AtomicBoolean init = new AtomicBoolean(false);

    private OPSecUtil() {

        java.util.logging.Logger bcLogger = java.util.logging.Logger.getLogger("org.bouncycastle");
        bcLogger.setLevel(java.util.logging.Level.SEVERE);
        bcLogger.setUseParentHandlers(false);  // Prevents parent loggers from handling

        loadProviders();
        SecUtil.addCredentialHasher(new ArgonPasswordHasher());


    }


    public static OPSecUtil singleton() {
        return SINGLETON;
    }

    public synchronized void reloadProviders() {
        boolean stat = SecUtil.removeProvider(BC_CKD_PROVIDER);
        log.getLogger().info("Provider " + BC_CKD_PROVIDER + " removed: " + stat);
        stat = SecUtil.removeProvider(BC_PROVIDER);
        log.getLogger().info("Provider " + BC_PROVIDER + " removed: " + stat);
        stat = SecUtil.removeProvider(BC_BCJSSE);
        log.getLogger().info("Provider " + BC_BCJSSE + " removed: " + stat);

        loadProviders();
    }

    public synchronized void loadProviders() {

        if (SecUtil.getProvider(BC_PROVIDER) == null) {
            Provider prov = new BouncyCastleProvider();
            SecUtil.addProviderAt(prov, 1);
//            SecUtil.addProvider(prov);
            checkProviderExists(BC_PROVIDER);
        }

        if (SecUtil.getProvider(BC_BCJSSE) == null) {
            Provider prov = new BouncyCastleJsseProvider();
            SecUtil.addProviderAt(prov, 2);
//            SecUtil.addProvider(prov);
            checkProviderExists(BC_BCJSSE);
            SecTag.REGISTRAR.registerValue(new SecTag(BC_BCJSSE, SecTag.TagID.X509));
            SecTag.REGISTRAR.registerValue(new SecTag(BC_BCJSSE, SecTag.TagID.TLS));
        }
        if (SecUtil.getProvider(BC_CKD_PROVIDER) == null) {
            Provider prov = new BouncyCastlePQCProvider();
            SecUtil.addProvider(prov);
            checkProviderExists(BC_CKD_PROVIDER);
        }
    }

    private static void checkProviderExists(String providerName) {
        Provider provider = SecUtil.getProvider(providerName);
        if (provider != null)
            log.getLogger().info("Provider Loaded: " + SUS.toCanonicalID('-', provider.getName(), provider.getVersion(), provider.getInfo()));
        else
            log.getLogger().info("**Warning**: Provider " + providerName + " NOT Loaded ");
    }

    public X500Name createSubject(String attributes) {
        X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);


        String[] attrs = attributes.split(",");
        for (String attr : attrs) {
            String[] parts = attr.split("=");
            String type = parts[0].trim();
            String value = parts[1].trim();

            switch (type.toUpperCase()) {
                case "CN":
                    nameBuilder.addRDN(BCStyle.CN, value);
                    break;
                case "O":
                    nameBuilder.addRDN(BCStyle.O, value);
                    break;
                case "OU":
                    nameBuilder.addRDN(BCStyle.OU, value);
                    break;
                case "L":
                    nameBuilder.addRDN(BCStyle.L, value);
                    break;
                case "ST":
                    nameBuilder.addRDN(BCStyle.ST, value);
                    break;
                case "C":
                    nameBuilder.addRDN(BCStyle.C, value);
                    break;
                case "E":
                    nameBuilder.addRDN(BCStyle.E, value);
                    break;
                case "UID":
                    nameBuilder.addRDN(BCStyle.UID, value);
                    break;
                default:
                    throw new IllegalArgumentException("Unsupported attribute type: " + type);
            }
        }

        return nameBuilder.build();
    }


    public KeyPair generateKeyPair(String keyType, String provider)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        return CryptoUtil.generateKeyPair(keyType, provider, SecUtil.defaultSecureRandom());
    }

    public X509CertificateHolder generateIntermediateCA(
            PrivateKey caPrivateKey, X509CertificateHolder caCert,
            String subjectDN, KeyPair intermediateKeyPair, int days) throws Exception {

        long now = System.currentTimeMillis();
        Date notBefore = new Date(now);
        Date notAfter = new Date(now + days * 24L * 60 * 60 * 1000);
        X500Name issuer = caCert.getSubject();
        BigInteger serial = BigInteger.valueOf(now);

        X500Name subject = new X500Name("CN=" + subjectDN);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer,
                serial,
                notBefore, notAfter,
                subject,
                intermediateKeyPair.getPublic()
        );

        // Add CA:TRUE extension
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
                .setProvider("BC").build(caPrivateKey);

        return builder.build(signer);
    }

    public X509CertificateHolder generateSignedCertificate(
            PrivateKey issuerKey, X509CertificateHolder issuerCert,
            String subjectDN, KeyPair subjectKeyPair, int days, boolean isCA) throws Exception {

        long now = System.currentTimeMillis();
        Date notBefore = new Date(now);
        Date notAfter = new Date(now + Const.TimeInMillis.DAY.mult(days));
        BigInteger serial = BigInteger.valueOf(now);

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuerCert.getSubject(),
                serial,
                notBefore, notAfter,
                new X500Name(subjectDN),
                subjectKeyPair.getPublic()
        );

        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCA));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
                .setProvider("BC").build(issuerKey);

        return builder.build(signer);
    }

    /**
     * Sign a CSR to produce a certificate.
     *
     * @param csr            the certificate signing request
     * @param caPrivateKey   the CA's private key for signing
     * @param caCert         the CA's certificate (issuer)
     * @param duration       validity duration (e.g., "365d", "1y")
     * @param copyExtensions if true, copy extensions from the CSR to the certificate
     * @return the signed X509Certificate
     */
    public X509Certificate signCSR(PKCS10CertificationRequest csr,
                                   PrivateKey caPrivateKey,
                                   X509Certificate caCert,
                                   String duration,
                                   boolean copyExtensions) throws Exception {
        // Extract public key from CSR
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(BC_PROVIDER);
        PublicKey subjectPublicKey = converter.getPublicKey(csr.getSubjectPublicKeyInfo());

        // Set validity period
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + Const.TimeInMillis.toMillis(duration));

        // Generate serial number
        BigInteger serial = new BigInteger(64, SecUtil.defaultSecureRandom());

        // Create certificate builder
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                caCert,
                serial,
                notBefore,
                notAfter,
                csr.getSubject(),
                subjectPublicKey
        );

        // Copy extensions from CSR if requested
        if (copyExtensions) {
            Extensions csrExtensions = extractExtensions(csr);
            if (csrExtensions != null) {
                for (ASN1ObjectIdentifier oid : csrExtensions.getExtensionOIDs()) {
                    Extension ext = csrExtensions.getExtension(oid);
                    certBuilder.addExtension(ext);
                }
            }
        }

        // Determine signature algorithm based on CA key type
        String signatureAlgorithm = getSignatureAlgorithm(caPrivateKey);
        ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm)
                .setProvider(BC_PROVIDER).build(caPrivateKey);

        // Build and convert to X509Certificate
        return new JcaX509CertificateConverter()
                .setProvider(BC_PROVIDER)
                .getCertificate(certBuilder.build(signer));
    }

    /**
     * Sign a CSR to produce a certificate holder.
     *
     * @param csr            the certificate signing request
     * @param caPrivateKey   the CA's private key for signing
     * @param caCertHolder   the CA's certificate holder (issuer)
     * @param days           validity in days
     * @param copyExtensions if true, copy extensions from the CSR to the certificate
     * @return the signed X509CertificateHolder
     */
    public X509CertificateHolder signCSR(PKCS10CertificationRequest csr,
                                         PrivateKey caPrivateKey,
                                         X509CertificateHolder caCertHolder,
                                         int days,
                                         boolean copyExtensions) throws Exception {
        // Extract public key from CSR
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(BC_PROVIDER);
        PublicKey subjectPublicKey = converter.getPublicKey(csr.getSubjectPublicKeyInfo());

        // Set validity period
        long now = System.currentTimeMillis();
        Date notBefore = new Date(now);
        Date notAfter = new Date(now + Const.TimeInMillis.DAY.mult(days));

        // Generate serial number
        BigInteger serial = new BigInteger(64, SecUtil.defaultSecureRandom());

        // Create certificate builder
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                caCertHolder.getSubject(),
                serial,
                notBefore,
                notAfter,
                csr.getSubject(),
                subjectPublicKey
        );

        // Copy extensions from CSR if requested
        if (copyExtensions) {
            Extensions csrExtensions = extractExtensions(csr);
            if (csrExtensions != null) {
                for (ASN1ObjectIdentifier oid : csrExtensions.getExtensionOIDs()) {
                    Extension ext = csrExtensions.getExtension(oid);
                    certBuilder.addExtension(ext);
                }
            }
        }

        // Determine signature algorithm based on CA key type
        String signatureAlgorithm = getSignatureAlgorithm(caPrivateKey);
        ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm)
                .setProvider(BC_PROVIDER).build(caPrivateKey);

        return certBuilder.build(signer);
    }

    /**
     * Sign a CSR with additional extensions beyond those in the CSR.
     *
     * @param csr               the certificate signing request
     * @param caPrivateKey      the CA's private key for signing
     * @param caCert            the CA's certificate (issuer)
     * @param duration          validity duration (e.g., "365d", "1y")
     * @param additionalExtensions extra extensions to add
     * @param copyCSRExtensions if true, copy extensions from the CSR
     * @return the signed X509Certificate
     */
    public X509Certificate signCSR(PKCS10CertificationRequest csr,
                                   PrivateKey caPrivateKey,
                                   X509Certificate caCert,
                                   String duration,
                                   Extensions additionalExtensions,
                                   boolean copyCSRExtensions) throws Exception {
        // Extract public key from CSR
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(BC_PROVIDER);
        PublicKey subjectPublicKey = converter.getPublicKey(csr.getSubjectPublicKeyInfo());

        // Set validity period
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + Const.TimeInMillis.toMillis(duration));

        // Generate serial number
        BigInteger serial = new BigInteger(64, SecUtil.defaultSecureRandom());

        // Create certificate builder
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                caCert,
                serial,
                notBefore,
                notAfter,
                csr.getSubject(),
                subjectPublicKey
        );

        // Copy extensions from CSR if requested
        if (copyCSRExtensions) {
            Extensions csrExtensions = extractExtensions(csr);
            if (csrExtensions != null) {
                for (ASN1ObjectIdentifier oid : csrExtensions.getExtensionOIDs()) {
                    Extension ext = csrExtensions.getExtension(oid);
                    certBuilder.addExtension(ext);
                }
            }
        }

        // Add additional extensions
        if (additionalExtensions != null) {
            for (ASN1ObjectIdentifier oid : additionalExtensions.getExtensionOIDs()) {
                Extension ext = additionalExtensions.getExtension(oid);
                certBuilder.addExtension(ext);
            }
        }

        // Determine signature algorithm based on CA key type
        String signatureAlgorithm = getSignatureAlgorithm(caPrivateKey);
        ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm)
                .setProvider(BC_PROVIDER).build(caPrivateKey);

        // Build and convert to X509Certificate
        return new JcaX509CertificateConverter()
                .setProvider(BC_PROVIDER)
                .getCertificate(certBuilder.build(signer));
    }

    private String getSignatureAlgorithm(PrivateKey privateKey) {
        String algorithm = privateKey.getAlgorithm();
        if ("EC".equalsIgnoreCase(algorithm) || "ECDSA".equalsIgnoreCase(algorithm)) {
            return CryptoConst.SignatureAlgo.SHA256_EC.getName();
        } else if ("RSA".equalsIgnoreCase(algorithm)) {
            return CryptoConst.SignatureAlgo.SHA256_RSA.getName();
        } else if ("Ed25519".equalsIgnoreCase(algorithm)) {
            return "Ed25519";
        } else if ("Ed448".equalsIgnoreCase(algorithm)) {
            return "Ed448";
        } else if (algorithm.toUpperCase().contains("DILITHIUM")) {
            return "Dilithium";
        }
        // Default to RSA
        return CryptoConst.SignatureAlgo.SHA256_RSA.getName();
    }

    public KeyPair generateKeyPair(CanonicalID keyType, String provider)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        return CryptoUtil.generateKeyPair(keyType, provider, SecUtil.defaultSecureRandom());
    }

    public X509Certificate generateSelfSignedCertificate(KeyPair keyPair, X500Name issuer, X500Name subject, String duration) throws Exception {
        // Set the certificate's subject and issuer details

        // Validity period for the certificate
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + Const.TimeInMillis.toMillis(duration)); // 1 year

        // Create the certificate builder
        BigInteger serial = new BigInteger(64, SecUtil.defaultSecureRandom());
        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer,
                serial,
                notBefore,
                notAfter,
                subject,
                keyPair.getPublic()
        );

        // ContentSigner for signing the certificate
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
                .setProvider("BC").build(keyPair.getPrivate());

        // Build the certificate and convert to X509Certificate
        return new JcaX509CertificateConverter().setProvider("BC")
                .getCertificate(certBuilder.build(signer));
    }


    public KeyPair toKeyPair(String type, String provider, String pubKeyBase64, String privKeyBase64)
            throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        return CryptoUtil.toKeyPair(type, provider, pubKeyBase64, privKeyBase64);
    }

    public KeyStore createKeyStore(String alias, String keystorePassword,
                                   PrivateKey privateKey, X509Certificate certificate) throws Exception {
        // Create a KeyStore object of type JKS
        KeyStore keyStore = KeyStore.getInstance(CryptoConst.PKCS12);
        keyStore.load(null, null); // Initialize a new KeyStore

        // Set the entry for the key and certificate
        KeyStore.PrivateKeyEntry entry = new KeyStore.PrivateKeyEntry(privateKey,
                new X509Certificate[]{certificate});
        KeyStore.PasswordProtection passwordProtection = new KeyStore.PasswordProtection(keystorePassword.toCharArray());

        // Set the entry into the KeyStore
        keyStore.setEntry(alias, entry, passwordProtection);

        // Return the KeyStore instance
        return keyStore;
    }


    public PKCS10CertificationRequest createCSR(KeyPair keyPair, String dn, String alternativeName,
                                                String... props) throws IOException, OperatorCreationException {
        // Validate inputs
        if (keyPair == null || keyPair.getPublic() == null || keyPair.getPrivate() == null) {
            throw new IllegalArgumentException("KeyPair must not be null and must include public and private keys");
        }
        if (dn == null || dn.trim().isEmpty()) {
            throw new IllegalArgumentException("Distinguished Name (dn) must not be null or empty");
        }

        // Create subject
        X500Name subject;
        try {
            subject = new X500Name(dn);
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid Distinguished Name format: " + dn, e);
        }

        // Initialize extensions
        ASN1EncodableVector extensions = new ASN1EncodableVector();

        // Step 1: Process Key Usage extension
        int keyUsageBits = 0;
        for (String prop : props) {
            KeyUsageType keyUsage = KeyUsageType.lookup(prop);
            if (keyUsage != null)
                keyUsageBits |= keyUsage.getValue().getPadBits();

//            switch (prop.toLowerCase()) {
//                case "digitalsignature":
//                    keyUsageBits |= KeyUsage.digitalSignature;
//                    log.getLogger().info(prop);
//                    break;
//                case "keyencipherment":
//                    keyUsageBits |= KeyUsage.keyEncipherment;
//                    log.getLogger().info(prop);
//                    break;
//                case "nonrepudiation":
//                    keyUsageBits |= KeyUsage.nonRepudiation;
//                    break;
//                case "dataencipherment":
//                    keyUsageBits |= KeyUsage.dataEncipherment;
//                    break;
//                case "keyagreement":
//                    keyUsageBits |= KeyUsage.keyAgreement;
//                    log.getLogger().info(prop);
//                    break;
//
//                case "keycertsign":
//                    keyUsageBits |= KeyUsage.keyCertSign;
//                    break;
//
//                case "crlsign":
//                    keyUsageBits |= KeyUsage.cRLSign;
//                    break;
//
//                case "encipheronly":
//                    keyUsageBits |= KeyUsage.encipherOnly;
//                    break;
//
//                case "decipheronly":
//                    keyUsageBits |= KeyUsage.decipherOnly;
//                    break;
//            }

        }
        if (keyUsageBits != 0) {
            log.getLogger().info("keyUsageBits: " + keyUsageBits);
            KeyUsage keyUsage = new KeyUsage(keyUsageBits);
            extensions.add(new Extension(
                    new ASN1ObjectIdentifier("2.5.29.15"), // Key Usage OID
                    true, // Critical
                    keyUsage.toASN1Primitive().getEncoded()
            ));
        }

        // Step 2: Process Subject Alternative Name extension
        if (alternativeName != null && !alternativeName.trim().isEmpty()) {
            String[] names = alternativeName.split(",");
            ASN1EncodableVector generalNames = new ASN1EncodableVector();
            for (String name : names) {
                name = name.trim();
                if (name.startsWith("DNS:")) {
                    generalNames.add(new GeneralName(GeneralName.dNSName, name.substring(4)));
                } else if (name.startsWith("IP:")) {
                    generalNames.add(new GeneralName(GeneralName.iPAddress, name.substring(3)));
                } else {
                    throw new IllegalArgumentException("Invalid alternative name format: " + name +
                            ". Use 'DNS:name' or 'IP:address'");
                }
            }
            // Corrected: Use GeneralNames.getInstance with DERSequence
            GeneralNames san = GeneralNames.getInstance(new DERSequence(generalNames));
            extensions.add(new Extension(
                    new ASN1ObjectIdentifier("2.5.29.17"), // Subject Alternative Name OID
                    false, // Non-critical
                    san.toASN1Primitive().getEncoded()
            ));
        }

        // Step 3: Create CSR
        PKCS10CertificationRequestBuilder csrBuilder =
                new JcaPKCS10CertificationRequestBuilder(subject, keyPair.getPublic());
        if (extensions.size() > 0) {
            csrBuilder.addAttribute(
                    new ASN1ObjectIdentifier("1.2.840.113549.1.9.14"), // ExtensionRequest
                    Extensions.getInstance(new DERSequence(extensions)) // Corrected: Use DERSequence directly
            );
        }

        // Step 4: Sign the CSR
        String signatureAlgorithm = keyPair.getPublic().getAlgorithm().equals("EC") ?
                "SHA256withECDSA" : "SHA256withRSA";
        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(signatureAlgorithm);
        return csrBuilder.build(signerBuilder.build(keyPair.getPrivate()));
    }

    public PKCS10CertificationRequest generateCSR(KeyPair keyPair, String attr, String altNames) throws Exception {
        X500Name subject = createSubject(attr);
        PKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(subject, keyPair.getPublic());

        Extensions extensions = null;
        // Add Subject Alternative Names (SAN) extension if provided
        if (altNames != null && !altNames.isEmpty()) {
            List<GeneralName> sanList = new ArrayList<>();
            String[] altNamesArray = altNames.split(",");
            for (String altName : altNamesArray) {
                String[] parts = altName.split(":");
                String type = parts[0];
                String value = parts[1];

                GeneralName san;
                switch (type.toUpperCase()) {
                    case "DNS":
                        san = new GeneralName(GeneralName.dNSName, value);
                        break;
                    case "IP":
                        san = new GeneralName(GeneralName.iPAddress, value);
                        break;
                    default:
                        throw new IllegalArgumentException("Unsupported SAN type: " + type);
                }
                sanList.add(san);
            }

            GeneralNames subjectAltName = new GeneralNames(sanList.toArray(new GeneralName[0]));
            ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
            extensionsGenerator.addExtension(Extension.subjectAlternativeName, false, subjectAltName);
            extensions = extensionsGenerator.generate();
            csrBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions);
        }


//        if("EC".equalsIgnoreCase(keyPair.getPublic().getAlgorithm())) {
//            KeyUsage keyUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyAgreement);
//            ASN1EncodableVector extensions = new ASN1EncodableVector();
//            extensions.add(new Extension(
//                    new ASN1ObjectIdentifier("2.5.29.15"), // Key Usage OID
//                    true, // Critical
//                    keyUsage.toASN1Primitive().getEncoded()
//            ));
//
//            csrBuilder.addAttribute(
//                    new ASN1ObjectIdentifier("1.2.840.113549.1.9.14"), // ExtensionRequest
//                    new Extensions(Extension.getInstance(new DERSequence(extensions)))
//            );
//        }


        JcaContentSignerBuilder csBuilder = "EC".equalsIgnoreCase(keyPair.getPublic().getAlgorithm()) ?
                new JcaContentSignerBuilder(CryptoConst.SignatureAlgo.SHA256_EC.getName()) :
                new JcaContentSignerBuilder(CryptoConst.SignatureAlgo.SHA256_RSA.getName());


        ContentSigner signer = csBuilder.build(keyPair.getPrivate());
        return csrBuilder.build(signer);
    }

    public PKCS10CertificationRequest readCSR(String pem) throws IOException {
        try (PEMParser pemParser = new PEMParser(new StringReader(pem))) {
            Object obj = pemParser.readObject();
            if (obj instanceof PKCS10CertificationRequest) {
                return (PKCS10CertificationRequest) obj;
            }
            throw new IllegalArgumentException("Invalid CSR PEM format: " + obj.getClass().getName());
        }
    }

    public PKCS10CertificationRequest readCSR(File file) throws IOException {
        try (PEMParser pemParser = new PEMParser(new FileReader(file))) {
            Object obj = pemParser.readObject();
            if (obj instanceof PKCS10CertificationRequest) {
                return (PKCS10CertificationRequest) obj;
            }
            throw new IllegalArgumentException("Invalid CSR PEM format: " + obj.getClass().getName());
        }
    }

    public PublicKey extractPublicKey(PKCS10CertificationRequest csr) throws IOException {
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(BC_PROVIDER);
        return converter.getPublicKey(csr.getSubjectPublicKeyInfo());
    }

    public Extensions extractExtensions(PKCS10CertificationRequest csr) {
        org.bouncycastle.asn1.pkcs.Attribute[] attributes = csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        if (attributes != null && attributes.length > 0) {
            org.bouncycastle.asn1.ASN1Set attrValues = attributes[0].getAttrValues();
            if (attrValues.size() > 0) {
                return Extensions.getInstance(attrValues.getObjectAt(0));
            }
        }
        return null;
    }

    public KeyUsage extractKeyUsage(PKCS10CertificationRequest csr) {
        Extensions extensions = extractExtensions(csr);
        if (extensions != null) {
            Extension keyUsageExt = extensions.getExtension(Extension.keyUsage);
            if (keyUsageExt != null) {
                return KeyUsage.getInstance(keyUsageExt.getParsedValue());
            }
        }
        return null;
    }

    public GeneralNames extractSubjectAlternativeNames(PKCS10CertificationRequest csr) {
        Extensions extensions = extractExtensions(csr);
        if (extensions != null) {
            Extension sanExt = extensions.getExtension(Extension.subjectAlternativeName);
            if (sanExt != null) {
                return GeneralNames.getInstance(sanExt.getParsedValue());
            }
        }
        return null;
    }

    public String csrToString(PKCS10CertificationRequest csr) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("Subject: ").append(csr.getSubject()).append("\n");
        sb.append("Public Key Algorithm: ").append(csr.getSubjectPublicKeyInfo().getAlgorithm().getAlgorithm()).append("\n");
        sb.append("Signature Algorithm: ").append(csr.getSignatureAlgorithm().getAlgorithm()).append("\n");

        Extensions extensions = extractExtensions(csr);
        if (extensions != null) {
            sb.append("Extensions:\n");
            for (ASN1ObjectIdentifier oid : extensions.getExtensionOIDs()) {
                Extension ext = extensions.getExtension(oid);
                sb.append("  - OID: ").append(oid).append(" (critical: ").append(ext.isCritical()).append(")\n");
                if (oid.equals(Extension.keyUsage)) {
                    KeyUsage ku = KeyUsage.getInstance(ext.getParsedValue());
                    sb.append("    Key Usage: ").append(keyUsageToString(ku)).append("\n");
                } else if (oid.equals(Extension.subjectAlternativeName)) {
                    GeneralNames san = GeneralNames.getInstance(ext.getParsedValue());
                    sb.append("    Subject Alt Names: ");
                    for (GeneralName name : san.getNames()) {
                        sb.append(generalNameToString(name)).append(", ");
                    }
                    sb.append("\n");
                }
            }
        }
        return sb.toString();
    }

    private String keyUsageToString(KeyUsage ku) {
        StringBuilder sb = new StringBuilder();
        int bits = ku.getPadBits();
        if ((bits & KeyUsage.digitalSignature) != 0) sb.append("digitalSignature ");
        if ((bits & KeyUsage.nonRepudiation) != 0) sb.append("nonRepudiation ");
        if ((bits & KeyUsage.keyEncipherment) != 0) sb.append("keyEncipherment ");
        if ((bits & KeyUsage.dataEncipherment) != 0) sb.append("dataEncipherment ");
        if ((bits & KeyUsage.keyAgreement) != 0) sb.append("keyAgreement ");
        if ((bits & KeyUsage.keyCertSign) != 0) sb.append("keyCertSign ");
        if ((bits & KeyUsage.cRLSign) != 0) sb.append("cRLSign ");
        if ((bits & KeyUsage.encipherOnly) != 0) sb.append("encipherOnly ");
        if ((bits & KeyUsage.decipherOnly) != 0) sb.append("decipherOnly ");
        return sb.toString().trim();
    }

    private String generalNameToString(GeneralName name) {
        switch (name.getTagNo()) {
            case GeneralName.dNSName:
                return "DNS:" + name.getName();
            case GeneralName.iPAddress:
                return "IP:" + name.getName();
            case GeneralName.rfc822Name:
                return "Email:" + name.getName();
            case GeneralName.uniformResourceIdentifier:
                return "URI:" + name.getName();
            default:
                return name.toString();
        }
    }

    public String convertPrivateKeyToPEM(PrivateKey privateKey) throws IOException {
        StringWriter stringWriter = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
            pemWriter.writeObject(privateKey);
        }
        return stringWriter.toString();
    }

    public String convertCertificateToPEM(X509Certificate certificate) throws IOException {
        StringWriter stringWriter = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
            pemWriter.writeObject(certificate);
        }
        return stringWriter.toString();
    }

    public String convertCertificateToPEM(X509CertificateHolder certificateHolder) throws IOException {
        StringWriter stringWriter = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
            pemWriter.writeObject(certificateHolder);
        }
        return stringWriter.toString();
    }

    public String convertCSRToPEM(PKCS10CertificationRequest csr) throws IOException {
        StringWriter stringWriter = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
            pemWriter.writeObject(csr);
        }
        return stringWriter.toString();
    }

    public static String sshCommand(String user, int port, String host, KeyPair[] keys, String command) throws IOException {
        SshClient client = SshClient.setUpDefaultClient();
        client.start();

//        KeyPairProvider keyPairProvider = new FileKeyPairProvider(Collections.singletonList(Paths.get(privateKeyPath)));
//        Iterable<KeyPair> keys = keyPairProvider.loadKeys(null);

        UByteArrayOutputStream ubaos = new UByteArrayOutputStream();
        try (ClientSession session = client.connect(user, host, port).verify(10000).getSession()) {
            for (KeyPair key : keys)
                session.addPublicKeyIdentity(key);
            session.auth().verify(5000);

            try (ClientChannel channel = session.createExecChannel(command)) {
                channel.setOut(ubaos);
                channel.setErr(ubaos);
                channel.open().verify(5_000);
                channel.waitFor(Collections.singleton(ClientChannelEvent.CLOSED), 0);
                return ubaos.toString();
            }
        } finally {
            client.stop();
        }
    }


    public static KeyPair[] loadKeyPairFromPath(URI path) throws GeneralSecurityException, IOException {
        KeyPairProvider keyPairProvider = new FileKeyPairProvider(Collections.singletonList(Paths.get(path)));
        List<KeyPair> ret = new ArrayList<>();

        for (KeyPair kp : keyPairProvider.loadKeys(null))
            ret.add(kp);
        return ret.toArray(new KeyPair[0]);
    }


    public static String sshCommand(SShURI sshURI, String command) throws IOException {
        return sshCommand(sshURI.subject, sshURI.port, sshURI.host, sshURI.credential, command);
    }


    public static String sshCommand(SShURI sshURI, KeyPair[] keyPairs, String command) throws IOException {
        return sshCommand(sshURI.subject, sshURI.port, sshURI.host, keyPairs, command);
    }

    public static String sshCommand(String subject, int port, String host, String password, String command) throws IOException {
        SshClient client = SshClient.setUpDefaultClient();
        client.start();

        try (ClientSession session = client.connect(subject, host, port).verify(10000).getSession()) {
            session.addPasswordIdentity(password);
            session.auth().verify(5000);
            UByteArrayOutputStream ubaos = new UByteArrayOutputStream();
            try (ClientChannel channel = session.createExecChannel(command)) {
                channel.setOut(ubaos);
                channel.setErr(ubaos);
                channel.open().verify(5_000);
                channel.waitFor(Collections.singleton(ClientChannelEvent.CLOSED), 0);
                return ubaos.toString();
            }
        } finally {
            client.stop();
        }
    }

    public PrivateKey convertPemToPrivateKey(String pem) throws IOException {
        StringReader stringReader = new StringReader(pem);
        try (PEMParser pemParser = new PEMParser(stringReader)) {
            Object object = pemParser.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

            if (object instanceof PrivateKey) {
                return (PrivateKey) object;
            } else if (object instanceof org.bouncycastle.openssl.PEMKeyPair) {
                return converter.getPrivateKey(((org.bouncycastle.openssl.PEMKeyPair) object).getPrivateKeyInfo());
            } else if (object instanceof org.bouncycastle.asn1.pkcs.PrivateKeyInfo) {
                return converter.getPrivateKey((org.bouncycastle.asn1.pkcs.PrivateKeyInfo) object);
            } else {
                throw new IllegalArgumentException("Unknown PEM object type: " + object.getClass().getName());
            }
        }
    }

    public String convertPublicKeyToPEM(PublicKey publicKey) throws IOException {
        StringWriter stringWriter = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
            pemWriter.writeObject(publicKey);
        }
        return stringWriter.toString();
    }

    public PublicKey convertPemToPublicKey(String pem) throws IOException {
        StringReader stringReader = new StringReader(pem);
        try (PEMParser pemParser = new PEMParser(stringReader)) {
            Object object = pemParser.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

            if (object instanceof org.bouncycastle.asn1.x509.SubjectPublicKeyInfo) {
                return converter.getPublicKey((org.bouncycastle.asn1.x509.SubjectPublicKeyInfo) object);
            } else {
                throw new IllegalArgumentException("Unknown PEM object type: " + object.getClass().getName());
            }
        }
    }


    public X509Certificate convertPemToX509Certificate(String pemCert) throws IOException, CertificateException {
        // Read the PEM file content

        // Strip the headers and footers
        pemCert = pemCert.replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "");  // Remove any whitespace

        // Decode the base64 content
        byte[] decoded = SharedBase64.decode(SharedBase64.Base64Type.DEFAULT, pemCert);

        // Convert the decoded bytes to an X509Certificate
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        try (InputStream in = new ByteArrayInputStream(decoded)) {
            return (X509Certificate) factory.generateCertificate(in);
        }
    }

    public Certificate convertBCCertificateToJcaCertificate(X509CertificateHolder bcCertificate)
            throws IOException, CertificateException {
        // Get encoded form of the BouncyCastle Certificate
        byte[] encodedCertificate = bcCertificate.getEncoded();

        // Create a CertificateFactory
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

        // Generate Certificate
        return certificateFactory.generateCertificate(new ByteArrayInputStream(encodedCertificate));
    }

    private List<Object> readPermObject(PEMParser pemParser) throws IOException {
        Object obj;
        List<Object> ret = new ArrayList<>();
        while ((obj = pemParser.readObject()) != null) {
            ret.add(obj);
        }
        pemParser.close();
        return ret;
    }

    public KeyStore createKeyStore(String privateKeyFilePath, String certificateFilePath, String chainFilePath, String keyStoreType, String keyStorePassword, String certAlias) throws CertificateException, IOException, PKCSException, OperatorCreationException, KeyStoreException, NoSuchAlgorithmException {
        // Load Certificate Chain
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        List<Certificate> chain = new ArrayList<>();

        // Load the primary certificate
        try (FileReader reader = new FileReader(certificateFilePath);
             PEMParser certParser = new PEMParser(reader)) {
            Certificate cert = factory.generateCertificate(new ByteArrayInputStream(certParser.readPemObject().getContent()));
            chain.add(cert);
            if (cert instanceof X509Certificate) {
                log.getLogger().info("" + ((X509Certificate) cert).getNotAfter());
            }
        }

        // Load additional certificates from the chain file
        try (FileReader chainReader = new FileReader(chainFilePath);
             PEMParser chainParser = new PEMParser(chainReader)) {
            Object obj;
            while ((obj = chainParser.readObject()) != null) {

                if (obj instanceof Certificate) {
                    chain.add((Certificate) obj);
                } else if (obj instanceof X509CertificateHolder) {
                    chain.add(convertBCCertificateToJcaCertificate((X509CertificateHolder) obj));
                }
            }
        }

        // Load Private Key
        PrivateKey privateKey = null;
        try (PEMParser pemParser = new PEMParser(new PemReader(new FileReader(privateKeyFilePath)))) {
            List<Object> listObject = readPermObject(pemParser);


            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
            //log.getLogger().info(listObject);
            for (Object object : listObject) {
                if (object instanceof PKCS8EncryptedPrivateKeyInfo) { // For encrypted private keys
                    PKCS8EncryptedPrivateKeyInfo encryptedPrivateKeyInfo = (PKCS8EncryptedPrivateKeyInfo) object;
                    InputDecryptorProvider decryptorProvider = new JceOpenSSLPKCS8DecryptorProviderBuilder().build(keyStorePassword.toCharArray());
                    privateKey = converter.getPrivateKey(encryptedPrivateKeyInfo.decryptPrivateKeyInfo(decryptorProvider));
                } else if (object instanceof PEMKeyPair) {
                    // Handling a key pair
                    PEMKeyPair keyPair = (PEMKeyPair) object;
                    //log.getLogger().info("private key info: " + keyPair.getPrivateKeyInfo() + " " + keyPair.getPrivateKeyInfo().getPrivateKeyAlgorithm());
                    privateKey = converter.getPrivateKey(keyPair.getPrivateKeyInfo());
                } else if (object instanceof PrivateKeyInfo) { // Direct private key info
                    privateKey = converter.getPrivateKey((PrivateKeyInfo) object);
                }
            }
        }


        log.getLogger().info("Key Format:" + privateKey.getFormat() + " " + privateKey.getAlgorithm());

        // Create KeyStore
        KeyStore keyStore = KeyStore.getInstance(keyStoreType);
        keyStore.load(null, null);
        Certificate[] certificates = chain.toArray(new Certificate[0]);
        keyStore.setKeyEntry(SUS.isEmpty(certAlias) ? "keyalias" : certAlias, privateKey, keyStorePassword.toCharArray(), certificates);

        return keyStore;
    }


    public String extractFilename(String attrs) {
        ParamUtil.ParamMap params = ParamUtil.parse("=", attrs.split(","));
        if (params.stringValue("CN", true) != null) {
            return params.stringValue("CN");
        }

        if (params.stringValue("E", true) != null) {
            return params.stringValue("E").replace("@", "_");
        }
        throw new IllegalArgumentException(attrs + " no CN or E attribute found");
    }

    public String outputFilename(String outDir, String filename) {

        if (outDir != null)
            filename = SharedStringUtil.concat(outDir, filename, "/");

        return filename;
    }

    public SecretKeyWithEncapsulation generateCKEncryptionKey(PublicKey publicKey)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyGenerator keyGen = KeyGenerator.getInstance("KYBER", "BCPQC");
        keyGen.init(new KEMGenerateSpec(publicKey, "AES"), SecUtil.defaultSecureRandom());
        return (SecretKeyWithEncapsulation) keyGen.generateKey();
    }

    public SecretKeyWithEncapsulation extractCKDecryptionKey(PrivateKey privateKey, byte[] encapsulatedKey)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyGenerator keyGen = KeyGenerator.getInstance("KYBER", "BCPQC");
        keyGen.init(new KEMExtractSpec(privateKey, encapsulatedKey, "AES"), SecUtil.defaultSecureRandom());
        return (SecretKeyWithEncapsulation) keyGen.generateKey();
    }

    public byte[] encryptCKAESKey(PublicKey publicKey, byte[] aesKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, IllegalBlockSizeException {
        return encryptCKAESKey(publicKey, CryptoUtil.toSecretKey(aesKey, "AES"));
    }


    public byte[] encryptCKAESKey(PublicKey publicKey, SecretKey aesKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, IllegalBlockSizeException {
        Cipher kyberWrapCipher = Cipher.getInstance("Kyber", "BCPQC");
        kyberWrapCipher.init(Cipher.WRAP_MODE, publicKey, SecUtil.defaultSecureRandom());
        return kyberWrapCipher.wrap(aesKey);
    }

    public Key decryptCKAESKey(PrivateKey privateKey, byte[] wrappedAesKeyBytes)
            throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, IllegalBlockSizeException {
        Cipher kyberUnwrapCipher = Cipher.getInstance("Kyber", "BCPQC");
        kyberUnwrapCipher.init(Cipher.UNWRAP_MODE, privateKey);
        return kyberUnwrapCipher.unwrap(wrappedAesKeyBytes, "AES", Cipher.SECRET_KEY);
    }


//    public static PrivateKey extractKCPrivateKeyFromEncoded(byte[] encodedKey) {
//        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(encodedKey);
//        KeyFactory keyFactory = null;
//        try {
//            keyFactory = KeyFactory.getInstance("KYBER", "BCPQC");
//            return keyFactory.generatePrivate(pkcs8EncodedKeySpec);
//        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
//            e.printStackTrace();
//            return null;
//        }
//    }
//
//    public static PublicKey exctractCKPublicKeyFromEncoded(byte[] encodedKey) {
//        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(encodedKey);
//        try {
//            KeyFactory keyFactory = KeyFactory.getInstance("KYBER", "BCPQC");
//            return keyFactory.generatePublic(x509EncodedKeySpec);
//        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
//            e.printStackTrace();
//            return null;
//        }
//    }


    public KeyPair generateKeyPair(String type, String provider, AlgorithmParameterSpec keySpec, SecureRandom random)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        return CryptoUtil.generateKeyPair(type, provider, keySpec, random);
    }

    public X509CRL readCRL(InputStream is) throws CertificateException, CRLException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509CRL) cf.generateCRL(is);
    }

    public X509CRLEntry[] getRevokedCerts(InputStream is) throws CertificateException, CRLException {
        return getRevokedCerts(readCRL(is));
    }

    public X509CRLEntry[] getRevokedCerts(X509CRL crl) {
        return crl.getRevokedCertificates().toArray(new X509CRLEntry[0]);
    }

    // ==================== PQC Analysis Utilities ====================

    /**
     * Known PQC hybrid key exchange algorithms (TLS NamedGroup values)
     */
    public static final String[] PQC_HYBRID_KEY_EXCHANGES = {
        "X25519MLKEM768",       // X25519 + ML-KEM-768
        "SecP256r1MLKEM768",    // ECDH P-256 + ML-KEM-768
        "X25519Kyber768",       // X25519 + Kyber-768 (older name)
        "SecP256r1Kyber768",    // ECDH P-256 + Kyber-768 (older name)
        "X448MLKEM1024",        // X448 + ML-KEM-1024
        "SecP384r1MLKEM1024",   // ECDH P-384 + ML-KEM-1024
    };

    /**
     * Classical ECDHE key exchange algorithms
     */
    public static final String[] CLASSICAL_ECDHE = {
        "x25519", "X25519",
        "x448", "X448",
        "secp256r1", "SecP256r1", "P-256",
        "secp384r1", "SecP384r1", "P-384",
        "secp521r1", "SecP521r1", "P-521",
    };

    /**
     * PQC signature algorithms (ML-DSA / Dilithium)
     */
    public static final String[] PQC_SIGNATURE_ALGORITHMS = {
        "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
        "DILITHIUM2", "DILITHIUM3", "DILITHIUM5",
        "Dilithium2", "Dilithium3", "Dilithium5",
        "FALCON-512", "FALCON-1024",
        "Falcon-512", "Falcon-1024",
        "SPHINCS+", "SLH-DSA",
    };

    /**
     * Check if a key exchange algorithm is PQC hybrid
     * @param algorithm the key exchange algorithm name
     * @return true if PQC hybrid
     */
    public boolean isPQCHybridKeyExchange(String algorithm) {
        if (algorithm == null) return false;
        String upper = algorithm.toUpperCase();
        for (String pqc : PQC_HYBRID_KEY_EXCHANGES) {
            if (upper.contains(pqc.toUpperCase())) {
                return true;
            }
        }
        // Also check for generic ML-KEM or Kyber in name
        return upper.contains("MLKEM") || upper.contains("ML-KEM") || upper.contains("KYBER");
    }

    /**
     * Check if a key exchange algorithm is classical ECDHE
     * @param algorithm the key exchange algorithm name
     * @return true if classical ECDHE
     */
    public boolean isClassicalECDHE(String algorithm) {
        if (algorithm == null) return false;
        String upper = algorithm.toUpperCase();
        // First check it's not PQC hybrid
        if (isPQCHybridKeyExchange(algorithm)) {
            return false;
        }
        for (String ecdhe : CLASSICAL_ECDHE) {
            if (upper.contains(ecdhe.toUpperCase())) {
                return true;
            }
        }
        return upper.contains("ECDHE") || upper.contains("ECDH");
    }

    /**
     * Check if a signature algorithm is PQC
     * @param algorithm the signature algorithm name (e.g., from certificate)
     * @return true if PQC signature
     */
    public boolean isPQCSignatureAlgorithm(String algorithm) {
        if (algorithm == null) return false;
        String upper = algorithm.toUpperCase();
        for (String pqc : PQC_SIGNATURE_ALGORITHMS) {
            if (upper.contains(pqc.toUpperCase())) {
                return true;
            }
        }
        return upper.contains("ML-DSA") || upper.contains("MLDSA") ||
               upper.contains("DILITHIUM") || upper.contains("FALCON") ||
               upper.contains("SPHINCS") || upper.contains("SLH-DSA");
    }

    /**
     * Classify a key exchange algorithm
     * @param algorithm the algorithm name
     * @return classification string: "PQC_HYBRID", "ECDHE", "DHE", "RSA", or "UNKNOWN"
     */
    public String classifyKeyExchange(String algorithm) {
        if (algorithm == null) return "UNKNOWN";
        String upper = algorithm.toUpperCase();

        if (isPQCHybridKeyExchange(algorithm)) {
            return "PQC_HYBRID";
        }
        if (isClassicalECDHE(algorithm)) {
            return "ECDHE";
        }
        if (upper.contains("DHE") || upper.contains("DH_") || upper.contains("FFDHE")) {
            return "DHE";
        }
        if (upper.contains("RSA") && !upper.contains("ECDSA")) {
            return "RSA";
        }
        return "UNKNOWN";
    }

    /**
     * Classify a signature algorithm
     * @param algorithm the algorithm name (e.g., "SHA256withECDSA")
     * @return classification string: "PQC_SIGNATURE", "ECDSA", "RSA", "EDDSA", or "UNKNOWN"
     */
    public String classifySignatureAlgorithm(String algorithm) {
        if (algorithm == null) return "UNKNOWN";
        String upper = algorithm.toUpperCase();

        if (isPQCSignatureAlgorithm(algorithm)) {
            return "PQC_SIGNATURE";
        }
        if (upper.contains("ECDSA") || upper.contains("EC")) {
            return "ECDSA";
        }
        if (upper.contains("ED25519") || upper.contains("ED448") || upper.contains("EDDSA")) {
            return "EDDSA";
        }
        if (upper.contains("RSA")) {
            return "RSA";
        }
        return "UNKNOWN";
    }

    /**
     * Check if TLS version supports PQC (requires TLS 1.3)
     * @param tlsVersion the TLS version string
     * @return true if TLS 1.3 or higher
     */
    public boolean isTlsVersionPqcCapable(String tlsVersion) {
        if (tlsVersion == null) return false;
        return tlsVersion.contains("1.3") || tlsVersion.contains("1.4");
    }

    /**
     * Analyze a certificate's signature algorithm for PQC readiness
     * @param cert the X509 certificate
     * @return array: [signatureType, signatureAlgorithm, publicKeyType, publicKeySize]
     */
    public String[] analyzeCertificatePQC(X509Certificate cert) {
        if (cert == null) return new String[]{"UNKNOWN", "UNKNOWN", "UNKNOWN", "0"};

        String sigAlg = cert.getSigAlgName();
        String sigType = classifySignatureAlgorithm(sigAlg);

        String pubKeyAlg = cert.getPublicKey().getAlgorithm();
        String pubKeyType = classifySignatureAlgorithm(pubKeyAlg);

        int keySize = 0;
        try {
            if (cert.getPublicKey() instanceof java.security.interfaces.RSAPublicKey) {
                keySize = ((java.security.interfaces.RSAPublicKey) cert.getPublicKey()).getModulus().bitLength();
            } else if (cert.getPublicKey() instanceof java.security.interfaces.ECPublicKey) {
                java.security.interfaces.ECPublicKey ecKey = (java.security.interfaces.ECPublicKey) cert.getPublicKey();
                keySize = ecKey.getParams().getOrder().bitLength();
            } else {
                // For PQC or other keys, estimate from encoded length
                keySize = cert.getPublicKey().getEncoded().length * 8;
            }
        } catch (Exception e) {
            // Ignore, keySize stays 0
        }

        return new String[]{sigType, sigAlg, pubKeyType, String.valueOf(keySize)};
    }

    // ==================== CRL/OCSP Revocation Checking ====================

    /**
     * Extract CRL Distribution Point URLs from a certificate.
     *
     * @param cert the X509 certificate
     * @return list of CRL distribution point URLs (may be empty)
     */
    public List<String> extractCRLDistributionPoints(X509Certificate cert) {
        List<String> urls = new ArrayList<>();
        if (cert == null) return urls;

        try {
            byte[] extValue = cert.getExtensionValue(OID_CRL_DISTRIBUTION_POINTS);
            if (extValue == null) return urls;

            ASN1InputStream asn1In = new ASN1InputStream(extValue);
            ASN1OctetString octetString = (ASN1OctetString) asn1In.readObject();
            asn1In.close();

            ASN1InputStream asn1In2 = new ASN1InputStream(octetString.getOctets());
            ASN1Sequence seq = (ASN1Sequence) asn1In2.readObject();
            asn1In2.close();

            CRLDistPoint distPoint = CRLDistPoint.getInstance(seq);
            for (DistributionPoint dp : distPoint.getDistributionPoints()) {
                DistributionPointName dpName = dp.getDistributionPoint();
                if (dpName != null && dpName.getType() == DistributionPointName.FULL_NAME) {
                    GeneralNames generalNames = (GeneralNames) dpName.getName();
                    for (GeneralName gn : generalNames.getNames()) {
                        if (gn.getTagNo() == GeneralName.uniformResourceIdentifier) {
                            String url = gn.getName().toString();
                            urls.add(url);
                        }
                    }
                }
            }
        } catch (Exception e) {
            if (log.isEnabled()) {
                log.getLogger().info("Error extracting CRL Distribution Points: " + e.getMessage());
            }
        }
        return urls;
    }

    /**
     * Extract OCSP Responder URLs from a certificate's Authority Information Access extension.
     *
     * @param cert the X509 certificate
     * @return list of OCSP responder URLs (may be empty)
     */
    public List<String> extractOCSPResponderURLs(X509Certificate cert) {
        List<String> urls = new ArrayList<>();
        if (cert == null) return urls;

        try {
            byte[] extValue = cert.getExtensionValue(OID_AUTHORITY_INFO_ACCESS);
            if (extValue == null) return urls;

            ASN1InputStream asn1In = new ASN1InputStream(extValue);
            ASN1OctetString octetString = (ASN1OctetString) asn1In.readObject();
            asn1In.close();

            ASN1InputStream asn1In2 = new ASN1InputStream(octetString.getOctets());
            ASN1Sequence seq = (ASN1Sequence) asn1In2.readObject();
            asn1In2.close();

            AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(seq);
            for (AccessDescription ad : aia.getAccessDescriptions()) {
                if (ad.getAccessMethod().equals(AccessDescription.id_ad_ocsp)) {
                    GeneralName gn = ad.getAccessLocation();
                    if (gn.getTagNo() == GeneralName.uniformResourceIdentifier) {
                        urls.add(gn.getName().toString());
                    }
                }
            }
        } catch (Exception e) {
            if (log.isEnabled()) {
                log.getLogger().info("Error extracting OCSP URLs: " + e.getMessage());
            }
        }
        return urls;
    }

    /**
     * Extract CA Issuer URLs from a certificate's Authority Information Access extension.
     *
     * @param cert the X509 certificate
     * @return list of CA issuer URLs (may be empty)
     */
    public List<String> extractCAIssuerURLs(X509Certificate cert) {
        List<String> urls = new ArrayList<>();
        if (cert == null) return urls;

        try {
            byte[] extValue = cert.getExtensionValue(OID_AUTHORITY_INFO_ACCESS);
            if (extValue == null) return urls;

            ASN1InputStream asn1In = new ASN1InputStream(extValue);
            ASN1OctetString octetString = (ASN1OctetString) asn1In.readObject();
            asn1In.close();

            ASN1InputStream asn1In2 = new ASN1InputStream(octetString.getOctets());
            ASN1Sequence seq = (ASN1Sequence) asn1In2.readObject();
            asn1In2.close();

            AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(seq);
            for (AccessDescription ad : aia.getAccessDescriptions()) {
                if (ad.getAccessMethod().equals(AccessDescription.id_ad_caIssuers)) {
                    GeneralName gn = ad.getAccessLocation();
                    if (gn.getTagNo() == GeneralName.uniformResourceIdentifier) {
                        urls.add(gn.getName().toString());
                    }
                }
            }
        } catch (Exception e) {
            if (log.isEnabled()) {
                log.getLogger().info("Error extracting CA Issuer URLs: " + e.getMessage());
            }
        }
        return urls;
    }

    /**
     * Check certificate revocation status via CRL.
     *
     * @param cert the certificate to check
     * @param crlUrl the CRL distribution point URL
     * @param timeoutMs connection timeout in milliseconds
     * @return RevocationResult indicating the status
     */
    public RevocationResult checkCRL(X509Certificate cert, String crlUrl, int timeoutMs) {
        if (cert == null) {
            return RevocationResult.error("CRL", "Certificate is null");
        }
        if (crlUrl == null || crlUrl.isEmpty()) {
            return RevocationResult.error("CRL", "CRL URL is null or empty");
        }

        try {
            java.net.URL url = new java.net.URL(crlUrl);
            java.net.URLConnection conn = url.openConnection();
            conn.setConnectTimeout(timeoutMs);
            conn.setReadTimeout(timeoutMs);

            try (InputStream is = conn.getInputStream()) {
                X509CRL crl = readCRL(is);

                X509CRLEntry entry = crl.getRevokedCertificate(cert.getSerialNumber());
                if (entry != null) {
                    Long revDate = entry.getRevocationDate() != null ? entry.getRevocationDate().getTime() : null;
                    String reason = entry.getRevocationReason() != null ? entry.getRevocationReason().name() : "UNSPECIFIED";
                    return RevocationResult.revoked("CRL", revDate, reason);
                }
                return RevocationResult.good("CRL");
            }
        } catch (java.net.SocketTimeoutException e) {
            return RevocationResult.error("CRL", "Timeout connecting to CRL: " + crlUrl);
        } catch (Exception e) {
            return RevocationResult.error("CRL", "Error checking CRL: " + e.getMessage());
        }
    }

    /**
     * Check certificate revocation status via OCSP.
     *
     * @param cert the certificate to check
     * @param issuerCert the issuer certificate (needed to verify OCSP response)
     * @param ocspUrl the OCSP responder URL
     * @param timeoutMs connection timeout in milliseconds
     * @return RevocationResult indicating the status
     */
    public RevocationResult checkOCSP(X509Certificate cert, X509Certificate issuerCert,
                                      String ocspUrl, int timeoutMs) {
        if (cert == null) {
            return RevocationResult.error("OCSP", "Certificate is null");
        }
        if (issuerCert == null) {
            return RevocationResult.error("OCSP", "Issuer certificate is null");
        }
        if (ocspUrl == null || ocspUrl.isEmpty()) {
            return RevocationResult.error("OCSP", "OCSP URL is null or empty");
        }

        try {
            // Build OCSP request
            DigestCalculatorProvider digCalcProv = new org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder()
                    .setProvider(BC_PROVIDER).build();
            CertificateID certId = new CertificateID(
                    digCalcProv.get(CertificateID.HASH_SHA1),
                    new JcaX509CertificateHolder(issuerCert),
                    cert.getSerialNumber()
            );

            OCSPReqBuilder reqBuilder = new OCSPReqBuilder();
            reqBuilder.addRequest(certId);
            OCSPReq ocspReq = reqBuilder.build();

            // Send OCSP request
            byte[] ocspReqData = ocspReq.getEncoded();

            java.net.URL url = new java.net.URL(ocspUrl);
            java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(timeoutMs);
            conn.setReadTimeout(timeoutMs);
            conn.setDoOutput(true);
            conn.setDoInput(true);
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/ocsp-request");
            conn.setRequestProperty("Accept", "application/ocsp-response");

            try (OutputStream os = conn.getOutputStream()) {
                os.write(ocspReqData);
            }

            // Read OCSP response
            byte[] respData;
            try (InputStream is = conn.getInputStream();
                 ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
                byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = is.read(buffer)) != -1) {
                    baos.write(buffer, 0, bytesRead);
                }
                respData = baos.toByteArray();
            }

            OCSPResp ocspResp = new OCSPResp(respData);
            if (ocspResp.getStatus() != OCSPResp.SUCCESSFUL) {
                return RevocationResult.error("OCSP", "OCSP response status: " + ocspResp.getStatus());
            }

            BasicOCSPResp basicResp = (BasicOCSPResp) ocspResp.getResponseObject();
            if (basicResp == null) {
                return RevocationResult.error("OCSP", "No basic OCSP response");
            }

            // Check all single responses
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

        } catch (java.net.SocketTimeoutException e) {
            return RevocationResult.error("OCSP", "Timeout connecting to OCSP responder: " + ocspUrl);
        } catch (Exception e) {
            return RevocationResult.error("OCSP", "Error checking OCSP: " + e.getMessage());
        }
    }

    /**
     * Convert OCSP/CRL revocation reason code to string.
     */
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
     * Check certificate revocation status using the best available method.
     * Tries OCSP first (faster), then falls back to CRL.
     *
     * @param cert the certificate to check
     * @param issuerCert the issuer certificate (may be null if only CRL is available)
     * @param timeoutMs connection timeout in milliseconds
     * @return RevocationResult indicating the status
     */
    public RevocationResult checkRevocation(X509Certificate cert, X509Certificate issuerCert, int timeoutMs) {
        if (cert == null) {
            return RevocationResult.error("NONE", "Certificate is null");
        }

        // Try OCSP first (faster, more current)
        if (issuerCert != null) {
            List<String> ocspUrls = extractOCSPResponderURLs(cert);
            for (String ocspUrl : ocspUrls) {
                RevocationResult result = checkOCSP(cert, issuerCert, ocspUrl, timeoutMs);
                if (result.getStatus() != RevocationStatus.ERROR) {
                    return result;
                }
                // If error, try next URL or fall back to CRL
            }
        }

        // Fall back to CRL
        List<String> crlUrls = extractCRLDistributionPoints(cert);
        for (String crlUrl : crlUrls) {
            RevocationResult result = checkCRL(cert, crlUrl, timeoutMs);
            if (result.getStatus() != RevocationStatus.ERROR) {
                return result;
            }
            // If error, try next URL
        }

        // No working revocation method found
        if (extractOCSPResponderURLs(cert).isEmpty() && crlUrls.isEmpty()) {
            return RevocationResult.unknown("NONE", "No CRL or OCSP information in certificate");
        }
        return RevocationResult.error("NONE", "All revocation checks failed");
    }

    // ==================== Cipher Suite Classification ====================

    /**
     * Cipher suite strength classification
     */
    public enum CipherStrength {
        /** Modern, secure cipher suite (AES-GCM, ChaCha20) */
        STRONG,
        /** Acceptable cipher suite (AES-CBC with HMAC) */
        ACCEPTABLE,
        /** Weak cipher suite (3DES, RC4) */
        WEAK,
        /** Insecure cipher suite (NULL, export, DES) */
        INSECURE,
        /** Unknown cipher suite */
        UNKNOWN
    }

    /**
     * Parsed cipher suite components
     */
    public static class CipherComponents {
        public final String name;
        public final String keyExchange;
        public final String authentication;
        public final String encryption;
        public final String mac;
        public final CipherStrength strength;
        public final boolean forwardSecrecy;

        public CipherComponents(String name, String keyExchange, String authentication,
                               String encryption, String mac, CipherStrength strength, boolean forwardSecrecy) {
            this.name = name;
            this.keyExchange = keyExchange;
            this.authentication = authentication;
            this.encryption = encryption;
            this.mac = mac;
            this.strength = strength;
            this.forwardSecrecy = forwardSecrecy;
        }
    }

    /**
     * Classify cipher suite strength by name.
     *
     * @param cipherSuiteName the cipher suite name (e.g., "TLS_AES_256_GCM_SHA384")
     * @return the strength classification
     */
    public CipherStrength classifyCipherSuiteStrength(String cipherSuiteName) {
        if (cipherSuiteName == null) return CipherStrength.UNKNOWN;

        String upper = cipherSuiteName.toUpperCase();

        // Insecure ciphers
        if (upper.contains("NULL") || upper.contains("EXPORT") ||
            upper.contains("_DES_") || upper.contains("ANON") ||
            upper.contains("MD5") || upper.contains("RC2")) {
            return CipherStrength.INSECURE;
        }

        // Weak ciphers
        if (upper.contains("3DES") || upper.contains("RC4") ||
            upper.contains("IDEA") || upper.contains("SEED") ||
            upper.contains("CAMELLIA")) {
            return CipherStrength.WEAK;
        }

        // Strong TLS 1.3 ciphers
        if (upper.startsWith("TLS_AES_") || upper.startsWith("TLS_CHACHA20_")) {
            return CipherStrength.STRONG;
        }

        // Strong ciphers with GCM or ChaCha20
        if (upper.contains("GCM") || upper.contains("CHACHA20") || upper.contains("CCM")) {
            return CipherStrength.STRONG;
        }

        // AES-CBC is acceptable
        if (upper.contains("AES") && upper.contains("CBC")) {
            return CipherStrength.ACCEPTABLE;
        }

        // Other AES modes
        if (upper.contains("AES")) {
            return CipherStrength.ACCEPTABLE;
        }

        return CipherStrength.UNKNOWN;
    }

    /**
     * Parse cipher suite name into components.
     *
     * @param cipherSuiteName the cipher suite name
     * @return parsed components
     */
    public CipherComponents parseCipherSuite(String cipherSuiteName) {
        if (cipherSuiteName == null) {
            return new CipherComponents("UNKNOWN", "UNKNOWN", "UNKNOWN", "UNKNOWN", "UNKNOWN",
                    CipherStrength.UNKNOWN, false);
        }

        String upper = cipherSuiteName.toUpperCase();
        CipherStrength strength = classifyCipherSuiteStrength(cipherSuiteName);

        // TLS 1.3 cipher suites (simpler format: TLS_AES_256_GCM_SHA384)
        if (upper.startsWith("TLS_AES_") || upper.startsWith("TLS_CHACHA20_")) {
            String encryption = extractEncryption(upper);
            String mac = extractMAC(upper);
            // TLS 1.3 always uses ephemeral key exchange
            return new CipherComponents(cipherSuiteName, "ECDHE/DHE", "Cert", encryption, mac, strength, true);
        }

        // TLS 1.2 and earlier (format: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)
        String keyExchange = extractKeyExchange(upper);
        String authentication = extractAuthentication(upper);
        String encryption = extractEncryption(upper);
        String mac = extractMAC(upper);
        boolean forwardSecrecy = upper.contains("DHE") || upper.contains("ECDHE");

        return new CipherComponents(cipherSuiteName, keyExchange, authentication, encryption, mac,
                strength, forwardSecrecy);
    }

    private String extractKeyExchange(String cipherName) {
        if (cipherName.contains("ECDHE")) return "ECDHE";
        if (cipherName.contains("DHE") || cipherName.contains("EDH")) return "DHE";
        if (cipherName.contains("ECDH")) return "ECDH";
        if (cipherName.contains("DH_")) return "DH";
        if (cipherName.contains("RSA")) return "RSA";
        if (cipherName.contains("PSK")) return "PSK";
        if (cipherName.contains("SRP")) return "SRP";
        return "UNKNOWN";
    }

    private String extractAuthentication(String cipherName) {
        if (cipherName.contains("_RSA_") || cipherName.contains("RSA_WITH")) return "RSA";
        if (cipherName.contains("ECDSA")) return "ECDSA";
        if (cipherName.contains("DSS")) return "DSS";
        if (cipherName.contains("ANON")) return "ANON";
        if (cipherName.contains("PSK")) return "PSK";
        return "RSA";
    }

    private String extractEncryption(String cipherName) {
        if (cipherName.contains("CHACHA20_POLY1305")) return "CHACHA20-POLY1305";
        if (cipherName.contains("AES_256_GCM")) return "AES-256-GCM";
        if (cipherName.contains("AES_128_GCM")) return "AES-128-GCM";
        if (cipherName.contains("AES_256_CCM")) return "AES-256-CCM";
        if (cipherName.contains("AES_128_CCM")) return "AES-128-CCM";
        if (cipherName.contains("AES_256_CBC")) return "AES-256-CBC";
        if (cipherName.contains("AES_128_CBC")) return "AES-128-CBC";
        if (cipherName.contains("AES256")) return "AES-256";
        if (cipherName.contains("AES128") || cipherName.contains("AES_")) return "AES-128";
        if (cipherName.contains("3DES")) return "3DES";
        if (cipherName.contains("DES_")) return "DES";
        if (cipherName.contains("RC4")) return "RC4";
        if (cipherName.contains("NULL")) return "NULL";
        return "UNKNOWN";
    }

    private String extractMAC(String cipherName) {
        if (cipherName.contains("SHA384")) return "SHA384";
        if (cipherName.contains("SHA256")) return "SHA256";
        if (cipherName.contains("SHA1") || cipherName.endsWith("SHA")) return "SHA1";
        if (cipherName.contains("MD5")) return "MD5";
        if (cipherName.contains("GCM") || cipherName.contains("CCM") || cipherName.contains("POLY1305")) {
            return "AEAD";
        }
        return "UNKNOWN";
    }

    // ==================== Protocol Version Classification ====================

    /**
     * Protocol version security classification
     */
    public enum ProtocolSecurity {
        /** Secure protocol (TLS 1.2, TLS 1.3) */
        SECURE,
        /** Deprecated protocol (TLS 1.0, TLS 1.1) */
        DEPRECATED,
        /** Critical security risk (SSLv2, SSLv3) */
        CRITICAL,
        /** Unknown protocol */
        UNKNOWN
    }

    /**
     * Classify protocol version security.
     *
     * @param protocolVersion the protocol version string (e.g., "TLSv1.3", "SSLv3")
     * @return security classification
     */
    public ProtocolSecurity classifyProtocolVersionSecurity(String protocolVersion) {
        if (protocolVersion == null) return ProtocolSecurity.UNKNOWN;

        String normalized = protocolVersion.toUpperCase().replace(" ", "");

        // TLS 1.3 and TLS 1.2 are secure
        if (normalized.contains("1.3") || normalized.contains("1.2")) {
            return ProtocolSecurity.SECURE;
        }

        // TLS 1.0 and TLS 1.1 are deprecated
        if (normalized.contains("1.1") || normalized.contains("1.0")) {
            return ProtocolSecurity.DEPRECATED;
        }

        // SSLv3 and SSLv2 are critical security risks
        if (normalized.contains("SSL") || normalized.contains("V3") || normalized.contains("V2")) {
            return ProtocolSecurity.CRITICAL;
        }

        return ProtocolSecurity.UNKNOWN;
    }

    /**
     * Check if a protocol version supports PQC key exchange.
     *
     * @param protocolVersion the protocol version string
     * @return true if the protocol can support PQC (TLS 1.3 only)
     */
    public boolean protocolSupportsPQC(String protocolVersion) {
        if (protocolVersion == null) return false;
        String normalized = protocolVersion.toUpperCase().replace(" ", "");
        return normalized.contains("1.3");
    }

}


