package io.xlogistx.opsec;


import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.channel.ClientChannel;
import org.apache.sshd.client.channel.ClientChannelEvent;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.keyprovider.FileKeyPairProvider;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
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
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
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
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
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

}


