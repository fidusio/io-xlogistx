package io.xlogistx.opsec;


import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.channel.ClientChannel;
import org.apache.sshd.client.channel.ClientChannelEvent;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.keyprovider.FileKeyPairProvider;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
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
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.zoxweb.server.io.UByteArrayOutputStream;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.security.CryptoUtil;
import org.zoxweb.server.security.SecUtil;
import org.zoxweb.shared.crypto.CryptoConst;
import org.zoxweb.shared.security.SShURI;
import org.zoxweb.shared.util.*;

import javax.crypto.*;
import java.io.*;
import java.math.BigInteger;
import java.net.URI;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.*;


public class OPSecUtil {
    public static final LogWrapper log = new LogWrapper(OPSecUtil.class).setEnabled(false);

    public static final String BC_PROVIDER = "BC";
    public static final String BC_CKD_PROVIDER = "BCPQC";
    public static final String CK_NAME = "KYBER";
    public static final String CD_NAME = "DILITHIUM";


    public enum Argon2
            implements GetName {
        MEMORY(Const.SizeInBytes.K.mult(15)),
        SALT_LEN(16),
        HASH_LEN(32),
        ITERATIONS(3),
        PARALLELISM(1),
        HASH(-1),
        SALT(-1),

        ;
        public final int VAL;

        Argon2(int val) {
            this.VAL = val;
        }

        public String getName() {
            return name().toLowerCase();
        }


        public static NVGenericMap hashPassword(String password) {

            return hashPassword(SharedStringUtil.getBytes(password));
        }

        public static NVGenericMap hashPassword(byte[] password) {

            byte[] salt = SecUtil.SINGLETON.generateRandomBytes(SALT_LEN.VAL);
            byte[] hash = argon2idHash(password, HASH_LEN.VAL, salt, MEMORY.VAL, ITERATIONS.VAL, PARALLELISM.VAL);
            return new NVGenericMap()
                    .build(new NVBlob(HASH, hash))
                    .build(new NVBlob(SALT, salt))
                    .build(new NVInt(MEMORY, MEMORY.VAL))
                    .build(new NVInt(ITERATIONS, ITERATIONS.VAL))
                    .build(new NVInt(PARALLELISM, PARALLELISM.VAL));
        }


        public static boolean validate(String password, NVGenericMap hashInfo) {
            byte[] storedHash = hashInfo.getValue(HASH);
            byte[] passwordHash = argon2idHash(password,
                    storedHash.length, (byte[]) hashInfo.getValue(SALT), hashInfo.getValue(MEMORY), hashInfo.getValue(ITERATIONS), hashInfo.getValue(PARALLELISM)
            );

            return Arrays.equals(passwordHash, storedHash);
        }


        public static String argon2idCanID(String password) {
            return argon2idCanID(SharedStringUtil.getBytes(password));
        }

        public static String argon2idCanID(byte[] password) {
            byte[] salt = SecUtil.SINGLETON.generateRandomBytes(16);
            byte[] hash = argon2idHash(password, 32, salt, Const.SizeInBytes.K.mult(15), 2, 1);
            return argonToCanID("argon2id", 19, hash, salt, Const.SizeInBytes.K.mult(15), 2, 1);
        }


        public static String argonToCanID(String alg, int version, byte[] hash, byte[] salt, int memory, int iterations, int parallelism) {
//            String base64Salt = Base64.getEncoder().withoutPadding().encodeToString(salt);
//            String base64Hash = Base64.getEncoder().withoutPadding().encodeToString(hash);

            String base64Salt = SharedBase64.encodeAsString(SharedBase64.Base64Type.DEFAULT_NP, salt);
            String base64Hash = SharedBase64.encodeAsString(SharedBase64.Base64Type.DEFAULT_NP, hash);
            return String.format("$%s$v=%d$m=%d,t=%d,p=%d$%s$%s",
                    alg, version, memory, iterations, parallelism, base64Salt, base64Hash);
        }
    }


    // this section always on the top
//    static
//    {
//        SecUtil.SINGLETON.addProvider(new BouncyCastlePQCProvider());
//        SecUtil.SINGLETON.addProvider(new BouncyCastleProvider());
//
//    }


//    private final static Provider BC_PROVIDER = new BouncyCastleProvider();
//    private static Provider BC_CHRYSTAL_PROVIDER = new BouncyCastlePQCProvider();

    public final static OPSecUtil SINGLETON = new OPSecUtil();


    //private final static AtomicBoolean init = new AtomicBoolean(false);

    private OPSecUtil() {

//        System.out.println(SecUtil.SINGLETON.secProvidersToString(false));
//
//        // just wait after for the providers to propagate
//        TaskUtil.sleep(Const.TimeInMillis.SECOND.MILLIS*3);
//
//        System.out.println("OPSecUtil ready");
//        System.out.println(SecUtil.SINGLETON.secProvidersToString(false));
        // add any new provider
//        SecUtil.SINGLETON.addProvider(BC_PROVIDER);
//        SecUtil.SINGLETON.addProvider(BC_CHRYSTAL_PROVIDER);
//        BC_PROVIDER.getServices();
//        BC_CHRYSTAL_PROVIDER.getServices();
//        for (Provider prov : Security.getProviders())
//        {
//            if (prov.equals(BC_PROVIDER) || prov.equals(BC_CHRYSTAL_PROVIDER))
//                log.getLogger().info("\n"+SecUtil.SINGLETON.secProviderToString(prov, false));
//        }

        loadProviders();

    }


    public synchronized void reloadProviders() {
        boolean stat = SecUtil.SINGLETON.removeProvider(BC_CKD_PROVIDER);
        log.getLogger().info("Provider " + BC_CKD_PROVIDER + " removed: " + stat);
        stat = SecUtil.SINGLETON.removeProvider(BC_PROVIDER);
        log.getLogger().info("Provider " + BC_PROVIDER + " removed: " + stat);

        loadProviders();
    }

    public synchronized void loadProviders() {

        if (SecUtil.SINGLETON.getProvider(BC_PROVIDER) == null) {
            Provider prov = new BouncyCastleProvider();
            SecUtil.SINGLETON.addProvider(prov);
            checkProviderExists(BC_PROVIDER);
        }
        if (SecUtil.SINGLETON.getProvider(BC_CKD_PROVIDER) == null) {
            Provider prov = new BouncyCastlePQCProvider();
            SecUtil.SINGLETON.addProvider(prov);
            checkProviderExists(BC_CKD_PROVIDER);
        }
    }

    private static void checkProviderExists(String providerName) {
        Provider provider = SecUtil.SINGLETON.getProvider(providerName);
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
        return CryptoUtil.generateKeyPair(keyType, provider, SecUtil.SINGLETON.defaultSecureRandom());
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

    public  X509CertificateHolder generateSignedCertificate(
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

    public KeyPair generateKeyPair(CanonicalID keyType, String provider)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        return CryptoUtil.generateKeyPair(keyType, provider, SecUtil.SINGLETON.defaultSecureRandom());
    }

    public X509Certificate generateSelfSignedCertificate(KeyPair keyPair, X500Name issuer, X500Name subject, String duration) throws Exception {
        // Set the certificate's subject and issuer details

        // Validity period for the certificate
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + Const.TimeInMillis.toMillis(duration)); // 1 year

        // Create the certificate builder
        BigInteger serial = new BigInteger(64, SecUtil.SINGLETON.defaultSecureRandom());
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

    public PKCS10CertificationRequest generateCSR(KeyPair keyPair, String attr, String altNames) throws Exception {
        X500Name subject = createSubject(attr);
        PKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(subject, keyPair.getPublic());

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
            csrBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensionsGenerator.generate());
        }


        JcaContentSignerBuilder csBuilder = "EC".equalsIgnoreCase(keyPair.getPublic().getAlgorithm()) ?
                new JcaContentSignerBuilder(CryptoConst.SignatureAlgo.SHA256_EC.getName()) :
                new JcaContentSignerBuilder(CryptoConst.SignatureAlgo.SHA256_RSA.getName());

        ContentSigner signer = csBuilder.build(keyPair.getPrivate());
        return csrBuilder.build(signer);
    }


    public String convertPrivateKeyToPEM(PrivateKey privateKey) throws IOException {
        StringWriter stringWriter = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
            pemWriter.writeObject(privateKey);
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


    public static String sshCommand(SShURI sshURI, String password, String command) throws IOException {
        return sshCommand(sshURI.user, sshURI.port, sshURI.host, password, command);
    }


    public static String sshCommand(SShURI sshURI, KeyPair[] keyPairs, String command) throws IOException {
        return sshCommand(sshURI.user, sshURI.port, sshURI.host, keyPairs, command);
    }

    public static String sshCommand(String user, int port, String host, String password, String command) throws IOException {
        SshClient client = SshClient.setUpDefaultClient();
        client.start();

        try (ClientSession session = client.connect(user, host, port).verify(10000).getSession()) {
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
        keyGen.init(new KEMGenerateSpec(publicKey, "AES"), SecUtil.SINGLETON.defaultSecureRandom());
        return (SecretKeyWithEncapsulation) keyGen.generateKey();
    }

    public SecretKeyWithEncapsulation extractCKDecryptionKey(PrivateKey privateKey, byte[] encapsulatedKey)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyGenerator keyGen = KeyGenerator.getInstance("KYBER", "BCPQC");
        keyGen.init(new KEMExtractSpec(privateKey, encapsulatedKey, "AES"), SecUtil.SINGLETON.defaultSecureRandom());
        return (SecretKeyWithEncapsulation) keyGen.generateKey();
    }

    public byte[] encryptCKAESKey(PublicKey publicKey, byte[] aesKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, IllegalBlockSizeException {
        return encryptCKAESKey(publicKey, CryptoUtil.toSecretKey(aesKey, "AES"));
    }


    public byte[] encryptCKAESKey(PublicKey publicKey, SecretKey aesKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, IllegalBlockSizeException {
        Cipher kyberWrapCipher = Cipher.getInstance("Kyber", "BCPQC");
        kyberWrapCipher.init(Cipher.WRAP_MODE, publicKey, SecUtil.SINGLETON.defaultSecureRandom());
        return kyberWrapCipher.wrap(aesKey);
    }

    public Key decryptCKAESKey(PrivateKey privateKey, byte[] wrappedAesKeyBytes)
            throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, IllegalBlockSizeException {
        Cipher kyberUnwrapCipher = Cipher.getInstance("Kyber", "BCPQC");
        kyberUnwrapCipher.init(Cipher.UNWRAP_MODE, privateKey);
        return kyberUnwrapCipher.unwrap(wrappedAesKeyBytes, "AES", Cipher.SECRET_KEY);
    }


    public static byte[] argon2idHash(String password, int hashLength, int saltLength, int memory, int iterations, int parallelism) {
        return argon2idHash(SharedStringUtil.getBytes(password), hashLength, saltLength, memory, iterations, parallelism);
    }

    public static byte[] argon2idHash(byte[] password, int hashLength, int saltLength, int memory, int iterations, int parallelism) {


        return argon2idHash(password, hashLength, SecUtil.SINGLETON.generateRandomBytes(saltLength), memory, iterations, parallelism);
    }

    public static byte[] argon2idHash(String password, int hashLength, byte[] salt, int memory, int iterations, int parallelism) {
        return argon2idHash(SharedStringUtil.getBytes(password), hashLength, salt, memory, iterations, parallelism);
    }

    public static byte[] argon2idHash(byte[] password, int hashLength, byte[] salt, int memory, int iterations, int parallelism) {


        Argon2Parameters.Builder builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withSalt(salt)
                .withIterations(iterations)
                .withMemoryAsKB(memory)
                .withParallelism(parallelism);

        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(builder.build());

        byte[] hash = new byte[hashLength];
        generator.generateBytes(password, hash);
        return hash;
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


}

