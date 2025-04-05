package io.xlogistx.opsec;


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
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.security.CryptoUtil;
import org.zoxweb.server.security.SecUtil;
import org.zoxweb.shared.crypto.CryptoConst;
import org.zoxweb.shared.util.*;

import javax.crypto.*;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;


public class OPSecUtil
{
    public static final LogWrapper log = new LogWrapper(OPSecUtil.class).setEnabled(false);

    public static final String BC_PROVIDER = "BC";
    public static final String BC_CKD_PROVIDER = "BCPQC";
    public static final String CK_NAME = "KYBER";
    public static final String CD_NAME = "DILITHIUM";





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

    private OPSecUtil()
    {

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


    public static  synchronized void reloadProviders()
    {
        Security.removeProvider(BC_CKD_PROVIDER);
        Security.removeProvider(BC_PROVIDER);
        loadProviders();
    }

    public static  synchronized void loadProviders()
    {
        if(Security.getProvider(BC_CKD_PROVIDER) == null)
        {
            Provider prov = new BouncyCastlePQCProvider();
            SecUtil.SINGLETON.addProvider(prov);
            log.getLogger().info("\n"+SecUtil.SINGLETON.secProviderToString(prov, false));
        }
        if(Security.getProvider(BC_PROVIDER) == null)
        {
            Provider prov = new BouncyCastleProvider();
            SecUtil.SINGLETON.addProvider(prov);
            log.getLogger().info("\n"+SecUtil.SINGLETON.secProviderToString(prov, false));
        }


    }


//    public static OPSecUtil SINGLETON()
//    {
//        if (SINGLETON == null)
//        {
//            ServerUtil.LOCK.lock();
//
//            try
//            {
//                if (SINGLETON == null)
//                {
////                    Security.insertProviderAt(new BouncyCastlePQCProvider(), 1);
////                    Security.insertProviderAt(new BouncyCastleProvider(), 2);
//
//
//
//
//                    SecUtil.SINGLETON.addProvider(BC_PROVIDER);
//                    SecUtil.SINGLETON.addProvider(BC_CHRYSTAL_PROVIDER);
//
////                    TaskUtil.sleep(Const.TimeInMillis.SECOND.MILLIS*5);
////                    System.out.println(SecUtil.SINGLETON.secProvidersToString(false));
//                    SINGLETON = new OPSecUtil();
//                }
//            }
//            finally
//            {
//                ServerUtil.LOCK.unlock();;
//            }
//        }
//        return SINGLETON;
//    }


    public X500Name createSubject(String attributes)
    {
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
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException
    {
        return CryptoUtil.generateKeyPair(keyType, provider, SecUtil.SINGLETON.defaultSecureRandom());
    }

    public KeyPair generateKeyPair(CanonicalID keyType, String provider)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException
    {
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
            throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException
    {
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
            throws IOException, CertificateException
    {
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
        while ((obj = pemParser.readObject()) != null)
        {
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
            if(cert instanceof X509Certificate)
            {
                System.out.println(((X509Certificate) cert).getNotAfter());
            }
        }

        // Load additional certificates from the chain file
        try (FileReader chainReader = new FileReader(chainFilePath);
             PEMParser chainParser = new PEMParser(chainReader)) {
            Object obj;
            while ((obj = chainParser.readObject()) != null) {

                if (obj instanceof Certificate) {
                    chain.add((Certificate) obj);
                }
                else if (obj instanceof X509CertificateHolder)
                {
                    chain.add(convertBCCertificateToJcaCertificate((X509CertificateHolder) obj));
                }
            }
        }

        // Load Private Key
        PrivateKey privateKey = null;
        try (PEMParser pemParser = new PEMParser(new PemReader(new FileReader(privateKeyFilePath)))) {
            List<Object> listObject = readPermObject(pemParser);



            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
            //System.out.println(listObject);
            for (Object object : listObject)
            {
                if (object instanceof PKCS8EncryptedPrivateKeyInfo)
                { // For encrypted private keys
                    PKCS8EncryptedPrivateKeyInfo encryptedPrivateKeyInfo = (PKCS8EncryptedPrivateKeyInfo) object;
                    InputDecryptorProvider decryptorProvider = new JceOpenSSLPKCS8DecryptorProviderBuilder().build(keyStorePassword.toCharArray());
                    privateKey = converter.getPrivateKey(encryptedPrivateKeyInfo.decryptPrivateKeyInfo(decryptorProvider));
                }
                else if (object instanceof PEMKeyPair)
                {
                    // Handling a key pair
                    PEMKeyPair keyPair = (PEMKeyPair) object;
                    //System.out.println("private key info: " + keyPair.getPrivateKeyInfo() + " " + keyPair.getPrivateKeyInfo().getPrivateKeyAlgorithm());
                    privateKey = converter.getPrivateKey(keyPair.getPrivateKeyInfo());
                }
                else if (object instanceof PrivateKeyInfo)
                { // Direct private key info
                    privateKey = converter.getPrivateKey((PrivateKeyInfo) object);
                }
            }
        }


        System.out.println("Key Format:" +  privateKey.getFormat() + " " + privateKey.getAlgorithm());

        // Create KeyStore
        KeyStore keyStore = KeyStore.getInstance(keyStoreType);
        keyStore.load(null, null);
        Certificate[] certificates = chain.toArray(new Certificate[0]);
        keyStore.setKeyEntry(SUS.isEmpty(certAlias) ? "keyalias" : certAlias, privateKey, keyStorePassword.toCharArray(), certificates);

        return keyStore;
    }


    public String extractFilename(String attrs)
    {
        ParamUtil.ParamMap params = ParamUtil.parse("=", attrs.split(","));
        if (params.stringValue("CN", true) != null)
        {
            return params.stringValue("CN");
        }

        if (params.stringValue("E", true) != null)
        {
            return params.stringValue("E").replace("@", "_");
        }
        throw new IllegalArgumentException(attrs + " no CN or E attribute found");
    }

    public String outputFilename(String outDir, String filename)
    {

        if(outDir != null)
            filename = SharedStringUtil.concat(outDir,  filename, "/");

        return filename;
    }

    public SecretKeyWithEncapsulation generateCKEncryptionKey(PublicKey publicKey)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException
    {
        KeyGenerator keyGen = KeyGenerator.getInstance("KYBER", "BCPQC");
        keyGen.init(new KEMGenerateSpec(publicKey, "AES"), SecUtil.SINGLETON.defaultSecureRandom());
        return (SecretKeyWithEncapsulation) keyGen.generateKey();
    }

    public SecretKeyWithEncapsulation extractCKDecryptionKey(PrivateKey privateKey, byte[] encapsulatedKey)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException
    {
        KeyGenerator keyGen = KeyGenerator.getInstance("KYBER", "BCPQC");
        keyGen.init(new KEMExtractSpec(privateKey, encapsulatedKey, "AES"), SecUtil.SINGLETON.defaultSecureRandom());
        return (SecretKeyWithEncapsulation)keyGen.generateKey();
    }

    public byte[] encryptCKAESKey(PublicKey publicKey, byte[] aesKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, IllegalBlockSizeException {
        return encryptCKAESKey(publicKey, CryptoUtil.toSecretKey(aesKey, "AES"));
    }



    public byte[] encryptCKAESKey(PublicKey publicKey, SecretKey aesKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, IllegalBlockSizeException
    {
        Cipher kyberWrapCipher = Cipher.getInstance("Kyber", "BCPQC");
        kyberWrapCipher.init(Cipher.WRAP_MODE, publicKey, SecUtil.SINGLETON.defaultSecureRandom());
        return kyberWrapCipher.wrap(aesKey);
    }
    public Key decryptCKAESKey(PrivateKey  privateKey, byte[] wrappedAesKeyBytes)
            throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, IllegalBlockSizeException
    {
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
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException
    {
        return CryptoUtil.generateKeyPair(type, provider, keySpec, random);
    }



}

