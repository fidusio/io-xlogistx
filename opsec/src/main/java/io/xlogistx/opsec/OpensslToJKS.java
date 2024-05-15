package io.xlogistx.opsec;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.zoxweb.shared.crypto.CryptoConst;
import org.zoxweb.shared.util.ParamUtil;
import org.zoxweb.shared.util.SharedStringUtil;

import java.io.ByteArrayInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class OpensslToJKS {

    static
    {
        Security.addProvider(new BouncyCastleProvider());
    }




    public static Certificate convertBCCertificateToJcaCertificate(X509CertificateHolder bcCertificate)
            throws IOException, CertificateException
    {
        // Get encoded form of the BouncyCastle Certificate
        byte[] encodedCertificate = bcCertificate.getEncoded();

        // Create a CertificateFactory
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

        // Generate Certificate
        return certificateFactory.generateCertificate(new ByteArrayInputStream(encodedCertificate));
    }

    public static KeyStore createKeyStore(String privateKeyFilePath, String certificateFilePath, String chainFilePath, String keyStoreType, String keyStorePassword) throws CertificateException, IOException, PKCSException, OperatorCreationException, KeyStoreException, NoSuchAlgorithmException {
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
        try (PEMParser pemParser = new PEMParser(new FileReader(privateKeyFilePath))) {
            Object object = pemParser.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

            if (object instanceof PKCS8EncryptedPrivateKeyInfo) { // For encrypted private keys
                PKCS8EncryptedPrivateKeyInfo encryptedPrivateKeyInfo = (PKCS8EncryptedPrivateKeyInfo) object;
                InputDecryptorProvider decryptorProvider = new JceOpenSSLPKCS8DecryptorProviderBuilder().build(keyStorePassword.toCharArray());
                privateKey = converter.getPrivateKey(encryptedPrivateKeyInfo.decryptPrivateKeyInfo(decryptorProvider));
            }  else if (object instanceof PEMKeyPair) { // Handling a key pair
                PEMKeyPair keyPair = (PEMKeyPair) object;
                privateKey = converter.getPrivateKey(keyPair.getPrivateKeyInfo());
            } else if (object instanceof PrivateKeyInfo) { // Direct private key info
                privateKey = converter.getPrivateKey((PrivateKeyInfo) object);
            }
        }

        // Create KeyStore
        KeyStore keyStore = KeyStore.getInstance(keyStoreType);
        keyStore.load(null, null);
        Certificate[] certificates = chain.toArray(new Certificate[0]);
        keyStore.setKeyEntry("keyalias", privateKey, keyStorePassword.toCharArray(), certificates);

        return keyStore;
    }

    public static void main(String[] args)
    {
        try {
            ParamUtil.ParamMap params = ParamUtil.parse("=", args);
            String cert = params.stringValue("cert");
            String key = params.stringValue("key");
            String chain = params.stringValue("chain");
            String domain = params.stringValue("domain");
            String password = params.stringValue("password");
            String keyStoreType = params.stringValue("ks_type", CryptoConst.PKCS12);
            String keyStoreDir = params.stringValue("ks_dir", null);

            KeyStore keyStore = createKeyStore(key, cert, chain, keyStoreType, password);
            // Store the keystore to filesystem
            String ksFilename = domain + ".jks";
            if(keyStoreDir != null)
                ksFilename = SharedStringUtil.concat(keyStoreDir,  domain + ".jks", "/");
            System.out.println(ksFilename);
            FileOutputStream fos = new java.io.FileOutputStream(ksFilename);
            keyStore.store(fos, password.toCharArray());
            fos.close();
        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("OpensslToJSK convert a pem certificate to java key store");
            System.err.println("Usage: OpensslToJKS cert=certificate key=private-key chain=chain-certificate domain=domain-name password=keystore-password [ks_type=keystore-type,JKS or PKCS12 ] [ks_dir=keystore-directory]");
        }
    }
}
