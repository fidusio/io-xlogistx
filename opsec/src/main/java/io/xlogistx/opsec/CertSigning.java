package io.xlogistx.opsec;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.zoxweb.server.security.CryptoUtil;
import org.zoxweb.shared.crypto.CryptoConst;
import org.zoxweb.shared.util.Const;
import org.zoxweb.shared.util.GetNameValue;
import org.zoxweb.shared.util.NVGenericMap;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;

public class CertSigning
{


    private static X509Certificate generateCertificate(NVGenericMap subject, PublicKey subjectPublicKey, String duration, CryptoConst.SignatureAlgo algorithm, X509Certificate issuerCert, PrivateKey issuerPrivateKey, boolean isCA) throws Exception {
        Date from = new Date();
        Date to = new Date(from.getTime() + Const.TimeInMillis.toMillis(duration));
        BigInteger serial = BigInteger.valueOf(from.getTime());

        //"SHA256withECDSA"
        ContentSigner contentSigner = new JcaContentSignerBuilder(algorithm.getName()).build(issuerPrivateKey);

        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                new X500Name(issuerCert == null ? toX500Name(subject): issuerCert.getSubjectX500Principal().getName()),
                serial, from, to, new X500Name(toX500Name(subject)), subjectPublicKey);


        if (isCA)
        {
            certBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints, true, new BasicConstraints(true));
        }

        X509CertificateHolder certHolder = certBuilder.build(contentSigner);
        return new JcaX509CertificateConverter().getCertificate(certHolder);
    }


    public static String toX500Name(NVGenericMap nvgm)
    {
        StringBuilder sb = new StringBuilder();
        for (GetNameValue<?> gnv : nvgm.values())
        {
            if (gnv.getValue() != null) {
                if (sb.length() > 0) {
                    sb.append(", ");
                }
                sb.append(gnv.getName());
                sb.append('=');
                sb.append(gnv.getValue());
            }
        }

        return sb.toString();
    }

    public static X509Certificate generateIntermediaryCertificate(NVGenericMap info, PublicKey intermediaryPublicKey, PrivateKey rootPrivateKey, X509Certificate rootCertificate) throws Exception {
        X500Name issuer = new X500Name(rootCertificate.getSubjectX500Principal().getName());
        X500Name subject = new X500Name(toX500Name(info));
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date();

        Date notAfter = new Date(System.currentTimeMillis() + Const.TimeInMillis.YEAR.MILLIS * 5); // 1 year validity
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer, serial, notBefore, notAfter, subject, intermediaryPublicKey
        );

        // Set BasicConstraints to indicate it's an intermediate certificate
        certBuilder.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints, true, new BasicConstraints(true));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(rootPrivateKey);
        X509CertificateHolder certHolder = certBuilder.build(signer);
        return new JcaX509CertificateConverter().getCertificate(certHolder);
    }


    public static X509Certificate generateRootCertificate(KeyPair keyPair) throws Exception {
        X500Name issuer = new X500Name("CN=Root Certificate");
        X500Name subject = issuer;
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date();
        Date notAfter = new Date(System.currentTimeMillis() + Const.TimeInMillis.YEAR.MILLIS*10); // 10 years validity
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(issuer, serial, notBefore, notAfter, subject, keyPair.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate());
        X509CertificateHolder certHolder = certBuilder.build(signer);
        return new JcaX509CertificateConverter().getCertificate(certHolder);
    }


    public static X509Certificate generateSignedCertificate(String commonName, PublicKey thirdPartyKey, X509Certificate issuerCert, PrivateKey issuerPrivateKey) throws Exception {

        X500Name subject = new X500Name("CN=" + commonName);
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date();
        Date notAfter = new Date(System.currentTimeMillis() + (365 * 24 * 60 * 60 * 1000L)); // 1 year validity
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(issuerCert, serial, notBefore, notAfter, subject, thirdPartyKey);
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(issuerPrivateKey);
        X509CertificateHolder certHolder = certBuilder.build(signer);
        return new JcaX509CertificateConverter().getCertificate(certHolder);
    }


    public static void main(String[] args){
//        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
//        keyGen.initialize(256);
//        KeyPair rootKeyPair = keyGen.generateKeyPair();
//        KeyPair thirdPartyKeyPair = keyGen.generateKeyPair();
//
//        X509Certificate rootCertificate = generateRootCertificate(rootKeyPair);
//        System.out.println("Root Certificate: ");
//        System.out.println(rootCertificate);
//
//        NVGenericMap nvgmIntermidiateInfo = new NVGenericMap()
//                .build("CN", "XlogistX Intermediary")
//                .build("O", "xlogistx.io")
//                .build("L", "Los Angeles")
//                .build("ST", "CA")
//                .build("C", "US");
//
//
//        X509Certificate signedCertificate = generateSignedCertificate("zabra.io" , thirdPartyKeyPair.getPublic(), rootCertificate, rootKeyPair.getPrivate());
//        System.out.println("\nSigned Certificate: ");
//        System.out.println(signedCertificate);
//        System.out.println(signedCertificate.getIssuerDN());
//
//        System.out.println(signedCertificate.getSubjectX500Principal());
//
//        System.out.println(toX500Name(nvgmIntermidiateInfo));





        try {
            Security.addProvider(new BouncyCastleProvider());


            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            keyGen.initialize(256);

            // Generate the Root Key Pair
            KeyPair rootKeyPair = CryptoUtil.generateKeyPair("EC", 521);
            X509Certificate rootCert = generateCertificate(new NVGenericMap().build("CN", "xlogistx.RootCA")
                    .build("O","xlogistx.io").build("OU", "OPSEC division"), rootKeyPair.getPublic(), "10years", CryptoConst.SignatureAlgo.SHA512_EC, null, rootKeyPair.getPrivate(), true);
            System.out.println("Root Certificate:");
            System.out.println(rootCert);

            // Generate Intermediate Key Pair and its Certificate
            KeyPair intermediateKeyPair = CryptoUtil.generateKeyPair("EC", 384);
            X509Certificate intermediateCert = generateCertificate(new NVGenericMap().build("CN", "IntermediateCA"), intermediateKeyPair.getPublic(), "6years", CryptoConst.SignatureAlgo.SHA384_EC, rootCert, rootKeyPair.getPrivate(), true);
            System.out.println("\nIntermediate Certificate:");
            System.out.println(intermediateCert);

            // Generate End-Entity Key Pair and its Certificate
            KeyPair endEntityKeyPair = CryptoUtil.generateKeyPair("RSA", 2048);
            X509Certificate endEntityCert = generateCertificate(new NVGenericMap().build("EMAILAddress", "user@xlogistx.io"), endEntityKeyPair.getPublic(), "180days", CryptoConst.SignatureAlgo.SHA256_EC, intermediateCert, intermediateKeyPair.getPrivate(), false);
            System.out.println("\nEnd-Entity Certificate:");
            System.out.println(endEntityCert);
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }



    }
}