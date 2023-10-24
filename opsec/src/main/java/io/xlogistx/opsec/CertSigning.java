package io.xlogistx.opsec;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;

public class CertSigning
{




    public static String getCommonName(X509Certificate certificate) {
        try {
            LdapName ldapName = new LdapName(certificate.getSubjectX500Principal().getName());
            for (Rdn rdn : ldapName.getRdns()) {
                if (rdn.getType().equalsIgnoreCase("CN")) {
                    return rdn.getValue().toString();
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }



    public static X509Certificate generateRootCertificate(KeyPair keyPair) throws Exception {
        X500Name issuer = new X500Name("CN=Root Certificate");
        X500Name subject = issuer;
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date();
        Date notAfter = new Date(System.currentTimeMillis() + (365 * 24 * 60 * 60 * 1000L*10)); // 10 years validity
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(issuer, serial, notBefore, notAfter, subject, keyPair.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate());
        X509CertificateHolder certHolder = certBuilder.build(signer);
        return new JcaX509CertificateConverter().getCertificate(certHolder);
    }


    public static X509Certificate generateSignedCertificate(String commonName, PublicKey thirdPartyKey, X509Certificate issuerCert, PrivateKey rootPrivate) throws Exception {

        X500Name subject = new X500Name("CN=" + commonName);
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date();
        Date notAfter = new Date(System.currentTimeMillis() + (365 * 24 * 60 * 60 * 1000L)); // 1 year validity
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(issuerCert, serial, notBefore, notAfter, subject, thirdPartyKey);
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(rootPrivate);
        X509CertificateHolder certHolder = certBuilder.build(signer);
        return new JcaX509CertificateConverter().getCertificate(certHolder);
    }


    public static void main(String[] args) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);
        KeyPair rootKeyPair = keyGen.generateKeyPair();
        KeyPair thirdPartyKeyPair = keyGen.generateKeyPair();

        X509Certificate rootCertificate = generateRootCertificate(rootKeyPair);
        System.out.println("Root Certificate: ");
        System.out.println(rootCertificate);

        X509Certificate signedCertificate = generateSignedCertificate("zabra.io" , thirdPartyKeyPair.getPublic(), rootCertificate, rootKeyPair.getPrivate());
        System.out.println("\nSigned Certificate: ");
        System.out.println(signedCertificate);
        System.out.println(signedCertificate.getIssuerDN());

        System.out.println(signedCertificate.getSubjectX500Principal());

    }
}