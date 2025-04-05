import io.xlogistx.opsec.OPSecUtil;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.zoxweb.server.io.UByteArrayOutputStream;

import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;

public class PEMKeyReader {
    static {
        OPSecUtil.loadProviders();
    }


    public static KeyPair generateECKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1"); // Specify the curve
        keyPairGenerator.initialize(ecSpec);
        return keyPairGenerator.generateKeyPair();
    }

    public static void writePrivateKeyToPEM(PrivateKey privateKey) throws IOException {
        UByteArrayOutputStream baos = new UByteArrayOutputStream();
        try (Writer writer = new OutputStreamWriter(baos);
             JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
            pemWriter.writeObject(privateKey);
            pemWriter.flush();
            System.out.println(baos.toString());
        }
    }

    public static PrivateKey readPrivateKeyFromPEM(String filename) throws Exception {
        try (FileReader keyReader = new FileReader(filename);
             PEMParser pemParser = new PEMParser(keyReader)) {

            Object object = pemParser.readObject();
            System.out.println(object);
            if (object instanceof PrivateKeyInfo) {
                PrivateKeyInfo privateKeyInfo = (PrivateKeyInfo) object;
                JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
                return converter.getPrivateKey(privateKeyInfo);
            }else if (object instanceof PEMKeyPair) {
                PEMKeyPair pemKeyPair = (PEMKeyPair) object;

                JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

                // Extract the private key
                PrivateKey privateKey = converter.getPrivateKey(pemKeyPair.getPrivateKeyInfo());
                // Optionally, you can also extract the public key
                //PublicKey publicKey = converter.getPublicKey(pemKeyPair.getPublicKeyInfo());

                //System.out.println("Public Key: " + publicKey);
                return privateKey;
            }
            else {
                throw new IllegalArgumentException("The provided file does not contain a valid EC private key.");
            }
        }
    }

    public static void main(String[] args) throws PEMException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        try {
            // File containing EC PARAMETERS and EC PRIVATE KEY
            String filename = args[0];
            X9ECParameters ecParams = null;
            PrivateKey privateKey = readPrivateKeyFromPEM(filename);
            writePrivateKeyToPEM(generateECKeyPair().getPrivate());
            System.exit(0);
            try (FileReader keyReader = new FileReader(filename);
                 PEMParser pemParser = new PEMParser(keyReader)) {

                Object object;
                ASN1ObjectIdentifier oid = null;
                while ((object = pemParser.readObject()) != null) {
                    System.out.println("Object : " + object);
                    if (object instanceof ASN1ObjectIdentifier) {
                        // EC PARAMETERS
                         oid = (ASN1ObjectIdentifier) object;
                        ecParams = SECNamedCurves.getByOID(oid);
                        if (ecParams != null) {
                            System.out.println("EC Parameters loaded for OID: " + oid);
                        } else {
                            System.err.println("Unknown OID: " + oid);
                        }
                    } else if (object instanceof PrivateKeyInfo) {
                        // EC PRIVATE KEY
                        PrivateKeyInfo privateKeyInfo = (PrivateKeyInfo) object;
                        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

                        if (ecParams != null) {
                            BCECPrivateKey ecPrivateKey = (BCECPrivateKey) converter.getPrivateKey(privateKeyInfo);
                            BigInteger d = ecPrivateKey.getD();

                            // Use the EC parameters to correctly interpret the private key
                            EllipticCurve ellipticCurve = new EllipticCurve(
                                    new ECFieldFp(ecParams.getCurve().getField().getCharacteristic()),
                                    ecParams.getCurve().getA().toBigInteger(),
                                    ecParams.getCurve().getB().toBigInteger()
                            );
                            java.security.spec.ECPoint g = new java.security.spec.ECPoint(
                                    ecParams.getG().getAffineXCoord().toBigInteger(),
                                    ecParams.getG().getAffineYCoord().toBigInteger()
                            );
                            ECParameterSpec ecSpec = new ECParameterSpec(
                                    ellipticCurve, g, ecParams.getN(), ecParams.getH().intValue()
                            );

                            ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(d, ecSpec);
                            KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
                            privateKey = keyFactory.generatePrivate(privateKeySpec);
                            System.out.println("Private Key loaded with OID: " + oid);
                        } else {
                            // Without EC parameters, we can't proceed
                            System.err.println("EC Parameters are required to interpret the private key.");
                        }
                    } else if (object instanceof PEMKeyPair) {
                        // EC PRIVATE KEY
                        PEMKeyPair pemKeyPair = (PEMKeyPair) object;
                        PrivateKeyInfo privateKeyInfo = pemKeyPair.getPrivateKeyInfo();
                        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

                        if (ecParams != null) {
                            // Convert PrivateKeyInfo to BCECPrivateKey to extract 'd'
                            PrivateKey privKey = converter.getPrivateKey(privateKeyInfo);
                            BigInteger d = ((java.security.interfaces.ECPrivateKey) privKey).getS();

                            // Use the EC parameters to correctly interpret the private key
                            EllipticCurve ellipticCurve = new EllipticCurve(
                                    new ECFieldFp(ecParams.getCurve().getField().getCharacteristic()),
                                    ecParams.getCurve().getA().toBigInteger(),
                                    ecParams.getCurve().getB().toBigInteger()
                            );
                            ECPoint g = new ECPoint(
                                    ecParams.getG().getAffineXCoord().toBigInteger(),
                                    ecParams.getG().getAffineYCoord().toBigInteger()
                            );
                            ECParameterSpec ecSpec = new ECParameterSpec(
                                    ellipticCurve, g, ecParams.getN(), ecParams.getH().intValue()
                            );

                            ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(d, ecSpec);
                            KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
                            privateKey = keyFactory.generatePrivate(privateKeySpec);
                            System.out.println("Private Key loaded with OID: " + oid);
                        } else {
                            System.err.println("EC Parameters are required to interpret the private key.");
                        }
                    }
                }
            }

            if (privateKey == null || ecParams == null) {
                System.err.println("Failed to load EC Parameters or Private Key.");
            } else {
                System.out.println("Successfully loaded EC Parameters and Private Key.");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}