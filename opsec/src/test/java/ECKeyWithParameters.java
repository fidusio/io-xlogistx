import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.io.pem.PemGenerationException;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemObjectGenerator;

import java.io.IOException;
import java.io.StringWriter;
import java.security.*;
import java.security.spec.ECGenParameterSpec;

public class ECKeyWithParameters {

    public static class X9ECParametersPemObjectGenerator implements PemObjectGenerator {

        private X9ECParameters x9ECParameters;

        public X9ECParametersPemObjectGenerator(X9ECParameters x9ECParameters) {
            this.x9ECParameters = x9ECParameters;
        }

        @Override
        public PemObject generate() throws PemGenerationException {
            try {
                // Convert X9ECParameters to ASN1Primitive and then get encoded bytes

                byte[] encoded = x9ECParameters.toASN1Primitive().getEncoded("DER");
                return new PemObject("EC PARAMETERS", encoded);
            } catch (IOException e) {
                throw new PemGenerationException("Error encoding X9ECParameters: " + e.getMessage(), e);
            }
        }
    }


    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) {
        try {
            KeyPair keyPair = generateECKeyPair();
            String pemOutput = exportPrivateKeyToPEM(keyPair.getPrivate());
            System.out.println(pemOutput);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static KeyPair generateECKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "BC");
        keyGen.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
        return keyGen.generateKeyPair();
    }

    private static String exportPrivateKeyToPEM(PrivateKey privateKey) throws IOException {
        StringWriter stringWriter = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter);

        try {
            X9ECParameters ecParameters = ECNamedCurveTable.getByName("secp256r1");
            System.out.println(ecParameters.toASN1Primitive());
            X9ECParametersPemObjectGenerator pemGen = new X9ECParametersPemObjectGenerator(ecParameters);
            pemWriter.writeObject(pemGen.generate());
            pemWriter.writeObject(privateKey);
        } finally {
            pemWriter.close();
        }

        return stringWriter.toString();
    }
}
