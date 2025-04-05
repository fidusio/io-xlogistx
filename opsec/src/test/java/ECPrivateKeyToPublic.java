import io.xlogistx.opsec.OPSecUtil;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.math.ec.ECPoint;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.util.Base64;

public class ECPrivateKeyToPublic {
    static {
        OPSecUtil.loadProviders();
    }

    public static void main(String[] args) throws Exception {
        // Generate EC key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
        keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // Store the private key
        PrivateKey privateKey = keyPair.getPrivate();
        String privateKeyBase64 = Base64.getEncoder().encodeToString(privateKey.getEncoded());
        System.out.println("Private Key (Base64): " + privateKeyBase64);

        // Regenerate the public key from the private key
        KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
        ECPrivateKeySpec ecPrivateKeySpec = keyFactory.getKeySpec(privateKey, ECPrivateKeySpec.class);

        // Get the EC parameter spec
        ECNamedCurveParameterSpec spec = org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec("secp256r1");

        // Calculate the public key point
        ECPoint q = spec.getG().multiply(ecPrivateKeySpec.getS());

        // Create the public key spec and generate the public key
        ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(new java.security.spec.ECPoint(q.getAffineXCoord().toBigInteger(), q.getAffineYCoord().toBigInteger()), new ECNamedCurveSpec("secp256r1", spec.getCurve(), spec.getG(), spec.getN()));
        PublicKey regeneratedPublicKey = keyFactory.generatePublic(ecPublicKeySpec);

        // Generate AES key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey aesKey = keyGen.generateKey();

        // Encrypt the AES key using the regenerated EC public key
        Cipher ecCipher = Cipher.getInstance("ECIES", "BC");
        ecCipher.init(Cipher.ENCRYPT_MODE, regeneratedPublicKey);
        byte[] encryptedAesKey = ecCipher.doFinal(aesKey.getEncoded());
        String encryptedAesKeyBase64 = Base64.getEncoder().encodeToString(encryptedAesKey);
        System.out.println("Encrypted AES Key (Base64): " + encryptedAesKeyBase64);

        // Decrypt the AES key using the stored EC private key
        ecCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedAesKeyBytes = ecCipher.doFinal(Base64.getDecoder().decode(encryptedAesKeyBase64));
        SecretKey originalAesKey = new SecretKeySpec(decryptedAesKeyBytes, "AES");
        System.out.println("Decrypted AES Key: " + Base64.getEncoder().encodeToString(originalAesKey.getEncoded()));

        // Encrypt data using the decrypted AES key with IV
        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aesCipher.init(Cipher.ENCRYPT_MODE, originalAesKey);
        byte[] iv = aesCipher.getIV();
        byte[] encryptedData = aesCipher.doFinal("Hello, World!".getBytes());
        String encryptedDataBase64 = Base64.getEncoder().encodeToString(encryptedData);
        String ivBase64 = Base64.getEncoder().encodeToString(iv);
        System.out.println("Encrypted Data (Base64): " + encryptedDataBase64);
        System.out.println("IV (Base64): " + ivBase64);

        // Decrypt data using the decrypted AES key and IV
        aesCipher.init(Cipher.DECRYPT_MODE, originalAesKey, new IvParameterSpec(Base64.getDecoder().decode(ivBase64)));
        byte[] decryptedData = aesCipher.doFinal(Base64.getDecoder().decode(encryptedDataBase64));
        System.out.println("Decrypted Data: " + new String(decryptedData));
    }
}
