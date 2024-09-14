import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

public class ECKeyEncryption {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws Exception {
        // Generate EC key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
        keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // Generate AES key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey aesKey = keyGen.generateKey();


        String text = "1234567890abcdefghijklmnopqrstuv";

        // Encrypt the AES key using the EC public key
        Cipher ecCipher = Cipher.getInstance("ECIES", "BC");
        ecCipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        byte[] encryptedAesKey = ecCipher.doFinal(text.getBytes("UTF-8"));
        String encryptedAesKeyBase64 = Base64.getEncoder().encodeToString(encryptedAesKey);
        System.out.println("Encrypted AES Key (Base64): " + encryptedAesKeyBase64 + " key size " +text.getBytes("UTF-8").length);

        // Save EC keys (in this example, we will just keep them in memory)
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // Decrypt the AES key using the EC private key
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
