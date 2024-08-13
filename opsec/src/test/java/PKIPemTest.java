import io.xlogistx.opsec.OPSecUtil;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.shared.util.SharedBase64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Base64;

public class PKIPemTest {

    public static void main(String ...args)
    {
        try
        {
            int index = 0;
            String privateKeyPem = IOUtil.inputStreamToString(args[index++]);
            String publicKeyPem = IOUtil.inputStreamToString(args[index++]);

            PrivateKey privateKey = OPSecUtil.convertPemToPrivateKey(privateKeyPem);
            PublicKey publicKey = OPSecUtil.convertPemToPublicKey(publicKeyPem);
            System.out.println(privateKey.getFormat() + " " + privateKey.getAlgorithm());

            String cipherName = "ECIES";
            if (privateKey instanceof RSAPrivateKey) {
                RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) privateKey;
                BigInteger modulus = rsaPrivateKey.getModulus();
                int keySize = modulus.bitLength();
                cipherName = "RSA";
                System.out.println("RSA Key Size: " + keySize + " bits");
            } else if (privateKey instanceof ECPrivateKey) {
                ECPrivateKey ecPrivateKey = (ECPrivateKey) privateKey;
                int keySize = ecPrivateKey.getParams().getCurve().getField().getFieldSize();
                System.out.println("EC Key Size: " + keySize + " bits");
            } else {
                System.out.println("Not an EC private key.");
            }






            // Generate AES key
//            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
//            keyGen.init(256);
//            SecretKey aesKey = keyGen.generateKey();
//            System.out.println("AES Key: " + SharedBase64.encodeAsString(SharedBase64.Base64Type.DEFAULT, aesKey.getEncoded()));
            String aesKeyBase64 = "Lq/bGZ2qRJZMEIQqi3OeKth8+IpoZRd5/bevzaRVRVE=";



            // Encrypt the AES key using the EC public key
            Cipher pkCipher = Cipher.getInstance(cipherName, "BC");
            pkCipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedAesKey = pkCipher.doFinal(SharedBase64.decode(aesKeyBase64));
            String encryptedAesKeyBase64 = Base64.getEncoder().encodeToString(encryptedAesKey);
            System.out.println("Encrypted AES Key (Base64): " + encryptedAesKeyBase64 + " key size " + SharedBase64.decode(aesKeyBase64).length);

            // Save EC keys (in this example, we will just keep them in memory)

            // Decrypt the AES key using the EC private key
            pkCipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedAesKeyBytes = pkCipher.doFinal(Base64.getDecoder().decode(encryptedAesKeyBase64));
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
        catch (Exception e)
        {
            e.printStackTrace();
        }
    }
}
