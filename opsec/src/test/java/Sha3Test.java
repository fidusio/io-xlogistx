import org.junit.jupiter.api.Test;
import org.zoxweb.shared.util.RateCounter;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Sha3Test {
    @Test
    public void testSha3_256() throws NoSuchAlgorithmException {
        byte[][] aesKeys = new byte[1000][];
        String algorithm = "AES";
        KeyGenerator keyGen = KeyGenerator.getInstance(algorithm);
        keyGen.init(256); // AES-256
        SecretKey aesKey = keyGen.generateKey();

        RateCounter rc = new RateCounter("test");
        rc.start();
        for (int i = 0; i < aesKeys.length; i++) {
            aesKey = keyGen.generateKey();
            aesKeys[i] = aesKey.getEncoded();
        }
        rc.stop(aesKeys.length);
        System.out.println(algorithm + " generating aes-keys " + rc);
        rc.reset();
        rc.start();
        algorithm = "SHA-256";
        MessageDigest hasher = MessageDigest.getInstance(algorithm);
        hasher.digest(aesKey.getEncoded());
        for (int i = 0; i < aesKeys.length; i++) {
            hasher.digest(aesKeys[i]);
        }
        rc.stop(aesKeys.length);
        System.out.println(algorithm + " hashing " + rc);
        algorithm = "SHA3-256";
        hasher = MessageDigest.getInstance(algorithm);
        hasher.digest(aesKey.getEncoded());
        rc.reset();
        rc.start();
        for (int i = 0; i < aesKeys.length; i++) {
            hasher.digest(aesKeys[i]);
        }
        rc.stop(aesKeys.length);
        System.out.println(algorithm + " hashing " + rc);

    }

    @Test
    public void testSha3_512() throws NoSuchAlgorithmException {
        byte[][] aesKeys = new byte[10000][];
        String algorithm = "AES";
        KeyGenerator keyGen = KeyGenerator.getInstance(algorithm);
        keyGen.init(256); // AES-256
        SecretKey aesKey = keyGen.generateKey();

        RateCounter rc = new RateCounter("test");
        rc.start();
        for (int i = 0; i < aesKeys.length; i++) {
            aesKey = keyGen.generateKey();
            aesKeys[i] = aesKey.getEncoded();
        }
        rc.stop(aesKeys.length);
        System.out.println(algorithm + " generating aes-keys " + rc);
        rc.reset();
        rc.start();
        algorithm = "SHA-256";
        MessageDigest hasher = MessageDigest.getInstance(algorithm);
        hasher.digest(aesKey.getEncoded());
        for (int i = 0; i < aesKeys.length; i++) {
            hasher.digest(aesKeys[i]);
        }
        rc.stop(aesKeys.length);
        System.out.println(algorithm + " hashing " + rc);
        algorithm = "SHA3-512";
        hasher = MessageDigest.getInstance(algorithm);
        hasher.digest(aesKey.getEncoded());
        rc.reset();
        rc.start();
        for (int i = 0; i < aesKeys.length; i++) {
            hasher.digest(aesKeys[i]);
        }
        rc.stop(aesKeys.length);
        System.out.println(algorithm + " hashing " + rc);

    }
}
