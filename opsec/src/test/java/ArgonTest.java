import com.password4j.Hash;
import com.password4j.Password;
import io.xlogistx.opsec.OPSecUtil;
import org.junit.jupiter.api.Test;
import org.zoxweb.shared.util.Const;
import org.zoxweb.shared.util.NVGenericMap;
import org.zoxweb.shared.util.RateCounter;
import org.zoxweb.shared.util.SharedBase64;

import java.security.SecureRandom;
import java.util.Arrays;

public class ArgonTest {

    private static final RateCounter rc = new RateCounter("test");

    @Test
    public void password4JTest() {
        // Hash the password

        Hash hash = Password.hash("myPassword123")
                .addRandomSalt()
                .withArgon2();

        String hashedPassword = hash.getResult();


        // Verify the password
        boolean valid = Password.check("myPassword123", hashedPassword).withArgon2();
        int length = 3;
        rc.reset().start();
        for (int i = 0; i < length; i++) {
            hash = Password.hash("myPassword123")
                    .addRandomSalt()
                    .withArgon2();

            hashedPassword = hash.getResult();


            // Verify the password
            valid = Password.check("myPassword123", hashedPassword).withArgon2();
        }

        rc.stop(length);
        System.out.println("Hash: " + hashedPassword);
        System.out.println("Password is valid: " + valid + " " + rc);
    }


    @Test
    public void bc() {
        // Example parameters
        int saltLength = 16;        // bytes
        int hashLength = 32;        // bytes
        int iterations = 3;         // time cost
        int memory = Const.SizeInBytes.K.mult(15);         // in KB (64 MB)
        int parallelism = 1;


        SecureRandom sc = new SecureRandom();
        String password = "myPassword123";
        byte[] salt = new byte[saltLength];
        sc.nextBytes(salt);

        // Hash


        int length = 3;

        byte[] hash = OPSecUtil.argon2idHash(password, salt, iterations, memory, parallelism, hashLength);
        rc.reset().start();
        boolean valid = false;
        for (int i = 0; i < length; i++) {
            salt = new byte[saltLength];
            sc.nextBytes(salt);
            hash = OPSecUtil.argon2idHash(password, salt, iterations, memory, parallelism, hashLength);
            valid = Arrays.equals(hash, OPSecUtil.argon2idHash(password, salt, iterations, memory, parallelism, hashLength));
        }

        // To verify, recompute the hash with same parameters and salt, and compare hashes

        rc.stop(length);
        System.out.println("Salt: " + SharedBase64.encodeAsString(SharedBase64.Base64Type.URL, salt));
        System.out.println("Hash: " + SharedBase64.encodeAsString(SharedBase64.Base64Type.URL, hash));
        System.out.println("Password valid: " + valid + " " + rc);
        NVGenericMap nvgm = OPSecUtil.Argon2.hashPassword(password);

        System.out.println("Password valid: " + OPSecUtil.Argon2.validate("pissoff", nvgm));
    }


}
