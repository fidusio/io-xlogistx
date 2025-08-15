import com.password4j.Hash;
import com.password4j.Password;
import io.xlogistx.opsec.ArgonPasswordHasher;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.zoxweb.server.security.SecUtil;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.shared.crypto.CIPassword;
import org.zoxweb.shared.util.RateCounter;

import java.security.NoSuchAlgorithmException;

public class ArgonTest {

    private static final RateCounter rc = new RateCounter("test");

    private static final ArgonPasswordHasher argon2Hasher = new ArgonPasswordHasher(ArgonPasswordHasher.Argon2.MEMORY.VAL, ArgonPasswordHasher.Argon2.ROUNDS.VAL, ArgonPasswordHasher.Argon2.PARALLELISM.VAL);

    @BeforeAll
    public static void init()
    {

        SecUtil.SINGLETON.addCredentialHasher(new ArgonPasswordHasher(ArgonPasswordHasher.Argon2.MEMORY.VAL, ArgonPasswordHasher.Argon2.ROUNDS.VAL, ArgonPasswordHasher.Argon2.PARALLELISM.VAL));
    }


    @Test
    public void password4JTest() throws NoSuchAlgorithmException {
        // Hash the password

        Hash hash = Password.hash("myPassword123")
                .addRandomSalt()
                .withArgon2();

        String hashedPassword = hash.getResult();
        System.out.println(hashedPassword);
        CIPassword ciPassword =  SecUtil.SINGLETON.fromCanonicalID(hashedPassword);
        System.out.println(GSONUtil.toJSONDefault(ciPassword,true));


        // Verify the password
        boolean valid = Password.check("myPassword123", ciPassword.toCanonicalID()).withArgon2();
        assert valid;
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


//    @Test
//    public void bc() {
//        // Example parameters
//        int saltLength = 16;        // bytes
//        int hashLength = 32;        // bytes
//        int iterations = 3;         // time cost
//        int memory = Const.SizeInBytes.K.mult(15);         // in KB (64 MB)
//        int parallelism = 1;
//
//
//
//        String password = "myPassword123";
//
//
//        // Hash
//        byte[] salt = SecUtil.SINGLETON.generateRandomBytes(16);
//
//        int length = 3;
//
//        byte[] hash = ArgonPasswordHasher.Argon2.argon2idHash(password, hashLength, salt, memory, iterations, parallelism);
//        rc.reset().start();
//        boolean valid = false;
//        for (int i = 0; i < length; i++) {
//            hash = ArgonPasswordHasher.Argon2.argon2idHash(password, hashLength, salt, memory, iterations, parallelism);
//            valid = Arrays.equals(hash, ArgonPasswordHasher.Argon2.argon2idHash(password, hashLength, salt, memory, iterations, parallelism));
//            assert valid;
//        }
//
//        // To verify, recompute the hash with same parameters and salt, and compare hashes
//
//        rc.stop(length);
//
//        System.out.println("Hash: " + SharedBase64.encodeAsString(SharedBase64.Base64Type.DEFAULT_NP, hash));
//        System.out.println("Password valid: " + valid + " " + rc);
//        NVGenericMap nvgm = ArgonPasswordHasher.Argon2.hashPassword(password);
//
//        System.out.println("Password valid: " + ArgonPasswordHasher.Argon2.validate("myPassword123", nvgm));
//        String canID = ArgonPasswordHasher.Argon2.argon2idCanID(password);
//        System.out.println(canID);
//        assert Password.check("myPassword123", canID).withArgon2();
//    }


}
