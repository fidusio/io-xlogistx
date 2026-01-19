import com.password4j.Hash;
import com.password4j.Password;
import io.xlogistx.opsec.ArgonPasswordHasher;
import io.xlogistx.opsec.OPSecUtil;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.zoxweb.server.security.SecUtil;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.shared.crypto.CIPassword;
import org.zoxweb.shared.crypto.CredentialHasher;
import org.zoxweb.shared.util.RateCounter;
import org.zoxweb.shared.util.SharedBase64;

import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class ArgonTest {

    private static final RateCounter rc = new RateCounter("test");

    @BeforeAll
    public static void init()
    {
        OPSecUtil.SINGLETON.loadProviders();
    }


    @Test
    public void argon2Test() throws NoSuchAlgorithmException {
        // Hash the password

        Hash hash = Password.hash("myPassword123")
                .addRandomSalt()
                .withArgon2();

        String hashedPassword = hash.getResult();
        System.out.println(hashedPassword);
        CIPassword ciPassword =  SecUtil.fromCanonicalID(hashedPassword);
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


    @Test
    public void password4JTest() {
        String password = "myPassword!23";



        int length = 3;

        CredentialHasher<CIPassword> argonHasher =  SecUtil.lookupCredentialHasher("argon2");
        CIPassword ciPassword = argonHasher.hash(password);//ArgonPasswordHasher.Argon2.argon2idHash(password, hashLength, salt, memory, iterations, parallelism);
        rc.reset().start();
        boolean valid = false;
        for (int i = 0; i < length; i++) {
            ciPassword = argonHasher.hash(password);//ArgonPasswordHasher.Argon2.argon2idHash(password, hashLength, salt, memory, iterations, parallelism);
            valid = argonHasher.validate(ciPassword, password);
            assert valid;
            System.out.println("CAN ID: " + ciPassword.toCanonicalID());

        }

        // To verify, recompute the hash with same parameters and salt, and compare hashes

        rc.stop(length);

        assert SharedBase64.encodeAsString(SharedBase64.Base64Type.DEFAULT_NP, ciPassword.getHash()).equals(Base64.getEncoder().withoutPadding().encodeToString(ciPassword.getHash()));
        System.out.println("Hash: " + SharedBase64.encodeAsString(SharedBase64.Base64Type.DEFAULT_NP, ciPassword.getHash()));
        System.out.println("Hash: " + Base64.getEncoder().withoutPadding().encodeToString(ciPassword.getHash()));
        System.out.println("Password valid: " + valid + " " + rc);
        CIPassword argon2Password = argonHasher.hash(password);

        System.out.println("Password valid: " + argonHasher.validate(argon2Password, password));
        System.out.println("Password valid: " + Password.check(password, argon2Password.getCanonicalID()).withArgon2());
        String canID = ciPassword.getCanonicalID();
        System.out.println("canID: "+ canID);

    }

    @Test
    public void genByPassword4JValidatedByBC()
    {
        String password = "myPassword!23";
        Hash hash = Password.hash(password)
                .addRandomSalt()
                .withArgon2();

        String argon2CanID  = hash.getResult();
        System.out.println("Password4J generated: " + argon2CanID);
        CredentialHasher<CIPassword> argonHasher =  SecUtil.lookupCredentialHasher("argon2");
        CIPassword ciPassword = argonHasher.fromCanonicalID(argon2CanID);
        assert argonHasher.validate(ciPassword, password);
    }

    @Test
    public void genByBCValidatedByPassword4J()
    {
        String password = "myPassword!23";
        CredentialHasher<CIPassword> argonHasher =  new ArgonPasswordHasher(ArgonPasswordHasher.Argon2.MEMORY.VAL, 2, 1, 64, 32);
        CIPassword ciPassword = argonHasher.hash(password);
        assert Password.check(password, ciPassword.getCanonicalID())
                .withArgon2();
    }


}
