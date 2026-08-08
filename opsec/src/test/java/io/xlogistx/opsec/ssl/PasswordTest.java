package io.xlogistx.opsec.ssl;


import io.xlogistx.opsec.OPSecUtil;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.zoxweb.server.security.SHAPasswordHasher;
import org.zoxweb.shared.crypto.CIPassword;
import org.zoxweb.shared.util.RateCounter;

public class PasswordTest {

    private static final SHAPasswordHasher ONE_ROUND = new SHAPasswordHasher(1);
    @BeforeAll
    public static void init() {
        OPSecUtil.singleton();
    }


    @Test
    public void testBCrypt()
    {
        // use brypt
    }
    @Test
    public void testArgon()
    {

    }

    @Test
    public void testSHA256()
    {
        CIPassword password = ONE_ROUND.hash("Password1234%");
        System.out.println(password.toCanonicalID());
        RateCounter rc = new RateCounter();
        rc.start();

        int max = 10000;
        for(int i=0;i<max;i++)
        {
            password = ONE_ROUND.hash("Password1234%");
            if(!ONE_ROUND.validate(password, "Password1234%"))
            {
                System.out.println("password not valid");
            }

        }
        rc.stop(max);


        System.out.println(rc);
    }
    @Test
    public void testSHA512()
    {

    }
}
