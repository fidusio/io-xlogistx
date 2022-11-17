package iot.xlogistx.okta;

import io.xlogistx.okta.api.OktaErrorCode;
import org.junit.jupiter.api.Test;

public class OktaUserTest {

    @Test
    public void oktaUserJsonTest()
    {
        //OktaUser user = new DefaultOktaUser().setOktaId("abcd");
    }
    @Test
    public void oktaErrorTest()
    {
        System.out.println(OktaErrorCode.getErrorMap());
        System.out.println(OktaErrorCode.getErrorMap().size());
    }
}
