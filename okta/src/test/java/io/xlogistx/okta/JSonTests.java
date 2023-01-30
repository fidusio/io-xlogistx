package io.xlogistx.okta;

import io.xlogistx.okta.api.DefaultOktaUser;
import io.xlogistx.okta.api.DefaultOktaUserProfile;
import io.xlogistx.okta.api.OktaCredentials;
import io.xlogistx.okta.api.OktaUser;
import org.junit.jupiter.api.Test;
import org.zoxweb.server.util.GSONUtil;


public class JSonTests {



    @Test
    public void oktaUser()
    {
        System.out.println(System.getProperties().get("java.version"));
        OktaUser oktaUser = new DefaultOktaUser().setOktaProfile(new DefaultOktaUserProfile());
        OktaCredentials opc = new OktaCredentials();
        opc.setPlainPassword("Password!@34");

        oktaUser.setCredentials(opc).getOktaProfile().setUserName("tata@tata.com")
                .setFirstName("Cody")
                .setLastName("Ninja")
                .setEmail("tata@tata.com")
                .setMobilePhone("+13105555555");




        String json = GSONUtil.toJSONDefault(oktaUser);

        System.out.println(json);
        OktaUser regenerated = GSONUtil.fromJSONDefault(json, DefaultOktaUser.class);
        String jsonReg = GSONUtil.toJSONDefault(regenerated);
        assert jsonReg.equals(json);
        System.out.println(jsonReg);

    }
}
