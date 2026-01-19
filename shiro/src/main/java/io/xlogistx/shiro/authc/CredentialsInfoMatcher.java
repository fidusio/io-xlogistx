package io.xlogistx.shiro.authc;

import io.xlogistx.shiro.DomainPrincipalCollection;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.apache.shiro.authc.credential.SimpleCredentialsMatcher;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.security.*;
import org.zoxweb.shared.crypto.CIPassword;
import org.zoxweb.shared.security.JWT;
import org.zoxweb.shared.security.SubjectAPIKey;
import org.zoxweb.shared.util.Const.Status;
import org.zoxweb.shared.util.SharedStringUtil;

public class CredentialsInfoMatcher implements CredentialsMatcher {
    public static final LogWrapper log = new LogWrapper(CredentialsInfoMatcher.class).setEnabled(false);
    private static final SimpleCredentialsMatcher SIMPLE_C_M = new SimpleCredentialsMatcher();

//    public CredentialsInfoMatcher() {
//        SecUtil.addCredentialHasher(new SHAPasswordHasher(8196))
//                .addCredentialHasher(new BCryptPasswordHasher(10));
//    }

    @Override
    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
        try {
            if (log.isEnabled())
                log.getLogger().info("credentials " + info.getCredentials() + " " + info.getCredentials().getClass());
            CIPassword ciPassword = null;
            if (info.getCredentials() instanceof CIPassword) {
                ciPassword = (CIPassword) info.getCredentials();
            } else if (info.getCredentials() instanceof String) {
                ciPassword = SecUtil.fromCanonicalID((String) info.getCredentials());
            }

            if (ciPassword != null) {
                if (!token.getPrincipal().equals(info.getPrincipals().getPrimaryPrincipal())) {
                    return false;
                }

                if (token instanceof DomainUsernamePasswordToken
                        && ((DomainUsernamePasswordToken) token).isAutoAuthenticationEnabled()) {
                    return true;
                }

                //if(log.isEnabled()) log.getLogger().info("SimpleAuthentication token:" + token.getClass().getName());

                String password = null;

                if (token.getCredentials() instanceof char[]) {
                    password = new String((char[]) token.getCredentials());
                } else if (token.getCredentials() instanceof byte[]) {
                    password = SharedStringUtil.toString((byte[]) token.getCredentials());
                } else if (token.getCredentials() instanceof String) {
                    password = (String) token.getCredentials();
                }

                return SecUtil.isPasswordValid(ciPassword, password);
            } else if (info.getCredentials() instanceof SubjectAPIKey && token instanceof JWTAuthenticationToken) {
                //if(log.isEnabled()) log.getLogger().info("JWTAuthenticationToken");
                SubjectAPIKey sak = (SubjectAPIKey) info.getCredentials();
                if (sak.getStatus() != Status.ACTIVE) {
                    // not active anymore
                    return false;
                }
                if (sak.getExpiryDate() != 0) {
                    if (System.currentTimeMillis() > sak.getExpiryDate()) {
                        return false;
                    }
                }
                JWT jwt = JWTProvider.SINGLETON.decode(sak.getAPIKeyAsBytes(), (String) token.getCredentials());
                if (info instanceof DomainAuthenticationInfo) {
                    DomainAuthenticationInfo dai = (DomainAuthenticationInfo) info;
                    DomainPrincipalCollection dpc = (DomainPrincipalCollection) dai.getPrincipals();
                    // if the token is not matching the domain id and app id we have a problem
                    if (!(dpc.getDomainID().equalsIgnoreCase(jwt.getPayload().getDomainID()) &&
                            dpc.getAppID().equalsIgnoreCase(jwt.getPayload().getAppID()))) {
                        return false;
                    }
                }
                return true;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return false;
    }

}
