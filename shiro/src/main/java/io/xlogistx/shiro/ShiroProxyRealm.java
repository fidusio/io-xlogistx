package io.xlogistx.shiro;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.security.HashUtil;
import org.zoxweb.shared.crypto.CryptoConst;
import org.zoxweb.shared.crypto.PasswordDAO;
import org.zoxweb.shared.util.NVGenericMap;
import org.zoxweb.shared.util.SetNVProperties;
import org.zoxweb.shared.util.SharedStringUtil;

import java.security.NoSuchAlgorithmException;

public class ShiroProxyRealm extends AuthorizingRealm
implements SetNVProperties
{

    public static final LogWrapper log = new LogWrapper(ShiroProxyRealm.class).setEnabled(true);

    private NVGenericMap configProperties;



    /**
     * This is a proxy realm meaning it depends on a remote server that actually
     * has the Subject info such as username or userid and the user credentials
     * The proxy realm will make a http call to the remote authentication server
     * The current system must be registered with remote server and authenticate the
     * request with a JWT token that Identifies the current system
     * the api call is a post call with a payload of the authentication token
     * the payload is a json object {"principal": token.getPrincipal(), "credentials": token.getCredentials()}
     * The remote server must validate the proxyrealm identity first
     * second validate the subject token, if the 2 validations passes return a json object that contains both
     * AuthenticationInfo and AuthorizationInfo
     * @param token the authentication token containing the user's principal and credentials.
     * @return the token AuthenticationInfo
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {

        // This is a proxy realm it depends on a remote server that
        // has the Subject info such as username or userid and the user credentials
        // The proxy realm will make a http call to the remote authentication server
        // The current system must be registered with remote server and authenticate the
        // request with a JWT token that Identifies the current system
        // the api call is a post call with a payload of the authentication token
        // the payload is a json object {"principal": token.getPrincipal(), "credentials": token.getCredentials()}
        // The remote server must validate the re



        if(log.isEnabled()) log.getLogger().info(""+token.getPrincipal());
        String user = (String) token.getPrincipal();
        if (!SharedStringUtil.isEmpty(user))
        {
            try
            {
                PasswordDAO passwordDAO = HashUtil.toPassword(CryptoConst.HASHType.BCRYPT, 0, 5, "password!");
                return new SimpleAuthenticationInfo(user, passwordDAO, "proxy");
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();

            }
        }
        return null;
    }


    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {






        if(log.isEnabled()) log.getLogger().info(""+principals);
        String user = (String) principals.getPrimaryPrincipal();
        if (!SharedStringUtil.isEmpty(user))
        {
            return new SimpleAuthorizationInfo();
        }
        return null;
    }
    @Override
    public void setProperties(NVGenericMap properties) {
        this.configProperties = properties;
    }

    @Override
    public NVGenericMap getProperties() {
        return configProperties;
    }
}
