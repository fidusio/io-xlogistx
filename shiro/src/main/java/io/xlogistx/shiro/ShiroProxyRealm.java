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

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {

        if(log.isEnabled()) log.getLogger().info(""+principals);
        String user = (String) principals.getPrimaryPrincipal();
        if (!SharedStringUtil.isEmpty(user))
        {
            SimpleAuthorizationInfo ret = new SimpleAuthorizationInfo();
            return ret;
        }
        return null;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
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
    public void setProperties(NVGenericMap properties) {
        this.configProperties = properties;
    }

    @Override
    public NVGenericMap getProperties() {
        return configProperties;
    }
}
