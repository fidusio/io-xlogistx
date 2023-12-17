package io.xlogistx.shiro;

import io.xlogistx.shiro.authz.AuthorizationInfoLookup;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.realm.text.IniRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.zoxweb.server.logging.LogWrapper;

public class XlogistXIniRealm
extends IniRealm
implements AuthorizationInfoLookup
{
    public static final LogWrapper log = new LogWrapper(XlogistXIniRealm.class).setEnabled(false);
    public AuthorizationInfo lookupAuthorizationInfo(PrincipalCollection principalCollection)
    {
        return doGetAuthorizationInfo(principalCollection);
    }

    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals)
    {
        if(log.isEnabled()) log.getLogger().info("" + principals.getPrimaryPrincipal());
        return super.doGetAuthorizationInfo(principals);
    }


    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException
    {
        if(log.isEnabled()) log.getLogger().info("" + token.getPrincipal());
        return super.doGetAuthenticationInfo(token);
    }



}
