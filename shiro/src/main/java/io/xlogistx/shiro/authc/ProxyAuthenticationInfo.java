package io.xlogistx.shiro.authc;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.MergableAuthenticationInfo;
import org.apache.shiro.authc.SaltedAuthenticationInfo;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;

public class ProxyAuthenticationInfo
        implements MergableAuthenticationInfo,
        SaltedAuthenticationInfo
{
    @Override
    public void merge(AuthenticationInfo info) {

    }

    @Override
    public ByteSource getCredentialsSalt() {
        return null;
    }

    @Override
    public PrincipalCollection getPrincipals() {
        return null;
    }

    @Override
    public Object getCredentials() {
        return null;
    }
}
