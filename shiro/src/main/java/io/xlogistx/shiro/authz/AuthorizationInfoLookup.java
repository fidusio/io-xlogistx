package io.xlogistx.shiro.authz;

import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.subject.PrincipalCollection;

public interface AuthorizationInfoLookup
{
    AuthorizationInfo lookupAuthorizationInfo(PrincipalCollection pc);
}
