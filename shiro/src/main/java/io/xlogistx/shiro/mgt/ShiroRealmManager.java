package io.xlogistx.shiro.mgt;

import io.xlogistx.shiro.authz.AuthorizationInfoLookup;
import org.zoxweb.shared.security.AccessSecurityException;
import org.zoxweb.shared.security.shiro.ShiroAuthzInfo;
import org.zoxweb.shared.security.shiro.ShiroPermission;
import org.zoxweb.shared.security.shiro.ShiroRole;
import org.zoxweb.shared.security.shiro.ShiroRoleGroup;


public interface ShiroRealmManager
extends AuthorizationInfoLookup
{
    ShiroPermission addPermission(ShiroPermission permission)
            throws AccessSecurityException;
    ShiroPermission updatePermission(ShiroPermission permission)
            throws AccessSecurityException;
    ShiroPermission deletePermission(ShiroPermission permission)
            throws AccessSecurityException;

    ShiroRole addRole(ShiroRole shiroRole)
            throws AccessSecurityException;
    ShiroRole updateRole(ShiroRole shiroRole)
            throws AccessSecurityException;
    ShiroRole deleteRole(ShiroRole shiroRole)
            throws AccessSecurityException;


    ShiroRoleGroup addRoleGroup(ShiroRoleGroup shiroRoleGroup)
            throws AccessSecurityException;
    ShiroRoleGroup updateRoleGroup(ShiroRoleGroup shiroRoleGroup)
            throws AccessSecurityException;
    ShiroRoleGroup deleteRoleGroup(ShiroRoleGroup shiroRoleGroup)
            throws AccessSecurityException;


    ShiroAuthzInfo addShiroAuthzInfo(ShiroAuthzInfo shiroAuthzInfo)
            throws AccessSecurityException;
    ShiroAuthzInfo updateShiroAuthzInfo(ShiroAuthzInfo shiroAuthzInfo)
            throws AccessSecurityException;
    ShiroAuthzInfo deleteShiroAuthzInfo(ShiroAuthzInfo shiroAuthzInfo)
            throws AccessSecurityException;

}
