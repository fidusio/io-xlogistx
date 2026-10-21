package io.xlogistx.shiro.ds;

import io.xlogistx.shiro.ShiroUtil;
import org.zoxweb.shared.app.AppIDDefault;
import org.zoxweb.shared.security.*;
import org.zoxweb.shared.security.model.SecurityModel;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.shared.util.DataEncoder;
import org.zoxweb.shared.util.SUS;

import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Flattens a subject's grants into the role names and Shiro permission strings the realm hands to
 * Shiro. Every subject first receives its self permission
 * {@code resource:<S>:<S>:create,read,update,delete,share}. A {@link PermissionGrant} contributes its
 * inlined token or its catalog token; when it embeds a {@link ResourceMap} the stored
 * {@code resource:<verbs>} is composed into {@code resource:<resource guid>:<grantee guid>:<verbs>}
 * ({@link SecurityModel#toResourceToken(String, String, String)}); a {@link RoleGrant} contributes
 * the role name and the role's permission tokens; a {@link RoleGroupGrant} does the same for every
 * role of the group (each re-read by GUID so nested permission references resolve).
 * <p>
 * <b>Login scope (user decision 2026-09-18).</b> A grant whose {@code app_id} is set is the
 * subject's assignment to that app. Which grants apply is decided by the login: a login with
 * domain and app loads <em>only</em> the grants scoped to that app, a login without loads
 * <em>only</em> the global (unscoped) grants. <b>The super-admin is the exception:</b> its global
 * grants (the {@code *}) apply in every login, app or not. Loaded grants flatten as plain tokens,
 * never prefixed. A wildcard token is emitted only for the super-admin subject (defense in depth
 * behind the manager guards).
 * <p>
 * <b>App-owned rows (dual ownership, user decision 2026-10-20).</b> A catalog token of the form
 * {@code app_resource:<fqcn>:<verbs>} ({@link SecurityModel#APP_RESOURCE}) is a right on the rows
 * the app owns in that class. For a login into an app whose record exists it is composed into the
 * checked form {@code app_resource:<app guid>:<fqcn>:<subject guid>:<verbs>}
 * ({@link SecurityModel#toAppResourceToken(String, String, String, String)}), the token the access
 * check asks for a row carrying that {@code app_guid}; for a global login, or when the app has no
 * record, such a token is dropped: nobody holds app rights outside a login into the app.
 */
public final class GrantFlattener {

    public static final class Result {
        public final Set<String> roles = new LinkedHashSet<>();
        public final Set<String> permissions = new LinkedHashSet<>();

        public boolean isEmpty() {
            return roles.isEmpty() && permissions.isEmpty();
        }
    }

    private GrantFlattener() {
    }

    public static final LogWrapper log = new LogWrapper(GrantFlattener.class).setEnabled(true);

    /** The global grants of the subject (a login without domain/app). */
    public static Result flatten(DomainSecurityManager dsm, String subjectGUID) {
        return flatten(dsm, subjectGUID, null);
    }

    /**
     * The grants that apply to a login scope: {@code scope == null} selects the global grants only,
     * otherwise only the grants scoped to that app (domain and app compared case-insensitively),
     * plus, for the super-admin subject, its global grants in any scope.
     */
    public static Result flatten(DomainSecurityManager dsm, String subjectGUID, AppIDDefault scope) {
        Result ret = new Result();
        if (dsm == null || SUS.isEmpty(subjectGUID)) {
            return ret;
        }
        boolean superAdmin = dsm.isSuperAdminSubject(subjectGUID);
        // the app record of the login scope (the scope object carries no GUID): its GUID is the app_guid of the
        // rows the app owns, the first part the app-resource tokens of this login are composed with
        String appGUID = appGUIDOf(dsm, scope);
        // The self permission every subject holds on its own resources (user decision 2026-09-29):
        // resource:<S>:<S>:create,read,update,delete,share — synthesized here, never stored, present in
        // every login scope. Ownership of an entity is thereby a permission like any other.
        ret.permissions.add(SecurityModel.toResourceToken(subjectGUID, subjectGUID, SecurityModel.RESOURCE_SELF_VERBS));
        for (PermissionGrant g : dsm.getPermissionGrants(subjectGUID)) {
            if (inScope(g, scope, superAdmin)) {
                addPermission(ret, permissionString(dsm, g), superAdmin, subjectGUID, appGUID);
            }
        }
        for (RoleGrant g : dsm.getRoleGrants(subjectGUID)) {
            if (inScope(g, scope, superAdmin)) {
                addRole(ret, dsm.lookupRoleByGUID(g.getRoleGUID()), superAdmin, subjectGUID, appGUID);
            }
        }
        for (RoleGroupGrant g : dsm.getRoleGroupGrants(subjectGUID)) {
            if (!inScope(g, scope, superAdmin)) {
                continue;
            }
            RoleGroupInfo group = dsm.lookupRoleGroupByGUID(g.getRoleGroupGUID());
            RoleInfo[] roles = group != null ? group.getRoles() : null;
            if (roles != null) {
                for (RoleInfo role : roles) {
                    if (role != null && !SUS.isEmpty(role.getGUID())) {
                        RoleInfo full = dsm.lookupRoleByGUID(role.getGUID());
                        addRole(ret, full != null ? full : role, superAdmin, subjectGUID, appGUID);
                    }
                }
            }
        }
        return ret;
    }

    /**
     * The GUID of the stored record of the login scope, null for a global login or an app without
     * record (then no app-resource token is emitted; the login gate refuses such a scope anyway).
     */
    static String appGUIDOf(DomainSecurityManager dsm, AppIDDefault scope) {
        if (scope == null) {
            return null;
        }
        try {
            AppIDDefault record = dsm.lookupApp(scope.getDomainID(), scope.getAppID());
            return record != null ? record.getGUID() : null;
        } catch (RuntimeException e) {
            log.getLogger().warning("app record of " + ShiroUtil.appScope(scope) + " not resolved: " + e);
            return null;
        }
    }

    /**
     * True if the grant belongs to the login scope. No domain/app means the common app, for the
     * grant as for the login ({@link ShiroUtil#scopeLabel}); a grant and a login
     * of the same app match. Two exceptions: the super-admin's unscoped grants (its {@code *})
     * belong to every scope, and a grant on a resource (a share, which embeds a {@code ResourceMap})
     * follows the data, not the app — it applies in every login.
     */
    static boolean inScope(AuthzInfo grant, AppIDDefault scope, boolean superAdmin) {
        if (grant instanceof PermissionGrant && ((PermissionGrant) grant).getResourceMap() != null) {
            return true;
        }
        AppIDDefault app = grant.getAppID();
        if (app == null && superAdmin) {
            return true;
        }
        return ShiroUtil.scopeLabel(app).equals(ShiroUtil.scopeLabel(scope));
    }

    static String permissionString(DomainSecurityManager dsm, PermissionGrant permissionGrant) {
        String token = permissionGrant.getPermissionToken();
        if (SUS.isEmpty(token)) {
            PermissionInfo p = dsm.lookupPermissionByGUID(permissionGrant.getPermissionGUID());
            token = p != null ? p.getPermissionToken() : null;
        }
        if (SUS.isEmpty(token)) {
            return null;
        }
        ResourceMap rm = permissionGrant.getResourceMap();
        if (rm != null && !SUS.isEmpty(rm.getResourceGUID())) {
            // scoped grant: the stored 2-part token resource:<verbs> becomes the standardized
            // resource:<resource guid>:<grantee guid>:<verbs>
            try {
                return SecurityModel.toResourceToken(rm.getResourceGUID(), permissionGrant.getSubjectGUID(), token);
            } catch (IllegalArgumentException | NullPointerException e) {
                log.getLogger().warning("skipped scoped grant " + permissionGrant.getGUID()
                        + ": token is not resource:<verbs>: " + token + " (" + e.getMessage() + ")");
                return null;
            }
        }
        return DataEncoder.StringLower.encode(token);
    }

    static void addRole(Result ret, RoleInfo role, boolean wildcardOK, String subjectGUID, String appGUID) {
        if (role == null) {
            return;
        }
        if (!SUS.isEmpty(role.getName())) {
            ret.roles.add(role.getName());
        }
        PermissionInfo[] permissions = role.getPermissions();
        if (permissions != null) {
            for (PermissionInfo p : permissions) {
                if (p != null) {
                    addPermission(ret, SUS.toLowerCase(p.getPermissionToken()), wildcardOK, subjectGUID, appGUID);
                }
            }
        }
    }

    /**
     * Adds one permission string; a wildcard is dropped for anyone but the super-admin; an
     * app-resource catalog token is composed with the login app and the subject, and dropped when
     * the login is not into an app with a record.
     */
    static void addPermission(Result ret, String token, boolean wildcardOK, String subjectGUID, String appGUID) {
        if (SUS.isEmpty(token)) {
            return;
        }
        if (SecurityModel.isWildcardToken(token) && !wildcardOK) {
            log.getLogger().warning("dropped wildcard permission for subject " + subjectGUID);
            return;
        }
        if (SecurityModel.isAppResourceCatalogToken(token)) {
            if (appGUID == null) {
                return; // app rights exist only inside a login into the app
            }
            String[] parts = token.split(SecurityModel.PART_SEP, -1);
            try {
                ret.permissions.add(SecurityModel.toAppResourceToken(appGUID, parts[1].trim(), subjectGUID, parts[2].trim()));
            } catch (IllegalArgumentException | NullPointerException e) {
                log.getLogger().warning("skipped app-resource token " + token + " for subject " + subjectGUID + ": " + e.getMessage());
            }
            return;
        }
        ret.permissions.add(token);
    }
}
