package io.xlogistx.shiro.ds;

import io.xlogistx.shiro.ShiroUtil;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.zoxweb.server.security.SecUtil;
import org.zoxweb.shared.app.AppIDDefault;
import org.zoxweb.shared.crypto.CIPassword;
import org.zoxweb.shared.crypto.CredentialHasher;
import org.zoxweb.shared.crypto.CryptoConst;
import org.zoxweb.shared.security.PermissionInfo;
import org.zoxweb.shared.security.RoleGrant;
import org.zoxweb.shared.security.RoleGroupInfo;
import org.zoxweb.shared.security.RoleInfo;
import org.zoxweb.shared.security.SubjectAPIKey;
import org.zoxweb.shared.security.SubjectIdentifier;
import org.zoxweb.shared.security.model.SecurityModel;
import org.zoxweb.shared.util.BaseSubjectID;
import org.zoxweb.shared.util.SUS;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * The setup of a security store: the built-in catalog and the super-admin account.
 * <p>
 * <b>Catalog</b> ({@link #seedCatalog}): materialises {@link SecurityModel} into the manager's
 * store as the catalog of the platform's own app {@code xlogistx.com-common} (created first when
 * missing) — one {@link PermissionInfo} per {@link SecurityModel.Permission}, one {@link RoleInfo}
 * per {@link SecurityModel.Role} carrying exactly the permissions the model declares, and one
 * {@link RoleGroupInfo} per {@link SecurityModel.RoleGroup}, every row with {@code app_id} = the
 * common app. Idempotent: rows are found by {@code (app, name)}; missing ones are created, drifted
 * ones (token, description, permission set, role set) are repaired, matching ones are left alone.
 * Everything runs in one transaction and nothing is granted to any subject. With enforcement on,
 * the caller needs the catalog permissions (or the wildcard). Every other app gets the same
 * treatment with the <em>starter set</em> — the non platform-only roles and groups and their
 * permissions — when it is created ({@link #seedStarterCatalog}).
 * <p>
 * <b>Super-admin</b> ({@link #bootstrapSuperAdmin}): the one path that creates the super-admin
 * account and hands it the reserved {@code super_admin} role, whose single permission is the
 * wildcard {@code *}. The grant carries no domain/app: the account belongs to no app and its
 * wildcard applies in every login. Not called by the manager itself: an operator runs it through
 * the admin CLI ({@code io.xlogistx.shiro.ds.tools.SecurityAdminTool}), which is the trusted
 * bootstrap path. Idempotent: an existing account is left as it is (password untouched), a missing
 * role grant is added, the catalog is seeded first. The password is hashed with ARGON2 and never
 * logged or kept.
 * <p>
 * <b>Common app</b> ({@link #ensureCommonApp}): the record of the platform's own app,
 * {@value #COMMON_DOMAIN_ID}-{@value #COMMON_APP_ID}, one {@link AppIDDefault} row owned by the
 * super-admin. Created once (by the seeding, as the catalog's owner); the bootstrap hands it to the
 * super-admin and gives it its registrar like any other app.
 */
public final class SecuritySetup {

    /** Domain of the platform's own app ({@link ShiroDSDomainSecurityManager#COMMON_DOMAIN_ID}). */
    public static final String COMMON_DOMAIN_ID = ShiroDSDomainSecurityManager.COMMON_DOMAIN_ID;
    /** App id of the platform's own app: with the domain, {@code xlogistx.com-common}. */
    public static final String COMMON_APP_ID = ShiroDSDomainSecurityManager.COMMON_APP_ID;

    /** What one catalog run did, per kind. */
    public static final class Report {
        public int permissionsCreated, permissionsUpdated, permissionsExisting;
        public int rolesCreated, rolesUpdated, rolesExisting;
        public int roleGroupsCreated, roleGroupsUpdated, roleGroupsExisting;

        public boolean isNoOp() {
            return permissionsCreated + permissionsUpdated + rolesCreated + rolesUpdated
                    + roleGroupsCreated + roleGroupsUpdated == 0;
        }

        @Override
        public String toString() {
            return "permissions[created=" + permissionsCreated + ", updated=" + permissionsUpdated + ", existing=" + permissionsExisting
                    + "] roles[created=" + rolesCreated + ", updated=" + rolesUpdated + ", existing=" + rolesExisting
                    + "] roleGroups[created=" + roleGroupsCreated + ", updated=" + roleGroupsUpdated + ", existing=" + roleGroupsExisting + "]";
        }
    }

    /** What the super-admin bootstrap did. */
    public static final class Result {
        public Report catalog;
        public String principalID;
        public SubjectIdentifier subject;
        public boolean subjectCreated;
        public boolean roleGranted;
        public boolean loginVerified;
        public boolean wildcardVerified;
        public AppIDDefault app;
        public boolean appCreated;
        /** The common app's registrar; its key (with the secret) only when it was created by this run. */
        public SubjectIdentifier registrar;
        public SubjectAPIKey registrarKey;

        @Override
        public String toString() {
            return "super-admin " + principalID + " subject=" + (subject != null ? subject.getGUID() : null)
                    + (subjectCreated ? " (created)" : " (existing)")
                    + " role=" + (roleGranted ? "granted" : "existing")
                    + " login=" + (loginVerified ? "verified" : "not checked")
                    + " wildcard=" + (wildcardVerified ? "verified" : "FAILED")
                    + " app=" + (app != null ? app.getDomainAppID() : null) + (appCreated ? " (created)" : " (existing)")
                    + " registrar=" + (registrar != null ? registrar.getGUID() : null) + (registrarKey != null ? " (created)" : " (existing)")
                    + " catalog{" + catalog + "}";
        }
    }

    private SecuritySetup() {
    }

    // ------------------------------------------------------------------
    // catalog
    // ------------------------------------------------------------------

    /**
     * Seeds or repairs the full catalog of the common app ({@code xlogistx.com-common}); the app
     * record is created first when missing, owned by the super-admin when that account exists.
     *
     * @param dsm the manager whose store receives the catalog
     * @return counts of what was created, repaired and left alone
     */
    public static Report seedCatalog(ShiroDSDomainSecurityManager dsm) {
        SUS.checkIfNulls("manager can't be null", dsm);
        return dsm.inTransaction(() -> {
            SubjectIdentifier superAdmin = dsm.lookupSuperAdminSubject();
            AppIDDefault common = ensureCommonApp(dsm, superAdmin != null ? superAdmin.getGUID() : null);
            return seedCatalog(dsm, common, SecurityModel.Permission.values(), SecurityModel.Role.values(), SecurityModel.RoleGroup.values());
        });
    }

    /**
     * The starter catalog of a new app: every {@link SecurityModel.Role} and
     * {@link SecurityModel.RoleGroup} that is not platform-only, with exactly the permissions they
     * declare — the app's own rows, idempotent like the common seeding. Called by
     * {@link ShiroDSDomainSecurityManager#createApp(String, String, SubjectIdentifier)}.
     */
    static Report seedStarterCatalog(ShiroDSDomainSecurityManager dsm, AppIDDefault app) {
        List<SecurityModel.Role> roles = new ArrayList<>();
        Set<SecurityModel.Permission> permissions = new LinkedHashSet<>();
        for (SecurityModel.Role r : SecurityModel.Role.values()) {
            if (!r.isPlatformOnly()) {
                roles.add(r);
                permissions.addAll(java.util.Arrays.asList(r.getPermissions()));
            }
        }
        List<SecurityModel.RoleGroup> groups = new ArrayList<>();
        for (SecurityModel.RoleGroup g : SecurityModel.RoleGroup.values()) {
            if (!g.isPlatformOnly()) {
                groups.add(g);
            }
        }
        return seedCatalog(dsm, app, permissions.toArray(new SecurityModel.Permission[0]),
                roles.toArray(new SecurityModel.Role[0]), groups.toArray(new SecurityModel.RoleGroup[0]));
    }

    /** Seeds or repairs the given subset of the model as rows of {@code app}, in one transaction. */
    public static Report seedCatalog(ShiroDSDomainSecurityManager dsm, AppIDDefault app, SecurityModel.Permission[] permissionModels,
                                      SecurityModel.Role[] roleModels, SecurityModel.RoleGroup[] groupModels) {
        Report report = new Report();
        dsm.inTransaction(() -> {
            Map<SecurityModel.Permission, PermissionInfo> permissions = seedPermissions(dsm, app, permissionModels, report);
            Map<SecurityModel.Role, RoleInfo> roles = seedRoles(dsm, app, roleModels, permissions, report);
            seedRoleGroups(dsm, app, groupModels, roles, report);
            return null;
        });
        dsm.getRealm().evictAllAuthorization();
        return report;
    }

    private static Map<SecurityModel.Permission, PermissionInfo> seedPermissions(ShiroDSDomainSecurityManager dsm, AppIDDefault app,
                                                                                SecurityModel.Permission[] models, Report report) {
        String scope = ShiroUtil.scopeLabel(app);
        Map<SecurityModel.Permission, PermissionInfo> ret = new LinkedHashMap<>();
        for (SecurityModel.Permission model : models) {
            PermissionInfo existing = dsm.lookupPermission(scope, model.getName());
            if (existing == null) {
                PermissionInfo row = model.toPermissionInfo();
                row.setAppID(app);
                ret.put(model, dsm.createPermission(row));
                report.permissionsCreated++;
                continue;
            }
            if (existing.getAppID() == null) {
                dsm.attachToApp(existing, app); // a row seeded before 2026-10-01: now the app's
            }
            boolean drift = !model.getValue().equals(existing.getPermissionToken())
                    || !SUS.equals(model.getDescription(), existing.getDescription(), false);
            if (drift) {
                if (model.isReserved()) {
                    // the reserved row is immutable through the manager; a drifted one is a corrupt catalog
                    throw new IllegalStateException("reserved permission row drifted: " + existing.getPermissionToken());
                }
                existing.setPermissionToken(model.getValue());
                existing.setDescription(model.getDescription());
                dsm.updatePermission(existing);
                report.permissionsUpdated++;
            } else {
                report.permissionsExisting++;
            }
            ret.put(model, existing);
        }
        return ret;
    }

    private static Map<SecurityModel.Role, RoleInfo> seedRoles(ShiroDSDomainSecurityManager dsm, AppIDDefault app,
                                                              SecurityModel.Role[] models,
                                                              Map<SecurityModel.Permission, PermissionInfo> permissions,
                                                              Report report) {
        String scope = ShiroUtil.scopeLabel(app);
        Map<SecurityModel.Role, RoleInfo> ret = new LinkedHashMap<>();
        for (SecurityModel.Role model : models) {
            PermissionInfo[] wanted = new PermissionInfo[model.getPermissions().length];
            for (int i = 0; i < wanted.length; i++) {
                wanted[i] = permissions.get(model.getPermissions()[i]);
                SUS.checkIfNulls("permission " + model.getPermissions()[i].getName() + " not seeded for " + scope, wanted[i]);
            }
            RoleInfo existing = dsm.lookupRole(scope, model.getName());
            if (existing == null) {
                RoleInfo row = new RoleInfo(model.getName(), model.getDescription(), wanted);
                row.setAppID(app);
                ret.put(model, dsm.createRole(row));
                report.rolesCreated++;
                continue;
            }
            if (existing.getAppID() == null) {
                dsm.attachToApp(existing, app);
            }
            Set<String> wantedGUIDs = new HashSet<>();
            for (PermissionInfo p : wanted) {
                wantedGUIDs.add(p.getGUID());
            }
            Set<String> currentGUIDs = new HashSet<>();
            PermissionInfo[] current = existing.getPermissions();
            if (current != null) {
                for (PermissionInfo p : current) {
                    if (p != null && !SUS.isEmpty(p.getGUID())) {
                        currentGUIDs.add(p.getGUID());
                    }
                }
            }
            boolean drift = !wantedGUIDs.equals(currentGUIDs)
                    || !SUS.equals(model.getDescription(), existing.getDescription(), false);
            if (drift) {
                existing.setDescription(model.getDescription());
                existing.setPermissions(wanted);
                dsm.updateRoleInternal(existing);
                report.rolesUpdated++;
            } else {
                report.rolesExisting++;
            }
            ret.put(model, existing);
        }
        return ret;
    }

    private static void seedRoleGroups(ShiroDSDomainSecurityManager dsm, AppIDDefault app, SecurityModel.RoleGroup[] models,
                                       Map<SecurityModel.Role, RoleInfo> roles, Report report) {
        String scope = ShiroUtil.scopeLabel(app);
        for (SecurityModel.RoleGroup model : models) {
            RoleInfo[] wanted = new RoleInfo[model.getRoles().length];
            for (int i = 0; i < wanted.length; i++) {
                wanted[i] = roles.get(model.getRoles()[i]);
                SUS.checkIfNulls("role " + model.getRoles()[i].getName() + " not seeded for " + scope, wanted[i]);
            }
            RoleGroupInfo existing = dsm.lookupRoleGroup(scope, model.getName());
            if (existing == null) {
                RoleGroupInfo group = new RoleGroupInfo(wanted);
                group.setName(model.getName());
                group.setDescription(model.getDescription());
                group.setAppID(app);
                dsm.createRoleGroup(group);
                report.roleGroupsCreated++;
                continue;
            }
            if (existing.getAppID() == null) {
                dsm.attachToApp(existing, app);
            }
            Set<String> wantedGUIDs = new HashSet<>();
            for (RoleInfo r : wanted) {
                wantedGUIDs.add(r.getGUID());
            }
            Set<String> currentGUIDs = new HashSet<>();
            RoleInfo[] current = existing.getRoles();
            if (current != null) {
                for (RoleInfo r : current) {
                    if (r != null && !SUS.isEmpty(r.getGUID())) {
                        currentGUIDs.add(r.getGUID());
                    }
                }
            }
            boolean drift = !wantedGUIDs.equals(currentGUIDs)
                    || !SUS.equals(model.getDescription(), existing.getDescription(), false);
            if (drift) {
                existing.setDescription(model.getDescription());
                existing.setRoles(wanted);
                dsm.updateRoleGroup(existing);
                report.roleGroupsUpdated++;
            } else {
                report.roleGroupsExisting++;
            }
        }
    }

    // ------------------------------------------------------------------
    // super-admin
    // ------------------------------------------------------------------

    /**
     * The setup of a store: the super-admin account (created first — it needs no catalog), the
     * common app owned by it with the full catalog, the reserved role granted to the account, and
     * the common app's registrar.
     *
     * @param dsm      the manager (enforcement is expected to be off, or the caller to hold the wildcard)
     * @param password the password for a new account; ignored when the account already exists
     * @return what happened; {@code wildcardVerified} is false only if the realm does not imply
     * an arbitrary permission for the account, which means the guards are misconfigured
     * @throws IllegalArgumentException if the account is missing and no password was given
     */
    public static Result bootstrapSuperAdmin(ShiroDSDomainSecurityManager dsm, String password) {
        SUS.checkIfNulls("manager can't be null", dsm);
        Result ret = new Result();
        ret.principalID = dsm.requireSuperAdminPrincipalID(); // from the SecretStore's super-admin-id, never from code

        SubjectIdentifier subject = dsm.lookupSubjectID(ret.principalID);
        if (subject == null) {
            if (SUS.isEmpty(password)) {
                throw new IllegalArgumentException("password required to create " + ret.principalID);
            }
            subject = dsm.createSubjectID(ret.principalID, hash(password), BaseSubjectID.SubjectType.SYSTEM);
            ret.subjectCreated = true;
        }
        ret.subject = subject;

        ret.appCreated = dsm.commonApp() == null;
        ret.catalog = dsm.seedCatalog(); // creates the common app (owned by the super-admin) and its catalog
        ret.app = dsm.commonApp();

        RoleInfo role = dsm.lookupRole(null, SecurityModel.Role.SUPER_ADMIN.getName());
        if (role == null) {
            throw new IllegalStateException("catalog has no " + SecurityModel.Role.SUPER_ADMIN.getName() + " role after seeding");
        }
        boolean granted = false;
        for (RoleGrant g : dsm.getRoleGrants(subject.getGUID())) {
            if (role.getGUID().equals(g.getRoleGUID())) {
                granted = true;
                break;
            }
        }
        if (!granted) {
            dsm.addRoleGrant(subject, role); // no domain/app: the wildcard applies in every login
            ret.roleGranted = true;
        }

        ShiroDSDomainSecurityManager.AppCreation registrar = dsm.ensureRegistrar(ret.app);
        ret.registrar = registrar.registrar;
        ret.registrarKey = registrar.registrarKey;

        if (!SUS.isEmpty(password) && ret.subjectCreated) {
            dsm.login(ret.principalID, password);
            ret.loginVerified = true;
        }
        ret.wildcardVerified = impliesAnything(dsm, subject.getGUID());
        return ret;
    }

    /**
     * The record of the platform's own app {@code xlogistx.com-common}: found, or created with
     * {@code creatorGUID} as its owner. A record that was created before the super-admin existed
     * (a bare {@code seed-catalog}) is handed to {@code creatorGUID} once one is known.
     *
     * @param dsm         the manager whose store holds the record
     * @param creatorGUID the subject owning it, normally the super-admin; null when none exists yet
     * @return the stored record
     */
    public static AppIDDefault ensureCommonApp(ShiroDSDomainSecurityManager dsm, String creatorGUID) {
        SUS.checkIfNulls("manager can't be null", dsm);
        return dsm.inTransaction(() -> {
            AppIDDefault app = dsm.commonApp();
            if (app == null) {
                return dsm.createAppRecord(COMMON_DOMAIN_ID, COMMON_APP_ID, creatorGUID);
            }
            if (SUS.isEmpty(app.getSubjectGUID()) && !SUS.isEmpty(creatorGUID)) {
                dsm.setAppOwner(app, creatorGUID);
            }
            return app;
        });
    }

    /**
     * Replaces the super-admin password (every old password row is removed).
     *
     * @throws IllegalStateException if the account does not exist
     */
    public static void resetSuperAdminPassword(ShiroDSDomainSecurityManager dsm, String newPassword) {
        SUS.checkIfNulls("manager can't be null", dsm);
        if (SUS.isEmpty(newPassword)) {
            throw new IllegalArgumentException("new password required");
        }
        SubjectIdentifier subject = dsm.lookupSuperAdminSubject();
        if (subject == null) {
            throw new IllegalStateException("super-admin account does not exist: " + dsm.requireSuperAdminPrincipalID());
        }
        dsm.updateCredential(subject, hash(newPassword));
    }

    /** True if the realm implies a random, never-granted permission for the subject: only the wildcard does that. */
    static boolean impliesAnything(ShiroDSDomainSecurityManager dsm, String subjectGUID) {
        DSAuthorizingRealm realm = dsm.getRealm();
        realm.evictAuthorization(subjectGUID);
        PrincipalCollection pc = new SimplePrincipalCollection(UUID.fromString(subjectGUID), realm.getName());
        return realm.isPermitted(pc, "bootstrap:probe:" + UUID.randomUUID());
    }

    private static CIPassword hash(String password) {
        CredentialHasher<CIPassword> hasher = SecUtil.lookupCredentialHasher(CryptoConst.HashType.ARGON2.getName());
        return hasher.hash(password);
    }
}
