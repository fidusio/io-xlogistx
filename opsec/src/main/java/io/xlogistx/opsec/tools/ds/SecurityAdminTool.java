package io.xlogistx.opsec.tools.ds;

import io.xlogistx.shiro.ShiroUtil;
import io.xlogistx.opsec.OPSecUtil;
import io.xlogistx.opsec.SecretStore;
import io.xlogistx.shiro.ds.SecuritySetup;
import io.xlogistx.shiro.ds.ShiroDSDomainSecurityManager;
import io.xlogistx.shiro.mgt.ShiroSecurityController;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.security.KeyMakerProvider;
import org.zoxweb.shared.api.APIConfigInfo;
import org.zoxweb.shared.api.APIDataStore;
import org.zoxweb.shared.api.APIServiceProvider;
import org.zoxweb.shared.api.APIServiceProviderCreator;
import org.zoxweb.shared.app.AppIDDefault;
import org.zoxweb.shared.crypto.CryptoConst;
import org.zoxweb.shared.security.KeyMaker;
import org.zoxweb.shared.security.PermissionGrant;
import org.zoxweb.shared.security.PermissionInfo;
import org.zoxweb.shared.security.RoleGrant;
import org.zoxweb.shared.security.RoleGroupGrant;
import org.zoxweb.shared.security.RoleGroupInfo;
import org.zoxweb.shared.security.RoleInfo;
import org.zoxweb.shared.security.SecurityController;
import org.zoxweb.shared.security.SubjectIdentifier;
import org.zoxweb.shared.security.model.SecurityModel;
import org.zoxweb.shared.util.GetName;
import org.zoxweb.shared.util.NVGenericMap;
import org.zoxweb.shared.util.ParamUtil;
import org.zoxweb.shared.util.SUS;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.Console;
import java.io.File;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Command-line administration of the security catalog and the admin accounts, the only
 * sanctioned way to create the super-admin. Arguments are {@code key=value} pairs;
 * {@code password}, {@code db.password}, {@code db.enc-password} and {@code store.password} are hidden from logs.
 * <pre>
 *   command=seed-catalog               store=&lt;vault&gt; [store.password=] [db.user= db.password= db.enc-password=]
 *   command=bootstrap-super-admin      db.url=... [principal.id=&lt;super-admin&gt;] [password=&lt;pw&gt;]
 *   command=reset-super-admin-password db.url=... [principal.id=&lt;super-admin&gt;] [password=&lt;pw&gt;]
 *   command=create-subject             db.url=... principal.id=&lt;principal&gt; [password=&lt;pw&gt;] [role=&lt;role name&gt; [app.id=&lt;domain-app&gt;]]
 *   command=grant-role                 db.url=... principal.id=&lt;principal&gt; role=&lt;role name&gt; [app.id=&lt;domain-app&gt;]
 *   command=revoke-role                db.url=... principal.id=&lt;principal&gt; role=&lt;role name&gt; [app.id=&lt;domain-app&gt;]
 *   command=revoke-app                 db.url=... principal.id=&lt;principal&gt; app.id=&lt;domain-app&gt;
 *   command=list-grants                db.url=... principal.id=&lt;principal&gt;
 *   command=reset-password             db.url=... principal.id=&lt;principal&gt;
 *   command=list-catalog               db.url=...
 * </pre>
 * {@code app.id} scopes a role grant to one app ({@code <domain>-<app>} as {@link AppIDDefault#create(String)}
 * reads it, or {@code domain.id=} plus a bare {@code app.id=}): that grant is the subject's
 * assignment to the app, flattened as {@code <domain-app>:<role>} / {@code <domain-app>:<token>},
 * and revoking it ({@code revoke-role}, or {@code revoke-app} for every grant under the app) removes
 * the assignment. The tool runs unenforced, so {@code broker_guid} stays empty here; grants made
 * through the API by an app admin carry that admin as broker.
 * {@code principal.id} names the account the command works on. <b>The super-admin is never named
 * on the command line or in code (user rule 2026-10-03):</b> its id is the secret store's reserved
 * {@value SecretStore#SUPER_ADMIN_ID} entry, read with the vault on every run and handed to the
 * manager; the two super-admin commands work on that account and refuse {@code principal.id=}. A
 * vault without the entry stops the run. The vault must also hold {@code super-admin-password}
 * (mandatory, {@link SecretStore.StoreParam}): {@code bootstrap-super-admin} creates the account
 * with that initial password and refuses {@code password=}.
 * The server that later serves the store reads the same
 * entry, or the flattener drops the wildcard. Only that one account may ever hold a bare {@code *}. Domain
 * admins such as {@code remote-admin} or {@code local-admin} (the latter on devices that run an
 * offline H2 store) are ordinary subjects made with {@code create-subject}: their reach is
 * domain-driven, {@code <domain-app-id>:*} at most, which the guards allow because only a token
 * whose first part is {@code *} is reserved ({@code SecurityModel.isWildcardToken}).
 * <p>
 * <b>Prerequisite of every run (user rule 2026-10-02):</b> the {@link SecretStore} vault named by
 * {@code store=} (or the {@code XLOGISTX_SECRET_STORE} environment variable) is opened with its
 * password ({@code store.password=} or a console prompt) before anything else, and two things are
 * taken from it: the {@code db.*} text secrets, the {@code master-key} secret key and the
 * super-admin id ({@value SecretStore#SUPER_ADMIN_ID}). The
 * master key is loaded into the {@link KeyMakerProvider}, and the datastore is opened with that
 * key maker and the {@link ShiroSecurityController}: every subject the tool creates gets its
 * subject key wrapped under the master key, and every {@code ENCRYPT} column is sealed. No vault,
 * no password or no master key in it: the tool stops before it touches the database.
 * <p>
 * The datastore URL is the vault's mandatory {@code db.url} entry and nothing else (user rule
 * 2026-10-04): {@code db.url=} on the command line is refused, and there is no environment
 * variable or system property for it any more. {@code db.user}, {@code db.password} and
 * {@code db.enc-password} come from the command line, else from the vault entries of the same name,
 * so an operator types one password instead of the database credentials. A PostgreSQL URL must name its database
 * ({@code jdbc:postgresql://host:5432/dbname}); nothing is created.
 * {@code db.enc-password} is the file password of an encrypted H2 database.
 * <p>
 * <b>Datastore creator (user decision 2026-10-05):</b> the store is created by a core
 * {@link APIServiceProviderCreator} that is named by its class name and loaded by reflection:
 * {@code ds.creator=<class>} on the command line, else {@link #DEFAULT_DS_CREATOR}. This class
 * therefore has no compile-time reference to a datastore implementation; it works on the store
 * through core's {@link APIDataStore} only. The creator's class must be on the runtime classpath.
 * When {@code password=} is absent and a console is attached, the password is prompted twice.
 * Permission enforcement is off inside the tool: it is the trusted bootstrap path, and it works
 * on the store through the manager's system view (the store's own access check is on).
 */
public class SecurityAdminTool {

    private static final LogWrapper log = new LogWrapper(SecurityAdminTool.class);
    public static final String SECRET_STORE_ENV = "XLOGISTX_SECRET_STORE";
    /**
     * The alias of the master key in the secret store ({@code master-key},
     * {@link SecretStore.StoreParam#MASTER_KEY}): the key every subject key is wrapped under.
     */
    public static final String MASTER_KEY_ALIAS = SecretStore.StoreParam.MASTER_KEY.getName();
    /**
     * Mandatory text entry of the secret store ({@code super-admin-password},
     * {@link SecretStore.StoreParam#SUPER_ADMIN_PASSWORD}): the password the super-admin account is
     * created with (user rules 2026-10-04). It is the <i>initial</i> password only: the bootstrap
     * uses it when it creates the account, never afterwards; the password is changed later with
     * {@code reset-super-admin-password}.
     */
    public static final String SUPER_ADMIN_PASSWORD = SecretStore.StoreParam.SUPER_ADMIN_PASSWORD.getName();
    /**
     * Class name of the datastore creator used when {@code ds.creator=} is absent (user decision
     * 2026-10-05). It is a string on purpose: the class is loaded by reflection as a core
     * {@link APIServiceProviderCreator}, so the tool does not depend on the h2p datastore classes
     * at compile time.
     */
    public static final String DEFAULT_DS_CREATOR = "io.xlogistx.datastore.h2p.H2PDSCreator";

    // Configuration properties the creator's empty configuration is filled with, by name.
    private static final String CFG_URL = "url";
    private static final String CFG_USER = "user";
    private static final String CFG_PASSWORD = "password";
    private static final String CFG_FILE_PASSWORD = "file_password";
    private static final String CFG_DRIVER = "driver";
    private static final String JDBC_PREFIX = "jdbc:";
    private static final String POSTGRES_SUBPROTOCOL = "postgresql";
    private static final String POSTGRES_DRIVER = "org.postgresql.Driver";

    public static final String USAGE =
            "Usage: command=<command> store=<secret store file> [store.password=<pw>] [options]\n"
                    + "       the secret store is required: it supplies the database (db.url, never the command line), the "
                    + MASTER_KEY_ALIAS + ", the " + SecretStore.SUPER_ADMIN_ID + " and the " + SUPER_ADMIN_PASSWORD + "\n"
                    + "\n"
                    + "Commands:\n"
                    + "  seed-catalog                 create or repair the built-in permissions, roles and role groups\n"
                    + "  bootstrap-super-admin        seed the catalog, create the super-admin account named by the secret store's\n"
                    + "                               " + SecretStore.SUPER_ADMIN_ID + " and grant it the super_admin role; idempotent. Initial password: the\n"
                    + "                               secret store's " + SUPER_ADMIN_PASSWORD + " entry (mandatory); password= is refused\n"
                    + "  reset-super-admin-password   replace the super-admin password (password=<pw> or console prompt)\n"
                    + "  create-subject               principal.id=<principal> [password=<pw> or console prompt] [role=<role name> [app.id=]]:\n"
                    + "                               create an account (e.g. remote-admin / local-admin with role=domain_admin);\n"
                    + "                               never super_admin: a domain admin's reach is <domain-app-id>:* at most\n"
                    + "  grant-role                   principal.id=<principal> role=<role name> [app.id=<domain-app>]\n"
                    + "  revoke-role                  principal.id=<principal> role=<role name> [app.id=<domain-app>]\n"
                    + "  revoke-app                   principal.id=<principal> app.id=<domain-app>: delete every grant under that app\n"
                    + "  list-grants                  principal.id=<principal>: roles, role groups and permissions with their app scope\n"
                    + "  reset-password               principal.id=<principal>: admin reset; prints the one-time token (4 h) to hand out\n"
                    + "  list-catalog                 print permissions, roles and role groups, with the app that owns each row\n"
                    + "  create-app                   domain.id=<domain> app.id=<app> (or app.id=<domain-app>) [principal.id=<first manager>]:\n"
                    + "                               create an app with its own starter roles and permissions and its registrar;\n"
                    + "                               prints the registrar key id and secret ONCE (keep them in the app's vault)\n"
                    + "  rotate-registrar-key         app.id=<domain-app>: replace the registrar key; prints the new secret once\n"
                    + "  list-apps                    print every app with its owner and registrar\n"
                    + "\n"
                    + "Options:\n"
                    + "  principal.id=<principal>     the account to work on; not accepted by the two super-admin commands:\n"
                    + "                               the super-admin id is the secret store's " + SecretStore.SUPER_ADMIN_ID + " entry\n"
                    + "  app.id=<domain-app>          the app a grant or a command works in (e.g. xlogistx.io-shop); with domain.id=<domain>\n"
                    + "                               it is the bare app name. Roles are the app's own; no app.id means the common app\n"
                    + "                               " + ShiroDSDomainSecurityManager.COMMON_SCOPE + "\n"
                    + "  db.user= db.password=        override the secret store's entries of the same name (db.url cannot be overridden)\n"
                    + "  db.enc-password=<pw>         H2 only: file password of an encrypted database\n"
                    + "  ds.creator=<class>           class name of the datastore creator (an APIServiceProviderCreator on the\n"
                    + "                               classpath); default " + DEFAULT_DS_CREATOR + "\n"
                    + "  store=<file>                 REQUIRED. SecretStore vault (BCFKS) holding the " + MASTER_KEY_ALIAS + " secret key, the\n"
                    + "                               " + SecretStore.SUPER_ADMIN_ID + ", the " + SUPER_ADMIN_PASSWORD + " and the text secrets db.url, db.user, db.password and db.enc-password (those fill in\n"
                    + "                               whatever is not on the command line); or set " + SECRET_STORE_ENV + " in the environment\n"
                    + "  store.password=<pw>          the vault password, prompted on the console when absent";

    public enum Command implements GetName {
        SEED_CATALOG("seed-catalog"),
        BOOTSTRAP_SUPER_ADMIN("bootstrap-super-admin"),
        RESET_SUPER_ADMIN_PASSWORD("reset-super-admin-password"),
        CREATE_SUBJECT("create-subject"),
        GRANT_ROLE("grant-role"),
        REVOKE_ROLE("revoke-role"),
        REVOKE_APP("revoke-app"),
        LIST_GRANTS("list-grants"),
        LIST_CATALOG("list-catalog"),
        RESET_PASSWORD("reset-password"),
        CREATE_APP("create-app"),
        ROTATE_REGISTRAR_KEY("rotate-registrar-key"),
        LIST_APPS("list-apps"),
        ;
        private final String name;

        Command(String name) {
            this.name = name;
        }

        @Override
        public String getName() {
            return name;
        }
    }

    public enum Param implements GetName {
        COMMAND("command"),
        DB_URL("db.url"),
        DB_USER("db.user"),
        DB_PASSWORD("db.password"),
        DB_ENC_PASSWORD("db.enc-password"),
        DS_CREATOR("ds.creator"),
        STORE("store"),
        STORE_PASSWORD("store.password"),
        PRINCIPAL_ID("principal.id"),
        PASSWORD("password"),
        ROLE("role"),
        APP_ID("app.id"),
        DOMAIN_ID("domain.id"),
        ;
        private final String name;

        Param(String name) {
            this.name = name;
        }

        @Override
        public String getName() {
            return name;
        }
    }

    public static final int EXIT_OK = 0;
    public static final int EXIT_USAGE = 1;
    public static final int EXIT_FAILURE = 2;

    public static void main(String... args) {
        System.exit(run(System.out, System.err, args));
    }

    /**
     * In-process entry point; returns the exit code instead of exiting.
     */
    public static int run(String... args) {
        return run(System.out, System.err, args);
    }

    public static int run(PrintStream out, PrintStream err, String... args) {
        ParamUtil.ParamMap params;
        Command command;
        String dbURL;
        Vault vault;
        AppIDDefault app;
        APIServiceProviderCreator creator;
        try {
            params = ParamUtil.parse("=", args);
            params.hide(Param.PASSWORD, Param.DB_PASSWORD, Param.DB_ENC_PASSWORD, Param.STORE_PASSWORD);
            command = params.enumValue(Param.COMMAND, Command.values());
            if (command == null) {
                throw new IllegalArgumentException("command is missing or unknown");
            }
            vault = loadVault(params, System.getenv(SECRET_STORE_ENV));
            app = appOf(params);
            if (!SUS.isEmpty(params.stringValue(Param.DB_URL, null))) {
                throw new IllegalArgumentException(Param.DB_URL.getName() + "= is not accepted: the database is the secret store's "
                        + SecretStore.StoreParam.DB_URL.getName() + " entry");
            }
            dbURL = vault.db.getValue(SecretStore.StoreParam.DB_URL.getName()); // mandatory, checked by loadVault
            creator = loadCreator(params.stringValue(Param.DS_CREATOR, null));
        } catch (RuntimeException e) {
            err.println(e.getMessage());
            err.println(USAGE);
            return EXIT_USAGE;
        }

        String principalID = params.stringValue(Param.PRINCIPAL_ID, null);
        principalID = SUS.isEmpty(principalID) ? null : principalID.trim();
        APIDataStore<?, ?> ds = null;
        try {
            KeyMakerProvider.SINGLETON.setMasterSecretKey(vault.masterKey);
            ds = openStore(creator, dbURL, dbSetting(params, vault.db, Param.DB_USER), dbSetting(params, vault.db, Param.DB_PASSWORD),
                    dbSetting(params, vault.db, Param.DB_ENC_PASSWORD), KeyMakerProvider.SINGLETON);
            ShiroDSDomainSecurityManager dsm = new ShiroDSDomainSecurityManager(ds);
            dsm.setSuperAdminPrincipalID(vault.superAdminID); // the only source of the super-admin id
            switch (command) {
                case SEED_CATALOG: {
                    SecuritySetup.Report report = dsm.seedCatalog();
                    out.println("catalog: " + report);
                    return EXIT_OK;
                }
                case BOOTSTRAP_SUPER_ADMIN: {
                    if (principalID != null) {
                        err.println(command.getName() + " does not take principal.id: the super-admin id is the secret store's "
                                + SecretStore.SUPER_ADMIN_ID + " entry (" + dsm.getSuperAdminPrincipalID() + ")");
                        return EXIT_USAGE;
                    }
                    boolean exists = dsm.lookupSuperAdminSubject() != null;
                    if (!SUS.isEmpty(params.stringValue(Param.PASSWORD, null))) {
                        err.println(command.getName() + " does not take password=: the initial super-admin password is the secret store's "
                                + SUPER_ADMIN_PASSWORD + " entry");
                        return EXIT_USAGE;
                    }
                    // the vault's mandatory entry, used only to create the account
                    SecuritySetup.Result result = SecuritySetup.bootstrapSuperAdmin(dsm, exists ? null : vault.superAdminPassword);
                    out.println(result);
                    if (exists) {
                        out.println("account already existed: password unchanged");
                    } else {
                        out.println("initial password: the secret store's " + SUPER_ADMIN_PASSWORD
                                + " entry; change it with reset-super-admin-password");
                    }
                    if (result.registrarKey != null) {
                        printRegistrarKey(out, result.app, result.registrarKey);
                    }
                    return result.wildcardVerified ? EXIT_OK : EXIT_FAILURE;
                }
                case RESET_SUPER_ADMIN_PASSWORD: {
                    if (principalID != null) {
                        err.println(command.getName() + " does not take principal.id: the super-admin id is the secret store's "
                                + SecretStore.SUPER_ADMIN_ID + " entry (" + dsm.getSuperAdminPrincipalID() + ")");
                        return EXIT_USAGE;
                    }
                    String password = password(params, "New super-admin password: ", err);
                    if (password == null) {
                        return EXIT_USAGE;
                    }
                    SecuritySetup.resetSuperAdminPassword(dsm, password);
                    out.println("super-admin password replaced for " + dsm.getSuperAdminPrincipalID());
                    return EXIT_OK;
                }
                case CREATE_SUBJECT: {
                    if (principalID == null) {
                        err.println("create-subject needs principal.id=<principal>");
                        err.println(USAGE);
                        return EXIT_USAGE;
                    }
                    String roleName = params.stringValue(Param.ROLE, null);
                    RoleInfo role = null;
                    if (!SUS.isEmpty(roleName)) {
                        if (SecurityModel.Role.SUPER_ADMIN.getName().equalsIgnoreCase(roleName.trim())) {
                            err.println("create-subject never grants " + SecurityModel.Role.SUPER_ADMIN.getName()
                                    + ": use bootstrap-super-admin for the super-admin account");
                            return EXIT_FAILURE;
                        }
                        role = dsm.lookupRole(roleScope(app), roleName);
                        if (role == null) {
                            err.println("unknown role " + roleName + " in app " + ShiroUtil.scopeLabel(app));
                            return EXIT_FAILURE;
                        }
                    }
                    SubjectIdentifier subject = dsm.lookupSubjectID(principalID);
                    boolean created = false;
                    if (subject == null) {
                        String password = password(params, "Password for " + principalID + ": ", err);
                        if (password == null) {
                            return EXIT_USAGE;
                        }
                        subject = dsm.createSubjectID(principalID, password, CryptoConst.HashType.ARGON2);
                        created = true;
                    }
                    boolean granted = false;
                    if (role != null && !holdsRole(dsm, subject, role, app)) {
                        dsm.addRoleGrant(subject, role, app);
                        granted = true;
                    }
                    out.println("subject " + principalID + " subject=" + subject.getGUID()
                            + (created ? " (created)" : " (existing, password unchanged)")
                            + (role != null ? " role " + roleName + scopeLabel(app) + "=" + (granted ? "granted" : "existing") : ""));
                    return EXIT_OK;
                }
                case GRANT_ROLE: {
                    String roleName = params.stringValue(Param.ROLE, null);
                    if (principalID == null || SUS.isEmpty(roleName)) {
                        err.println("grant-role needs principal.id=<principal> role=<role name>");
                        err.println(USAGE);
                        return EXIT_USAGE;
                    }
                    SubjectIdentifier subject = dsm.lookupSubjectID(principalID);
                    if (subject == null) {
                        err.println("unknown subject: " + principalID);
                        return EXIT_FAILURE;
                    }
                    RoleInfo role = dsm.lookupRole(roleScope(app), roleName);
                    if (role == null) {
                        err.println("unknown role " + roleName + " in app " + ShiroUtil.scopeLabel(app));
                        return EXIT_FAILURE;
                    }
                    if (holdsRole(dsm, subject, role, app)) {
                        out.println("role " + roleName + scopeLabel(app) + " already granted to " + principalID);
                        return EXIT_OK;
                    }
                    dsm.addRoleGrant(subject, role, app);
                    out.println("granted role " + roleName + scopeLabel(app) + " to " + principalID);
                    return EXIT_OK;
                }
                case REVOKE_ROLE: {
                    String roleName = params.stringValue(Param.ROLE, null);
                    if (principalID == null || SUS.isEmpty(roleName)) {
                        err.println("revoke-role needs principal.id=<principal> role=<role name> [app.id=<domain-app>]");
                        err.println(USAGE);
                        return EXIT_USAGE;
                    }
                    SubjectIdentifier subject = dsm.lookupSubjectID(principalID);
                    if (subject == null) {
                        err.println("unknown subject: " + principalID);
                        return EXIT_FAILURE;
                    }
                    RoleInfo role = dsm.lookupRole(roleScope(app), roleName);
                    if (role == null) {
                        err.println("unknown role " + roleName + " in app " + ShiroUtil.scopeLabel(app));
                        return EXIT_FAILURE;
                    }
                    int revoked = 0;
                    for (RoleGrant g : roleGrants(dsm, subject, role, app)) {
                        if (dsm.deleteRoleGrant(g)) {
                            revoked++;
                        }
                    }
                    if (revoked == 0) {
                        err.println("no grant of role " + roleName + scopeLabel(app) + " for " + principalID);
                        return EXIT_FAILURE;
                    }
                    out.println("revoked " + revoked + " grant(s) of role " + roleName + scopeLabel(app) + " from " + principalID);
                    return EXIT_OK;
                }
                case REVOKE_APP: {
                    if (principalID == null || app == null) {
                        err.println("revoke-app needs principal.id=<principal> app.id=<domain-app>");
                        err.println(USAGE);
                        return EXIT_USAGE;
                    }
                    SubjectIdentifier subject = dsm.lookupSubjectID(principalID);
                    if (subject == null) {
                        err.println("unknown subject: " + principalID);
                        return EXIT_FAILURE;
                    }
                    int revoked = dsm.revokeAppGrants(subject.getGUID(), app);
                    out.println("revoked " + revoked + " grant(s)" + scopeLabel(app) + " from " + principalID);
                    return EXIT_OK;
                }
                case LIST_GRANTS: {
                    if (principalID == null) {
                        err.println("list-grants needs principal.id=<principal>");
                        err.println(USAGE);
                        return EXIT_USAGE;
                    }
                    SubjectIdentifier subject = dsm.lookupSubjectID(principalID);
                    if (subject == null) {
                        err.println("unknown subject: " + principalID);
                        return EXIT_FAILURE;
                    }
                    listGrants(dsm, subject, out);
                    return EXIT_OK;
                }
                case LIST_CATALOG: {
                    listCatalog(dsm, out);
                    return EXIT_OK;
                }
                case RESET_PASSWORD: {
                    if (principalID == null) {
                        err.println("reset-password needs principal.id=<principal>");
                        err.println(USAGE);
                        return EXIT_USAGE;
                    }
                    org.zoxweb.shared.security.PasswordResetRequest req = dsm.adminResetPassword(principalID);
                    out.println("reset token for " + req.getPrincipalID() + " (valid until " + new java.util.Date(req.getExpiryTS()) + "):");
                    out.println(req.getToken());
                    out.println("the account is locked until the reset completes or the token expires; complete with "
                            + "completePasswordReset(principal, token, newPassword)");
                    return EXIT_OK;
                }
                case CREATE_APP: {
                    if (app == null) {
                        err.println("create-app needs domain.id=<domain> app.id=<app> (or app.id=<domain-app>)");
                        err.println(USAGE);
                        return EXIT_USAGE;
                    }
                    SubjectIdentifier manager = null;
                    if (principalID != null) {
                        manager = dsm.lookupSubjectID(principalID);
                        if (manager == null) {
                            err.println("unknown subject for the first manager: " + principalID);
                            return EXIT_FAILURE;
                        }
                    }
                    if (dsm.lookupApp(app.getDomainID(), app.getAppID()) != null) {
                        err.println("app already exists: " + ShiroUtil.appScope(app));
                        return EXIT_FAILURE;
                    }
                    ShiroDSDomainSecurityManager.AppCreation created = dsm.createApp(app.getDomainID(), app.getAppID(), manager);
                    out.println(created);
                    printRegistrarKey(out, created.app, created.registrarKey);
                    return EXIT_OK;
                }
                case ROTATE_REGISTRAR_KEY: {
                    if (app == null) {
                        err.println("rotate-registrar-key needs app.id=<domain-app>");
                        err.println(USAGE);
                        return EXIT_USAGE;
                    }
                    org.zoxweb.shared.security.SubjectAPIKey key = dsm.rotateRegistrarKey(app);
                    printRegistrarKey(out, dsm.lookupApp(app.getDomainID(), app.getAppID()), key);
                    return EXIT_OK;
                }
                case LIST_APPS: {
                    listApps(dsm, out);
                    return EXIT_OK;
                }
                default:
                    err.println(USAGE);
                    return EXIT_USAGE;
            }
        } catch (RuntimeException e) {
            err.println(command.getName() + " failed: " + e.getMessage());
            log.getLogger().severe(command.getName() + " failed: " + e);
            return EXIT_FAILURE;
        } finally {
            if (ds != null) {
                try {
                    ds.close();
                } catch (Exception ignore) {
                    // best effort
                }
            }
        }
    }

    /** A {@code db.*} setting: the command-line value when present, else the vault's text secret of the same name. */
    static String dbSetting(ParamUtil.ParamMap params, NVGenericMap vault, Param param) {
        String ret = params.stringValue(param, null);
        return SUS.isEmpty(ret) ? vault.getValue(param.getName()) : ret;
    }

    /**
     * What every run takes from the secret store: the {@code db.*} settings, the master key, the
     * super-admin id and the super-admin's initial password.
     */
    static final class Vault {
        final NVGenericMap db;
        final SecretKey masterKey;
        final String superAdminID;
        /** The mandatory {@code super-admin-password} entry. */
        final String superAdminPassword;

        Vault(NVGenericMap db, SecretKey masterKey, String superAdminID, String superAdminPassword) {
            this.db = db;
            this.masterKey = masterKey;
            this.superAdminID = superAdminID;
            this.superAdminPassword = superAdminPassword;
        }
    }

    /**
     * The prerequisite of every run: opens the vault named by {@code store=} (else {@code env})
     * and takes its {@code db.*} text secrets, its {@code master-key} secret key and its
     * {@value SecretStore#SUPER_ADMIN_ID} entry. The
     * vault password is {@code store.password=} or a single console prompt; the vault is closed
     * again before this returns, only the copied values live on.
     *
     * @throws IllegalArgumentException when no vault is named, when it cannot be opened (missing
     *                                  file, wrong password, no password source) or when it lacks
     *                                  a mandatory entry ({@link SecretStore.StoreParam}: the
     *                                  master key, the super-admin id, the super-admin password,
     *                                  the database URL)
     */
    static Vault loadVault(ParamUtil.ParamMap params, String env) {
        String store = params.stringValue(Param.STORE, null);
        if (SUS.isEmpty(store)) {
            store = env;
        }
        if (SUS.isEmpty(store)) {
            throw new IllegalArgumentException("secret store required: pass store=<file> or set " + SECRET_STORE_ENV
                    + "; it supplies the db.* settings and the " + MASTER_KEY_ALIAS);
        }
        File file = new File(store.trim());
        if (!file.isFile()) {
            throw new IllegalArgumentException("secret store not found: " + file);
        }
        char[] password = vaultPassword(params, file);
        if (password == null) {
            throw new IllegalArgumentException("store.password required for " + file
                    + ": pass store.password=<value> or run from an interactive console");
        }
        NVGenericMap db;
        SecretKey masterKey;
        String superAdminID;
        String superAdminPassword;
        List<SecretStore.StoreParam> missing;
        try (SecretStore vault = SecretStore.open(file, password)) {
            missing = vault.missingMandatory(); // SecretStore.StoreParam says what a store must hold
            db = vault.toNVGenericMap("db.");
            superAdminID = vault.getSuperAdminID();
            superAdminPassword = vault.get(SUPER_ADMIN_PASSWORD);
            SecretKey stored = vault.getSecretKey(MASTER_KEY_ALIAS);
            // a copy that does not depend on the vault, which is closed here
            masterKey = stored != null && stored.getEncoded() != null
                    ? new SecretKeySpec(stored.getEncoded(), stored.getAlgorithm()) : null;
        } catch (Exception e) {
            throw new IllegalArgumentException("cannot open secret store " + file + ": " + e.getMessage(), e);
        } finally {
            Arrays.fill(password, '\0');
        }
        if (!missing.isEmpty()) {
            StringBuilder names = new StringBuilder();
            for (SecretStore.StoreParam param : missing) {
                names.append(names.length() > 0 ? ", " : "").append(param.getName());
            }
            throw new IllegalArgumentException("secret store " + file + " holds no " + names
                    + ": mandatory, add it with the SecretStore tool (command=secret-key for " + MASTER_KEY_ALIAS + ", command=put for the others)");
        }
        if (masterKey == null) {
            throw new IllegalArgumentException("secret store " + file + " holds no " + MASTER_KEY_ALIAS
                    + " secret key: the entry of that name is not a secret key (SecretStore command=secret-key)");
        }
        if (SUS.isEmpty(superAdminID) || SUS.isEmpty(superAdminPassword)
                || SUS.isEmpty((String) db.getValue(SecretStore.StoreParam.DB_URL.getName()))) {
            throw new IllegalArgumentException("secret store " + file + ": " + SecretStore.SUPER_ADMIN_ID + ", "
                    + SUPER_ADMIN_PASSWORD + " and " + SecretStore.StoreParam.DB_URL.getName() + " must be non-empty text entries");
        }
        log.getLogger().info("secret store " + file + " supplied " + db.size() + " db.* setting(s), the " + MASTER_KEY_ALIAS
                + ", the " + SecretStore.SUPER_ADMIN_ID + " and the " + SUPER_ADMIN_PASSWORD);
        return new Vault(db, masterKey, superAdminID, superAdminPassword);
    }

    private static char[] vaultPassword(ParamUtil.ParamMap params, File file) {
        String password = params.stringValue(Param.STORE_PASSWORD, null);
        if (!SUS.isEmpty(password)) {
            return password.toCharArray();
        }
        Console console = System.console();
        if (console == null) {
            return null;
        }
        char[] ret = console.readPassword("Password for secret store " + file.getName() + ": ");
        return ret == null || ret.length == 0 ? null : ret;
    }

    /**
     * Loads the datastore creator by its class name: {@code className}, or
     * {@link #DEFAULT_DS_CREATOR} when it is null or empty. The class must be on the classpath, have
     * a public no-argument constructor and implement core's {@link APIServiceProviderCreator}.
     *
     * @throws IllegalArgumentException when the class cannot be found, created, or is not a creator
     */
    static APIServiceProviderCreator loadCreator(String className) {
        String name = SUS.isEmpty(className) ? DEFAULT_DS_CREATOR : className.trim();
        Object created;
        try {
            created = Class.forName(name).getDeclaredConstructor().newInstance();
        } catch (ClassNotFoundException e) {
            throw new IllegalArgumentException("datastore creator " + name + " is not on the classpath", e);
        } catch (ReflectiveOperationException | LinkageError e) {
            throw new IllegalArgumentException("datastore creator " + name + " cannot be created: " + e, e);
        }
        if (!(created instanceof APIServiceProviderCreator)) {
            throw new IllegalArgumentException("datastore creator " + name + " is not an " + APIServiceProviderCreator.class.getName());
        }
        return (APIServiceProviderCreator) created;
    }

    /**
     * Opens the store the way every run uses it: with the {@link ShiroSecurityController} and the
     * given key maker on its configuration, so encryption at rest and the store's access check are on.
     * The store is made by {@code creator} from its own empty configuration, filled by property
     * name: {@code url}, {@code user}, {@code password}, {@code file_password} and, for a
     * PostgreSQL URL, {@code driver}. An empty user or password keeps the creator's default.
     *
     * @param creator  the datastore creator, never null ({@link #loadCreator})
     * @param keyMaker the key maker with the master key loaded, never null
     */
    static APIDataStore<?, ?> openStore(APIServiceProviderCreator creator, String url, String user, String password,
                                        String filePassword, KeyMaker keyMaker) {
        SUS.checkIfNulls("creator or key maker can't be null", creator, keyMaker);
        OPSecUtil.singleton();
        APIConfigInfo cfg = creator.createEmptyConfigInfo();
        NVGenericMap properties = cfg.getProperties();
        if (POSTGRES_SUBPROTOCOL.equals(jdbcSubprotocol(url))) {
            if (SUS.isEmpty(postgresDatabase(url))) {
                throw new IllegalArgumentException("PostgreSQL URL must name the database: jdbc:postgresql://host:port/dbname");
            }
            try {
                Class.forName(POSTGRES_DRIVER);
            } catch (ClassNotFoundException e) {
                throw new IllegalStateException("PostgreSQL driver not on the classpath", e);
            }
            // the creator's default driver is H2's; the pool connects with the driver that is set
            properties.build(CFG_DRIVER, POSTGRES_DRIVER);
        } else if (!SUS.isEmpty(filePassword)) {
            // a file password means an encrypted H2 database: without a cipher in the URL it would be dropped
            if (!hasCipher(url)) {
                url = url + ";CIPHER=AES";
            }
            properties.build(CFG_FILE_PASSWORD, filePassword);
        }
        properties.build(CFG_URL, url);
        if (!SUS.isEmpty(user)) {
            properties.build(CFG_USER, user);
        }
        if (!SUS.isEmpty(password)) {
            properties.build(CFG_PASSWORD, password);
        }
        cfg.setSecurityController(new ShiroSecurityController());
        cfg.setKeyMaker(keyMaker);
        APIServiceProvider<?, ?> ret = creator.createAPI(null, cfg);
        if (!(ret instanceof APIDataStore)) {
            throw new IllegalStateException(creator.getClass().getName() + " did not create an " + APIDataStore.class.getName());
        }
        return (APIDataStore<?, ?>) ret;
    }

    /** The lower-cased subprotocol of {@code jdbc:<subprotocol>:<subname>}. */
    static String jdbcSubprotocol(String url) {
        if (url == null || !url.regionMatches(true, 0, JDBC_PREFIX, 0, JDBC_PREFIX.length())) {
            throw new IllegalArgumentException("Not a JDBC URL: " + url);
        }
        String rest = url.substring(JDBC_PREFIX.length());
        int colon = rest.indexOf(':');
        return (colon >= 0 ? rest.substring(0, colon) : rest).toLowerCase();
    }

    /**
     * The database a PostgreSQL URL names ({@code jdbc:postgresql://host:port/db[?options]} or
     * {@code jdbc:postgresql:db}), or an empty string when it names none.
     */
    static String postgresDatabase(String url) {
        String rest = url.substring(JDBC_PREFIX.length());
        int colon = rest.indexOf(':');
        String base = colon >= 0 ? rest.substring(colon + 1) : "";
        int cut = base.indexOf('?');
        int semi = base.indexOf(';');
        if (semi >= 0 && (cut < 0 || semi < cut)) {
            cut = semi;
        }
        if (cut >= 0) {
            base = base.substring(0, cut);
        }
        if (!base.startsWith("//")) {
            return base;
        }
        base = base.substring(2);
        int slash = base.indexOf('/');
        return slash >= 0 ? base.substring(slash + 1) : "";
    }

    /** True when an H2 URL carries a {@code ;CIPHER=} setting. */
    static boolean hasCipher(String url) {
        String[] settings = url.split(";");
        for (int i = 1; i < settings.length; i++) {
            if (settings[i].trim().regionMatches(true, 0, "CIPHER=", 0, 7)) {
                return true;
            }
        }
        return false;
    }

    private static boolean holdsRole(ShiroDSDomainSecurityManager dsm, SubjectIdentifier subject, RoleInfo role, AppIDDefault app) {
        return !roleGrants(dsm, subject, role, app).isEmpty();
    }

    /** The subject's grants of {@code role} under exactly {@code app} (null = the global grants). */
    private static List<RoleGrant> roleGrants(ShiroDSDomainSecurityManager dsm, SubjectIdentifier subject, RoleInfo role, AppIDDefault app) {
        List<RoleGrant> ret = new ArrayList<>();
        for (RoleGrant g : dsm.getRoleGrants(subject.getGUID())) {
            if (role.getGUID().equals(g.getRoleGUID()) && sameScope(g.getAppID(), app)) {
                ret.add(g);
            }
        }
        return ret;
    }

    /** No domain/app is the common app, for a stored grant as for the command line. */
    private static boolean sameScope(AppIDDefault stored, AppIDDefault wanted) {
        return ShiroUtil.scopeLabel(stored).equals(ShiroUtil.scopeLabel(wanted));
    }

    private static String scopeLabel(AppIDDefault app) {
        return app == null ? "" : " [app " + ShiroUtil.appScope(app) + "]";
    }

    /** The {@code appID} argument of the catalog lookups for the app of the command line: null = the common app. */
    private static String roleScope(AppIDDefault app) {
        return app == null ? null : ShiroUtil.appScope(app);
    }

    /**
     * The registrar key as the operator must keep it: key id ({@code sub} of its JWTs) and secret.
     * The tool prints the secret only here, when the key is created or rotated. The secret is not
     * lost afterwards: it stays in the datastore as a sealed record that the master key opens;
     * this tool simply has no command that prints it again.
     */
    private static void printRegistrarKey(PrintStream out, AppIDDefault app, org.zoxweb.shared.security.SubjectAPIKey key) {
        out.println("registrar of " + (app != null ? app.getDomainAppID() : "?") + " — principal "
                + ShiroDSDomainSecurityManager.registrarPrincipal(app));
        out.println("  key id: " + key.getSubjectID());
        out.println("  secret: " + key.getAPIKey());
        out.println("  printed by this tool only now: keep both in the app's vault");
        out.println("  the secret stays sealed in the datastore and the master key opens it; this tool has no command to print it again");
    }

    private static void listApps(ShiroDSDomainSecurityManager dsm, PrintStream out) {
        out.println("apps:");
        java.util.Set<String> seen = new java.util.HashSet<>();
        // read straight from the store, whose access check is on: the tool reads it in the system context
        SecurityController sc = dsm.getDataStore().getAPIConfigInfo().getSecurityController();
        List<AppIDDefault> apps = sc.runAsSystem(() -> dsm.getDataStore().<AppIDDefault>search(AppIDDefault.NVC_APP_ID_DEFAULT, null));
        for (AppIDDefault app : apps) {
            String label;
            try {
                label = ShiroUtil.appScope(app);
            } catch (RuntimeException e) {
                continue; // an incomplete pair is not an app record
            }
            if (!seen.add(label)) {
                continue;
            }
            SubjectIdentifier registrar = dsm.lookupRegistrar(app);
            out.println("  " + label + " guid=" + app.getGUID()
                    + (SUS.isEmpty(app.getSubjectGUID()) ? " (no owner)" : " owner=" + app.getSubjectGUID())
                    + (registrar != null ? " registrar=" + registrar.getGUID() : " (no registrar)")
                    + (ShiroDSDomainSecurityManager.COMMON_SCOPE.equals(label) ? " [common]" : ""));
        }
    }

    /**
     * {@code app.id=} as {@code <domain>-<app>} ({@link AppIDDefault#create(String)}), or with
     * {@code domain.id=} the bare app name; null when absent.
     *
     * @throws IllegalArgumentException when the value is malformed
     */
    static AppIDDefault appOf(ParamUtil.ParamMap params) {
        String appID = params.stringValue(Param.APP_ID, null);
        if (SUS.isEmpty(appID)) {
            return null;
        }
        String domainID = params.stringValue(Param.DOMAIN_ID, null);
        try {
            return SUS.isEmpty(domainID) ? AppIDDefault.create(appID.trim()) : new AppIDDefault(domainID.trim(), appID.trim());
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("app.id must be <domain>-<app> (or domain.id=<domain> app.id=<app>): " + e.getMessage(), e);
        }
    }

    private static void listGrants(ShiroDSDomainSecurityManager dsm, SubjectIdentifier subject, PrintStream out) {
        out.println("grants of " + subject.getGUID() + ":");
        for (RoleGrant g : dsm.getRoleGrants(subject.getGUID())) {
            RoleInfo r = dsm.lookupRoleByGUID(g.getRoleGUID());
            out.println("  role " + (r != null ? r.getName() : g.getRoleGUID()) + scopeLabel(g.getAppID()) + brokerLabel(g.getBrokerGUID()));
        }
        for (RoleGroupGrant g : dsm.getRoleGroupGrants(subject.getGUID())) {
            RoleGroupInfo r = dsm.lookupRoleGroupByGUID(g.getRoleGroupGUID());
            out.println("  role group " + (r != null ? r.getName() : g.getRoleGroupGUID()) + scopeLabel(g.getAppID()) + brokerLabel(g.getBrokerGUID()));
        }
        for (PermissionGrant g : dsm.getPermissionGrants(subject.getGUID())) {
            String token = g.getPermissionToken();
            if (SUS.isEmpty(token)) {
                PermissionInfo p = dsm.lookupPermissionByGUID(g.getPermissionGUID());
                token = p != null ? p.getName() + " = " + p.getPermissionToken() : g.getPermissionGUID();
            }
            out.println("  permission " + token
                    + (g.getResourceMap() != null ? " on " + g.getResourceMap().getResourceGUID() : "")
                    + scopeLabel(g.getAppID()) + brokerLabel(g.getBrokerGUID()));
        }
    }

    private static String brokerLabel(String brokerGUID) {
        return SUS.isEmpty(brokerGUID) ? "" : " by " + brokerGUID;
    }

    /**
     * {@code password=} if given, else a double console prompt, else null after an error message.
     */
    private static String password(ParamUtil.ParamMap params, String prompt, PrintStream err) {
        String password = params.stringValue(Param.PASSWORD, null);
        if (!SUS.isEmpty(password)) {
            return password;
        }
        Console console = System.console();
        if (console == null) {
            err.println("password required: pass password=<value> or run from an interactive console");
            return null;
        }
        char[] first = console.readPassword(prompt);
        char[] second = console.readPassword("Repeat: ");
        try {
            if (first == null || first.length == 0 || !Arrays.equals(first, second)) {
                err.println("passwords are empty or do not match");
                return null;
            }
            return new String(first);
        } finally {
            if (first != null) Arrays.fill(first, '\0');
            if (second != null) Arrays.fill(second, '\0');
        }
    }

    private static void listCatalog(ShiroDSDomainSecurityManager dsm, PrintStream out) {
        out.println("permissions:");
        for (PermissionInfo p : dsm.getPermissions()) {
            out.println("  " + p.getName() + " = " + p.getPermissionToken()
                    + "  [app " + ShiroUtil.scopeLabel(p.getAppID()) + "]");
        }
        out.println("roles:");
        for (RoleInfo r : dsm.getRoles()) {
            StringBuilder sb = new StringBuilder();
            if (r.getPermissions() != null) {
                for (PermissionInfo p : r.getPermissions()) {
                    if (sb.length() > 0) sb.append(", ");
                    sb.append(p.getName());
                }
            }
            out.println("  " + r.getName() + " -> [" + sb + "]  [app " + ShiroUtil.scopeLabel(r.getAppID()) + "]");
        }
        out.println("role groups:");
        for (RoleGroupInfo g : dsm.getRoleGroups()) {
            StringBuilder sb = new StringBuilder();
            if (g.getRoles() != null) {
                for (RoleInfo r : g.getRoles()) {
                    if (sb.length() > 0) sb.append(", ");
                    sb.append(r.getName());
                }
            }
            out.println("  " + g.getName() + " -> [" + sb + "]");
        }
    }
}
