package io.xlogistx.shiro.ds;

import io.xlogistx.shiro.ShiroUtil;
import io.xlogistx.shiro.authc.CredentialsInfoMatcher;
import io.xlogistx.shiro.authc.DomainUsernamePasswordToken;
import io.xlogistx.shiro.authc.JWTAuthenticationToken;
import io.xlogistx.shiro.mgt.ShiroSecurityManager;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.UnavailableSecurityManagerException;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.cache.MemoryConstrainedCacheManager;
import org.apache.shiro.mgt.RealmSecurityManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.security.HashUtil;
import org.zoxweb.server.security.JWTProvider;
import org.zoxweb.server.security.PasswordResetTokenUtil;
import org.zoxweb.server.security.SecUtil;
import org.zoxweb.server.util.UUID7;
import org.zoxweb.shared.api.APIDataStore;
import org.zoxweb.shared.app.AppIDDefault;
import org.zoxweb.shared.crypto.CIPassword;
import org.zoxweb.shared.crypto.CredentialHasher;
import org.zoxweb.shared.crypto.CryptoConst;
import org.zoxweb.shared.crypto.EncapsulatedKey;
import org.zoxweb.shared.data.AppIDResource;
import org.zoxweb.shared.db.QueryMatch;
import org.zoxweb.shared.db.QueryMatchIn;
import org.zoxweb.shared.security.*;
import org.zoxweb.shared.security.model.SecurityModel;
import org.zoxweb.shared.filters.FilterType;
import org.zoxweb.shared.util.*;
import org.zoxweb.shared.util.Const.RelationalOperator;
import org.zoxweb.shared.util.ExceptionReason.Reason;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.security.SecureRandom;
import java.util.function.Supplier;
import java.util.logging.Level;

/**
 * {@link DomainSecurityManager} that persists through an {@link APIDataStore} and authenticates,
 * authorizes and caches through Apache Shiro.
 *
 * <p><b>Persistence.</b> Same entities and tables as {@code DomainSecurityManagerDefault}:
 * {@link SubjectIdentifier}, {@link PrincipalIdentifier}, credential rows ({@link CIPassword},
 * {@link SubjectAPIKey}, plus whatever {@link #addCredentialType(Class)} registers), the
 * permission / role / role-group catalog and the three grant tables, all linked by
 * {@code subject_guid}. Compared with the default it adds: a join-or-begin transaction helper so
 * every multi-row operation is atomic and composes with a caller's transaction; ACTIVE status
 * stamped on new principals and credentials; an ownership check on in-place credential updates;
 * loud failure on unsupported credential types; a row lock that closes the last-principal race;
 * complete password replacement; an explicit API-key cascade on subject delete; and principal IDs
 * normalized through {@link SecConst.SubjectIDFilter} on write and lookup (trimmed, lower-cased,
 * validated), matching what the Shiro token does to the username.</p>
 *
 * <p><b>Authentication.</b> Two credential kinds, one realm: principal ID + password
 * ({@link #login}) and JWT bearer token signed with a signing key's secret ({@link #loginJWT};
 * mint one with {@link #mintJWT}). A raw API key is not a login (2026-10-03): a
 * {@link SubjectAPIKey} of type {@code API_KEY} is the subject's credential for a third-party API,
 * sealed in the store and served in clear to its logged-in owner; {@link #loginApiKey} always
 * refuses, and only a key of type {@code SYMMETRIC_KEY} verifies a JWT. Each login builds a Shiro token and
 * runs it through the {@link ShiroSecurityManager}'s authenticator: the {@link DSAuthorizingRealm}
 * loads the subject and credential and applies the status rules, {@link CredentialsInfoMatcher}
 * compares. Nothing is bound to the thread and no session is created, so these calls are safe for
 * "verify the current password" flows. {@link #loginSubject} and
 * {@link #loginSubjectJWT} are the calls that produce a bound Shiro {@link Subject} with a
 * session; {@link #logout()} ends it.</p>
 *
 * <p><b>Authorization.</b> A bound subject can ask {@code isPermitted(...)} / {@code hasRole(...)}:
 * grants are flattened into permission strings and role names by {@link GrantFlattener} and cached
 * per subject GUID. Every mutation that changes what a subject may do evicts the affected entries.
 * With {@link #setEnforcePermissions(boolean)} on, catalog and subject mutations additionally
 * require the bound subject to hold the matching {@link SecurityModel} permission (off by default
 * so CLI tools and first-run bootstrap work with nobody logged in).</p>
 *
 * <p><b>Instance grants and sharing.</b> A {@link PermissionGrant} is either catalog-backed
 * ({@code permission_guid}, optionally scoped to one resource through an embedded
 * {@link ResourceMap}) or inlined ({@code permission_token} of the form {@code resource:<verbs>},
 * always scoped): never both, never neither. A scoped grant flattens to the standardized token
 * {@code resource:<resource guid>:<grantee guid>:<verbs>} (user decision 2026-09-29), which is what
 * {@code ShiroUtil.checkResourcePermission} / {@code ShiroSecurityController} check per entity; every
 * subject also holds the synthesized self permission {@code resource:<S>:<S>:create,read,update,delete,share},
 * so ownership is a permission, never an equality test.
 * "A shares X with B" is {@link #addPermissionGrant(SubjectIdentifier, ResourceMap, String)}: one
 * inlined grant row, grantee in {@code subject_guid}, grantor in {@code broker_guid}. The resource
 * must exist; under enforcement any grant on a resource requires {@code share} on it (the owner
 * through its self permission, or a grantee whose share carries {@code share}), and a catalog grant
 * scoped to a resource is also open to the global assign permission. Revoking a scoped grant deletes
 * the grant and its map row; revocation is open to the grantor, a {@code share} holder on the
 * resource, and holders of the global remove permission.
 * Share rules (user decision 2026-10-06, inlined shares only; catalog-scoped grants are unchanged):
 * one share per grantee per resource; the owner changes a share in place
 * ({@link #updatePermissionGrant(PermissionGrant, String)}) and is the only one who may; a sharer
 * who is not the owner gives only {@code read} or {@code read,share}; revoking a share, or
 * taking {@code share} out of it, revokes what the grantee issued on the resource, recursively,
 * in the same transaction. No key row is touched by any of it.</p>
 *
 * <p><b>Wiring.</b> Two modes. <i>Self-managed</i>: {@link #ShiroDSDomainSecurityManager(APIDataStore)}
 * builds its own {@link ShiroSecurityManager} with one {@link DSAuthorizingRealm};
 * {@link #installAsGlobal()} publishes it through {@code SecurityUtils}. <i>Attached</i>: the realm is
 * declared in {@code shiro.ini} (it has a no-arg constructor) and the security manager comes from
 * the INI; the manager is created with {@link #attach(DSAuthorizingRealm, APIDataStore)} or found
 * with {@link #fromGlobal()} after {@code SecurityUtils.setSecurityManager(...)}, and every Shiro call
 * goes through the global security manager. In attached mode {@link #getShiroSecurityManager()} is
 * {@code null} and {@link #installAsGlobal()} throws.</p>
 */
public class ShiroDSDomainSecurityManager
        implements DomainSecurityManager {

    public static final LogWrapper log = new LogWrapper(ShiroDSDomainSecurityManager.class).setEnabled(false);
    private static final String INVALID_CREDENTIALS = "Invalid credentials";
    private static final String INVALID_KEY = "An API key is not a login credential";
    private static final String INVALID_TOKEN = "Invalid token";

    /** Domain of the platform's own app (user, 2026-10-01); defined in {@link ShiroUtil#COMMON_DOMAIN_ID}. */
    public static final String COMMON_DOMAIN_ID = ShiroUtil.COMMON_DOMAIN_ID;
    /** App id of the platform's own app; defined in {@link ShiroUtil#COMMON_APP_ID}. */
    public static final String COMMON_APP_ID = ShiroUtil.COMMON_APP_ID;
    /** Scope label of the common app, the meaning of "no domain/app" everywhere in this manager; defined in {@link ShiroUtil#COMMON_SCOPE}. */
    public static final String COMMON_SCOPE = ShiroUtil.COMMON_SCOPE;
    /** Prefix of an app's registrar principal: {@code registrar.<domain>-<app>} (never email-shaped). */
    public static final String REGISTRAR_PRINCIPAL_PREFIX = "registrar.";

    private volatile APIDataStore<?, ?> dataStore;
    /** {@link #dataStore} as this manager reaches it: every call in the controller's system context. */
    private volatile APIDataStore<?, ?> systemStore;
    private static final SecureRandom RANDOM = new SecureRandom();
    private final Set<Class<?>> credentialCollections = ConcurrentHashMap.newKeySet();
    private final DSAuthorizingRealm realm;
    private final CredentialsInfoMatcher credentialsMatcher;
    /** Own security manager; {@code null} when attached to an externally configured one. */
    private final ShiroSecurityManager shiroSecurityManager;
    private volatile boolean enforcePermissions = false;

    /** Backed by the given store, with an in-memory authorization cache. */
    public ShiroDSDomainSecurityManager(APIDataStore<?, ?> dataStore) {
        this(dataStore, null);
    }

    /**
     * @param dataStore    persistence for every entity
     * @param cacheManager Shiro cache manager for authorization info, or {@code null} for an
     *                     in-memory {@link MemoryConstrainedCacheManager}
     */
    public ShiroDSDomainSecurityManager(APIDataStore<?, ?> dataStore, CacheManager cacheManager) {
        this(dataStore, cacheManager, null);
    }

    private ShiroDSDomainSecurityManager(APIDataStore<?, ?> dataStore, CacheManager cacheManager, DSAuthorizingRealm externalRealm) {
        SUS.checkIfNulls("dataStore can't be null", dataStore);
        this.dataStore = dataStore;
        this.systemStore = systemView(dataStore);
        credentialCollections.add(CIPassword.class);
        credentialCollections.add(SubjectAPIKey.class);

        if (externalRealm != null) {
            realm = externalRealm;
            if (realm.getCredentialsMatcher() instanceof CredentialsInfoMatcher) {
                credentialsMatcher = (CredentialsInfoMatcher) realm.getCredentialsMatcher();
            } else {
                credentialsMatcher = new CredentialsInfoMatcher();
                realm.setCredentialsMatcher(credentialsMatcher);
            }
            realm.setDomainSecurityManager(this);
            shiroSecurityManager = null;
            return;
        }

        credentialsMatcher = new CredentialsInfoMatcher();
        realm = new DSAuthorizingRealm(this); // no-arg defaults: name, caching flags
        realm.setCredentialsMatcher(credentialsMatcher);

        shiroSecurityManager = new ShiroSecurityManager();
        shiroSecurityManager.setMainThreadBlocked(false);
        shiroSecurityManager.setCacheManager(cacheManager != null ? cacheManager : new MemoryConstrainedCacheManager());
        shiroSecurityManager.setRealm(realm);
    }

    /**
     * Attach a manager to a realm that was built elsewhere (typically by {@code shiro.ini}). The
     * realm's own matcher is kept when it is a {@link CredentialsInfoMatcher}. Shiro calls made by the
     * returned manager go through {@code SecurityUtils.getSecurityManager()}, which must therefore be
     * the security manager that owns {@code realm}.
     *
     * @throws IllegalStateException if the realm is already bound to another manager
     */
    public static ShiroDSDomainSecurityManager attach(DSAuthorizingRealm realm, APIDataStore<?, ?> dataStore) {
        SUS.checkIfNulls("realm can't be null", realm);
        synchronized (realm) {
            if (realm.isBound()) {
                DomainSecurityManager bound = realm.getDomainSecurityManager();
                if (bound instanceof ShiroDSDomainSecurityManager && ((ShiroDSDomainSecurityManager) bound).dataStore == dataStore) {
                    return (ShiroDSDomainSecurityManager) bound;
                }
                throw new IllegalStateException("Realm '" + realm.getName() + "' is already bound to another manager");
            }
            ShiroDSDomainSecurityManager ret = new ShiroDSDomainSecurityManager(dataStore, null, realm);
            ret.registerAsResource();
            return ret;
        }
    }

    /**
     * The manager behind the {@link DSAuthorizingRealm} of the global security manager
     * ({@code SecurityUtils}). An unbound realm resolves its store from {@link ResourceManager}
     * (see {@link DSAuthorizingRealm#setDataStoreResource}).
     *
     * @throws IllegalStateException when no global security manager is set, it holds no
     *                               {@link DSAuthorizingRealm}, or the realm cannot resolve a store
     */
    public static ShiroDSDomainSecurityManager fromGlobal() {
        return shiroManagerOf(globalRealm());
    }

    /**
     * The realm's manager as this class. The realm holds the core {@link DomainSecurityManager}
     * interface, so it may be bound to another implementation.
     *
     * @throws IllegalStateException when the realm's manager is not a {@code ShiroDSDomainSecurityManager}
     */
    private static ShiroDSDomainSecurityManager shiroManagerOf(DSAuthorizingRealm realm) {
        DomainSecurityManager bound = realm.getDomainSecurityManager();
        if (bound instanceof ShiroDSDomainSecurityManager) {
            return (ShiroDSDomainSecurityManager) bound;
        }
        throw new IllegalStateException("Realm '" + realm.getName() + "' is bound to "
                + (bound != null ? bound.getClass().getName() : "no manager") + ", not to a ShiroDSDomainSecurityManager");
    }

    /** Like {@link #fromGlobal()}, but attaches {@code dataStore} when the realm is still unbound. */
    public static ShiroDSDomainSecurityManager fromGlobal(APIDataStore<?, ?> dataStore) {
        DSAuthorizingRealm realm = globalRealm();
        return realm.isBound() ? shiroManagerOf(realm) : attach(realm, dataStore);
    }

    private static DSAuthorizingRealm globalRealm() {
        SecurityManager sm;
        try {
            sm = SecurityUtils.getSecurityManager();
        } catch (UnavailableSecurityManagerException e) {
            throw new IllegalStateException("No global Shiro SecurityManager: load shiro.ini and call SecurityUtils.setSecurityManager first", e);
        }
        if (sm instanceof RealmSecurityManager) {
            Collection<Realm> realms = ((RealmSecurityManager) sm).getRealms();
            if (realms != null) {
                for (Realm r : realms) {
                    if (r instanceof DSAuthorizingRealm) {
                        return (DSAuthorizingRealm) r;
                    }
                }
            }
        }
        throw new IllegalStateException("Global Shiro SecurityManager " + sm.getClass().getName() + " holds no DSAuthorizingRealm");
    }

    // ------------------------------------------------------------------
    // Shiro wiring
    // ------------------------------------------------------------------

    /** Own security manager, or {@code null} when attached to an externally configured one. */
    public ShiroSecurityManager getShiroSecurityManager() {
        return shiroSecurityManager;
    }

    /** The security manager Shiro calls go through: own, or the global one when attached. */
    public SecurityManager getSecurityManager() {
        return securityManager();
    }

    /** {@code true} when this manager owns its security manager; {@code false} when attached to one built elsewhere. */
    public boolean isSelfManaged() {
        return shiroSecurityManager != null;
    }

    private SecurityManager securityManager() {
        if (shiroSecurityManager != null) {
            return shiroSecurityManager;
        }
        try {
            return SecurityUtils.getSecurityManager();
        } catch (UnavailableSecurityManagerException e) {
            throw new IllegalStateException("Attached to an externally configured realm but no global Shiro SecurityManager is set", e);
        }
    }

    public DSAuthorizingRealm getRealm() {
        return realm;
    }

    /** The matcher, for JWT policy knobs (clock skew, timestamp window, replay cache). */
    public CredentialsInfoMatcher getCredentialsMatcher() {
        return credentialsMatcher;
    }

    /**
     * Make this manager's own Shiro security manager the JVM-wide default ({@link SecurityUtils}).
     *
     * @throws IllegalStateException in attached mode: the INI-built security manager is the one to install
     */
    public ShiroDSDomainSecurityManager installAsGlobal() {
        if (shiroSecurityManager == null) {
            throw new IllegalStateException("Attached to an externally configured SecurityManager; install that one with SecurityUtils.setSecurityManager");
        }
        SecurityUtils.setSecurityManager(shiroSecurityManager);
        registerAsResource();
        return this;
    }

    /**
     * Publishes this manager under {@link ResourceManager.Resource#DOMAIN_SECURITY_MANAGER} when the
     * slot is empty, so HTTP services that only know the core interface can find it.
     */
    private void registerAsResource() {
        if (ResourceManager.lookupResource(ResourceManager.Resource.DOMAIN_SECURITY_MANAGER) == null) {
            ResourceManager.SINGLETON.register(ResourceManager.Resource.DOMAIN_SECURITY_MANAGER, this);
        }
    }

    public boolean isEagerAuthorization() {
        return realm.isEagerAuthorization();
    }

    /** Load and cache roles/permissions at login instead of on the first authorization check (see {@link DSAuthorizingRealm#setEagerAuthorization}). */
    public ShiroDSDomainSecurityManager setEagerAuthorization(boolean eager) {
        realm.setEagerAuthorization(eager);
        return this;
    }

    public boolean isEnforcePermissions() {
        return enforcePermissions;
    }

    /** When on, mutations require the thread-bound Shiro subject to hold the matching permission. */
    public ShiroDSDomainSecurityManager setEnforcePermissions(boolean enforcePermissions) {
        this.enforcePermissions = enforcePermissions;
        return this;
    }

    /**
     * Full Shiro login: authenticates, creates a session, binds the resulting {@link Subject} to the
     * calling thread and returns it. Use {@link #logout()} to end it.
     *
     * @throws AccessSecurityException on any authentication failure (generic message)
     */
    public Subject loginSubject(String principalID, String password, String domainID, String appID)
            throws AccessSecurityException {
        if (SUS.isEmpty(principalID) || password == null) {
            throw new AccessSecurityException(INVALID_CREDENTIALS);
        }
        return bindSubject(new DomainUsernamePasswordToken(principalID, password, false, null, domainID, appID), INVALID_CREDENTIALS);
    }

    /**
     * Full Shiro login with a JWT bearer token (see {@link #loginJWT}): session, thread binding,
     * returned {@link Subject}. The Shiro principal collection also carries the key ID
     * ({@code DomainPrincipalCollection.getJWSubjectID()}).
     *
     * @param host caller host for the Shiro token, or {@code null}
     */
    public Subject loginSubjectJWT(String compactJWT, String host) throws AccessSecurityException {
        return bindSubject(jwtToken(compactJWT, host), INVALID_TOKEN);
    }

    /**
     * Full Shiro login with a JWT bearer token that leaves the calling thread alone: the subject is
     * logged in (session included) and returned, <b>not bound</b>. It is the subject to hand to
     * xlogistx-shiro's {@code io.xlogistx.shiro.SubjectSwap} (same thread) or {@code SubjectTask}
     * (another thread) — the way an application runs a registrar sign-up:
     * <pre>
     *   Subject registrar = dsm.loginUnboundSubjectJWT(ShiroDSDomainSecurityManager.mintJWT(key, null, ttl), null);
     *   try (SubjectSwap swap = new SubjectSwap(registrar)) {
     *       dsm.registerSubject(principal, password); // the registrar is the acting subject here only
     *   }                                             // the thread's previous subject is back
     * </pre>
     * The caller owns the returned subject: it may keep it for the next sign-ups or end it with
     * {@code logout()}.
     *
     * @param host caller host for the Shiro token, or {@code null}
     * @throws AccessSecurityException on any authentication failure (generic message)
     */
    public Subject loginUnboundSubjectJWT(String compactJWT, String host) throws AccessSecurityException {
        return unboundSubject(jwtToken(compactJWT, host), INVALID_TOKEN);
    }

    /** Build a subject and log it in with {@code token}; nothing is bound to the calling thread. */
    private Subject unboundSubject(AuthenticationToken token, String failureMessage) {
        Subject subject = new Subject.Builder(securityManager()).buildSubject();
        try {
            subject.login(token);
        } catch (AuthenticationException e) {
            logAuthFailure(token, e);
            throw new AccessSecurityException(failureMessage);
        }
        return subject;
    }

    /** Build a subject, log it in with {@code token}, bind it to the calling thread. */
    private Subject bindSubject(AuthenticationToken token, String failureMessage) {
        Subject subject = unboundSubject(token, failureMessage);
        ThreadContext.bind(subject);
        return subject;
    }

    /** Log out and unbind the Shiro subject bound to the calling thread, if any. */
    public void logout() {
        Subject subject = ThreadContext.getSubject();
        if (subject != null) {
            try {
                subject.logout();
            } finally {
                ThreadContext.unbindSubject();
            }
        }
    }

    // ------------------------------------------------------------------
    // login
    // ------------------------------------------------------------------

    @Override
    public SubjectIdentifier login(String principalID, String credential) throws AccessSecurityException {
        if (SUS.isEmpty(principalID) || credential == null) {
            throw new AccessSecurityException(INVALID_CREDENTIALS);
        }
        return authenticate(new DomainUsernamePasswordToken(principalID, credential, false, null, null, null), INVALID_CREDENTIALS);
    }

    /**
     * Always refuses: an API key does not log anyone in (user rule 2026-10-03). It is a subject's
     * credential for a third-party API; the subject logs in with a password or a JWT, then reads its
     * key from the store. Kept only because the core interface still declares it.
     *
     * @throws AccessSecurityException always
     */
    @Override
    @SuppressWarnings("deprecation")
    public SubjectIdentifier loginApiKey(String key) throws AccessSecurityException {
        throw new AccessSecurityException(INVALID_KEY);
    }

    /**
     * Authenticate a JWT bearer token (compact form) signed with a {@link SubjectAPIKey}'s secret:
     * the {@code sub} claim names the key ID ({@link SubjectAPIKey#getSubjectID()}), the HMAC is
     * checked with the key's bytes, {@code exp} / {@code nbf} / scope / status rules apply (see
     * {@link CredentialsInfoMatcher}). Authenticator only: no subject, session or thread binding.
     *
     * @return the owning subject
     * @throws AccessSecurityException on any failure (generic message; the cause is logged at INFO)
     */
    public SubjectIdentifier loginJWT(String compactJWT) throws AccessSecurityException {
        return authenticate(jwtToken(compactJWT, null), INVALID_TOKEN);
    }

    /** Parse (without verifying) a compact JWT into a Shiro token; any defect becomes {@link AccessSecurityException}. */
    private static JWTAuthenticationToken jwtToken(String compactJWT, String host) {
        if (SUS.isEmpty(compactJWT)) {
            throw new AccessSecurityException(INVALID_TOKEN);
        }
        String trimmed = compactJWT.trim();
        try {
            JWT jwt = SecUtil.parseJWT(trimmed);
            return new JWTAuthenticationToken(new JWTToken(jwt, trimmed), host);
        } catch (Exception e) {
            if (log.isEnabled()) log.getLogger().log(Level.INFO, "unparseable JWT: " + e);
            throw new AccessSecurityException(INVALID_TOKEN);
        }
    }

    /**
     * Mint a compact JWT that {@link #loginJWT} will accept for {@code sak}: {@code sub} = the key
     * ID, domain / app claims = the key's scope (when set), {@code iat} = now, a fresh nonce, and
     * {@code exp} = now + {@code ttlMillis} when positive. Signed with the key's secret bytes.
     *
     * @param algo HMAC algorithm, {@code null} for HS256
     * @throws IllegalArgumentException when the key is not a signing key, or has no key ID or no secret
     */
    public static String mintJWT(SubjectAPIKey sak, CryptoConst.JWTAlgo algo, long ttlMillis) {
        SUS.checkIfNulls("API key can't be null", sak);
        if (!sak.isSigningKey()) {
            throw new IllegalArgumentException("Not a signing key: only a SYMMETRIC_KEY signs a login token");
        }
        if (SUS.isEmpty(sak.getSubjectID())) {
            throw new IllegalArgumentException("API key has no key ID (principalID)");
        }
        byte[] secret = sak.getAPIKeyAsBytes();
        if (secret == null || secret.length == 0) {
            throw new IllegalArgumentException("API key has no secret");
        }
        String domainID = sak.getAppID() != null ? sak.getAppID().getDomainID() : null;
        String appID = sak.getAppID() != null ? sak.getAppID().getAppID() : null;
        JWT jwt = JWT.createJWT(algo != null ? algo : CryptoConst.JWTAlgo.HS256, sak.getSubjectID(), domainID, appID);
        if (ttlMillis > 0) {
            jwt.getPayload().setExpirationTime(new Date(System.currentTimeMillis() + ttlMillis));
        }
        return jwt.hash(secret, JWTProvider.SINGLETON);
    }

    /**
     * Checks a password against the principal's stored {@link CIPassword} without logging in:
     * nothing is bound, no session is created and the Shiro authenticator is not involved.
     *
     * <p>Meant for the "prove you know the current password" step of a password-reset flow, which
     * {@link #login} cannot serve because it denies every subject that is not ACTIVE. The subject
     * may be ACTIVE or {@link SecConst.SecStatus#PENDING_RESET_PASSWORD}; the principal and the
     * password credential must be ACTIVE or unset, as for {@link #login}.</p>
     *
     * @return {@code true} only if the principal resolves, the status rules above hold and the
     *         password matches; {@code false} for every other case (never throws for bad input)
     */
    public boolean verifyPassword(String principalID, String password) {
        if (SUS.isEmpty(principalID) || password == null) {
            return false;
        }
        PrincipalIdentifier principal = lookupPrincipalID(principalID);
        if (principal == null || !DSAuthorizingRealm.isActiveOrUnset(principal.getStatus())) {
            return logVerifyFailure(principalID, "unknown or inactive principal");
        }
        SubjectIdentifier subject = SUS.isEmpty(principal.getSubjectGUID()) ? null : lookupSubjectByGUID(principal.getSubjectGUID());
        if (subject == null) {
            return logVerifyFailure(principalID, "unknown subject");
        }
        SecConst.SecStatus status = subject.getSubjectStatus();
        if (status != SecConst.SecStatus.ACTIVE && status != SecConst.SecStatus.PENDING_RESET_PASSWORD) {
            return logVerifyFailure(principalID, "subject status " + status);
        }
        CIPassword stored = null;
        for (CredentialInfo ci : lookupCredentialsBySubjectGUID(subject.getGUID(), CredentialInfo.Type.PASSWORD)) {
            if (ci instanceof CIPassword) {
                stored = (CIPassword) ci;
                break;
            }
        }
        if (stored == null || !DSAuthorizingRealm.isActiveOrUnset(stored.getCredentialStatus())) {
            return logVerifyFailure(principalID, "missing or inactive password credential");
        }
        try {
            return SecUtil.isPasswordValid(stored, password) || logVerifyFailure(principalID, "password mismatch");
        } catch (RuntimeException e) {
            return logVerifyFailure(principalID, "unreadable password credential: " + e);
        }
    }

    private static boolean logVerifyFailure(String principalID, String why) {
        if (log.isEnabled()) log.getLogger().log(Level.INFO, "verifyPassword failed for " + principalID + ": " + why);
        return false;
    }

    // ------------------------------------------------------------------
    // password reset
    // ------------------------------------------------------------------

    private static final String INVALID_RESET = "Invalid or expired reset token";
    /** EMAIL-channel token lifetime; default {@code SecStatus.PENDING_RESET_PASSWORD.getValue()} (2 days). */
    private volatile long emailResetTTLMillis = SecConst.SecStatus.PENDING_RESET_PASSWORD.getValue();
    /** ADMIN-channel token lifetime; default 4 hours (the hand-off is synchronous). */
    private volatile long adminResetTTLMillis = 4L * Const.TimeInMillis.HOUR.MILLIS;

    /** Token lifetime per channel; must be positive. */
    public ShiroDSDomainSecurityManager setResetTokenTTL(PasswordResetToken.Channel channel, long ttlMillis) {
        SUS.checkIfNulls("channel can't be null", channel);
        if (ttlMillis <= 0) {
            throw new IllegalArgumentException("ttl must be positive");
        }
        if (channel == PasswordResetToken.Channel.ADMIN) {
            adminResetTTLMillis = ttlMillis;
        } else {
            emailResetTTLMillis = ttlMillis;
        }
        return this;
    }

    public long getResetTokenTTL(PasswordResetToken.Channel channel) {
        return channel == PasswordResetToken.Channel.ADMIN ? adminResetTTLMillis : emailResetTTLMillis;
    }

    /** Unenforced status write: the reset paths are authorized by the token, not by a bound subject. */
    private void setSubjectStatusInternal(SubjectIdentifier subject, SecConst.SecStatus status) {
        subject.setSubjectStatus(status);
        subject.setLastTimeUpdated(System.currentTimeMillis());
        ds().update(subject);
        realm.evictAuthorization(subject.getGUID());
    }

    private List<PasswordResetToken> resetTokensOf(String subjectGUID) {
        return ds().search(PasswordResetToken.NVC_PASSWORD_RESET_TOKEN, null, eq(MetaToken.SUBJECT_GUID, subjectGUID));
    }

    /** Marks every outstanding token of the subject INACTIVE (superseded); returns how many. */
    private int supersedeOutstanding(String subjectGUID, long now) {
        int ret = 0;
        for (PasswordResetToken t : resetTokensOf(subjectGUID)) {
            if (t.isOutstanding(now)) {
                t.setStatus(SecConst.SecStatus.INACTIVE);
                ds().update(t);
                ret++;
            }
        }
        return ret;
    }

    /** True while the subject has an ACTIVE, unexpired reset token (the realm consults this for PENDING subjects). */
    @Override
    public boolean hasOutstandingResetToken(String subjectGUID) {
        long now = System.currentTimeMillis();
        for (PasswordResetToken t : resetTokensOf(subjectGUID)) {
            if (t.isOutstanding(now)) {
                return true;
            }
        }
        return false;
    }

    /** A PENDING_RESET_PASSWORD subject whose token expired is restored to ACTIVE (bounded lockout). */
    @Override
    public void restoreActiveAfterExpiredReset(SubjectIdentifier subject) {
        if (subject != null && subject.getSubjectStatus() == SecConst.SecStatus.PENDING_RESET_PASSWORD) {
            setSubjectStatusInternal(subject, SecConst.SecStatus.ACTIVE);
        }
    }

    /** The subject behind a principal when both are usable for a reset; generic failures otherwise. */
    private SubjectIdentifier resetableSubject(PrincipalIdentifier principal) {
        if (principal == null || !DSAuthorizingRealm.isActiveOrUnset(principal.getStatus())) {
            throw new AccessSecurityException("Unknown principal");
        }
        SubjectIdentifier subject = SUS.isEmpty(principal.getSubjectGUID()) ? null : lookupSubjectByGUID(principal.getSubjectGUID());
        if (subject == null) {
            throw new AccessSecurityException("Unknown principal");
        }
        SecConst.SecStatus status = subject.getSubjectStatus();
        if (status != SecConst.SecStatus.ACTIVE && status != SecConst.SecStatus.PENDING_RESET_PASSWORD) {
            throw new AccessSecurityException("Subject is not active");
        }
        return subject;
    }

    /** Active principals of the subject that are email addresses: the recovery channel. */
    private String[] emailPrincipalsOf(String subjectGUID) {
        List<String> ret = new ArrayList<>();
        for (PrincipalIdentifier p : lookupAllPrincipalIdentifiers(subjectGUID)) {
            if (DSAuthorizingRealm.isActiveOrUnset(p.getStatus()) && FilterType.EMAIL.isValid(p.getPrincipalID())) {
                ret.add(p.getPrincipalID());
            }
        }
        return ret.toArray(new String[0]);
    }

    private PasswordResetRequest issueResetToken(SubjectIdentifier subject, String principalID, PasswordResetToken.Channel channel,
                                                 String brokerGUID, String[] delivery) {
        long now = System.currentTimeMillis();
        long ttl = getResetTokenTTL(channel);
        String clear = PasswordResetTokenUtil.newToken();
        PasswordResetToken row = new PasswordResetToken();
        row.setSubjectGUID(subject.getGUID());
        row.setPrincipalID(principalID);
        row.setTokenHash(PasswordResetTokenUtil.hash(clear));
        row.setExpiryTS(now + ttl);
        row.setConsumedTS(0);
        row.setStatus(SecConst.SecStatus.ACTIVE);
        row.setChannel(channel);
        row.setBrokerGUID(brokerGUID);
        inTransaction(() -> {
            supersedeOutstanding(subject.getGUID(), now);
            ds().insert(row);
            setSubjectStatusInternal(subject, SecConst.SecStatus.PENDING_RESET_PASSWORD);
            return null;
        });
        return new PasswordResetRequest(clear, subject.getGUID(), principalID, delivery, row.getExpiryTS(), channel);
    }

    /**
     * {@inheritDoc}
     * <p>Anonymous by design: no enforcement. Every email principal of the subject is a delivery address.
     */
    @Override
    public PasswordResetRequest requestPasswordReset(String principalID) throws AccessSecurityException {
        PrincipalIdentifier principal = resolvePrincipal(principalID);
        if (principal == null) {
            throw new AccessSecurityException("Unknown principal");
        }
        SubjectIdentifier subject = resetableSubject(principal);
        String[] emails = emailPrincipalsOf(subject.getGUID());
        if (emails.length == 0) {
            throw new NoRecoveryChannelException("Subject has no email principal");
        }
        return issueResetToken(subject, principal.getPrincipalID(), PasswordResetToken.Channel.EMAIL, null, emails);
    }

    /**
     * {@inheritDoc}
     * <p>Requires {@code subject:update} (the wildcard implies it); the bound subject is recorded as the broker.
     */
    @Override
    public PasswordResetRequest adminResetPassword(String principalID) throws AccessSecurityException {
        enforce(SecurityModel.PERM_UPDATE_SUBJECT);
        String pid = requirePrincipal(principalID);
        PrincipalIdentifier principal = resolvePrincipal(pid);
        if (principal == null) {
            throw new AccessSecurityException("Unknown principal: " + pid);
        }
        SubjectIdentifier subject = resetableSubject(principal);
        return issueResetToken(subject, principal.getPrincipalID(), PasswordResetToken.Channel.ADMIN, currentSubjectGUID(),
                emailPrincipalsOf(subject.getGUID()));
    }

    /**
     * {@inheritDoc}
     * <p>Anonymous by design: the token is the authorization. Every failure other than the password
     * policy collapses to one generic message; the reason is logged at INFO when logging is on.
     */
    @Override
    public void completePasswordReset(String principalID, String token, String newPassword) throws AccessSecurityException {
        PrincipalIdentifier principal = resolvePrincipal(principalID);
        if (principal == null || SUS.isEmpty(token)) {
            throw resetFailure(principalID, "unknown principal or empty token");
        }
        SubjectIdentifier subject = SUS.isEmpty(principal.getSubjectGUID()) ? null : lookupSubjectByGUID(principal.getSubjectGUID());
        if (subject == null) {
            throw resetFailure(principalID, "unknown subject");
        }
        FilterType.PASSWORD.validate(newPassword);
        long now = System.currentTimeMillis();
        inTransaction(() -> {
            ds().update(subject); // row lock: two completions serialize on the subject
            PasswordResetToken match = null;
            for (PasswordResetToken t : resetTokensOf(subject.getGUID())) {
                if (t.isOutstanding(now) && PasswordResetTokenUtil.matches(t.getTokenHash(), token)) {
                    match = t;
                }
            }
            if (match == null) {
                throw resetFailure(principalID, "no outstanding token matches");
            }
            SecConst.SecStatus status = subject.getSubjectStatus();
            if (status != SecConst.SecStatus.ACTIVE && status != SecConst.SecStatus.PENDING_RESET_PASSWORD) {
                throw resetFailure(principalID, "subject status " + status);
            }
            replacePassword(subject.getGUID(), HashUtil.toBCryptPassword(newPassword));
            match.setStatus(SecConst.SecStatus.DEACTIVATED);
            match.setConsumedTS(now);
            ds().update(match);
            supersedeOutstanding(subject.getGUID(), now);
            setSubjectStatusInternal(subject, SecConst.SecStatus.ACTIVE);
            return null;
        });
    }

    private static AccessSecurityException resetFailure(String principalID, String why) {
        if (log.isEnabled()) log.getLogger().log(Level.INFO, "password reset failed for " + principalID + ": " + why);
        return new AccessSecurityException(INVALID_RESET);
    }

    /** {@inheritDoc} Self-or-{@code subject:update} under enforcement. */
    @Override
    public boolean cancelPasswordReset(String principalID) {
        PrincipalIdentifier principal = resolvePrincipal(principalID);
        SubjectIdentifier subject = principal == null || SUS.isEmpty(principal.getSubjectGUID()) ? null
                : lookupSubjectByGUID(principal.getSubjectGUID());
        if (subject == null) {
            return false;
        }
        enforceSelfOr(subject.getGUID(), SecurityModel.PERM_UPDATE_SUBJECT);
        return inTransaction(() -> {
            boolean changed = supersedeOutstanding(subject.getGUID(), System.currentTimeMillis()) > 0;
            if (subject.getSubjectStatus() == SecConst.SecStatus.PENDING_RESET_PASSWORD) {
                setSubjectStatusInternal(subject, SecConst.SecStatus.ACTIVE);
                changed = true;
            }
            return changed;
        });
    }

    @Override
    public int purgeExpiredResetTokens() {
        long now = System.currentTimeMillis();
        int ret = 0;
        List<PasswordResetToken> all = ds().search(PasswordResetToken.NVC_PASSWORD_RESET_TOKEN, null);
        for (PasswordResetToken t : all) {
            if (!t.isOutstanding(now) && ds().delete(t, false)) {
                ret++;
            }
        }
        return ret;
    }

    /** Authenticator-only path: no subject, no session, no thread binding. */
    private SubjectIdentifier authenticate(AuthenticationToken token, String failureMessage) {
        AuthenticationInfo info;
        try {
            info = securityManager().authenticate(token);
        } catch (AuthenticationException e) {
            logAuthFailure(token, e);
            throw new AccessSecurityException(failureMessage);
        }
        String subjectGUID = info != null ? DSAuthorizingRealm.subjectGUIDOf(info.getPrincipals()) : null;
        SubjectIdentifier subject = subjectGUID != null ? lookupSubjectByGUID(subjectGUID) : null;
        if (subject == null) {
            throw new AccessSecurityException(failureMessage);
        }
        return subject;
    }

    private static void logAuthFailure(AuthenticationToken token, AuthenticationException e) {
        if (log.isEnabled()) {
            Throwable cause = e.getCause();
            log.getLogger().log(Level.INFO, "authentication failed for " + token + ": " + e
                    + (cause != null ? " caused by " + cause : ""), cause);
        }
    }

    // ------------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------------

    /**
     * The store as this manager uses it: {@link #systemView} of the configured store. The security
     * rows are read and written with nobody logged in (login, grant loading) and on behalf of other
     * subjects (creating a subject, granting), which the store's own access check would refuse; who
     * may call what is decided here, by {@link #enforce} and its variants.
     */
    private APIDataStore<?, ?> ds() {
        APIDataStore<?, ?> ret = systemStore;
        if (ret == null) {
            throw new IllegalStateException("No data store set");
        }
        return ret;
    }

    /**
     * A view of {@code store} whose every call runs in the system context of the store's
     * {@link SecurityController} ({@link SecurityController#runAsSystem}), resolved per call so a
     * controller configured later is honoured. A store without controller checks nothing and is
     * called directly.
     * <p>The store's access check asks Shiro whether the bound subject is permitted; answering loads
     * that subject's grants through this manager. Those reads must not be access-checked themselves
     * — the check would call itself without end.
     */
    private static APIDataStore<?, ?> systemView(APIDataStore<?, ?> store) {
        return (APIDataStore<?, ?>) Proxy.newProxyInstance(APIDataStore.class.getClassLoader(),
                new Class<?>[]{APIDataStore.class},
                (proxy, method, args) -> {
                    SecurityController sc = store.getAPIConfigInfo() != null ? store.getAPIConfigInfo().getSecurityController() : null;
                    Throwable[] failure = new Throwable[1];
                    Supplier<Object> call = () -> {
                        try {
                            return method.invoke(store, args);
                        } catch (InvocationTargetException e) {
                            failure[0] = e.getCause();
                        } catch (IllegalAccessException e) {
                            failure[0] = e;
                        }
                        return null;
                    };
                    Object ret = sc != null ? sc.runAsSystem(call) : call.get();
                    if (failure[0] != null) {
                        throw failure[0];
                    }
                    return ret;
                });
    }

    /**
     * Run {@code body} inside the ambient transaction if one is active on this thread, otherwise
     * inside a new one that is committed on success and rolled back on any throwable.
     */
    <T> T inTransaction(Supplier<T> body) {
        APIDataStore<?, ?> ds = ds();
        if (ds.isTransactionActive()) {
            return body.get();
        }
        ds.beginTransaction();
        boolean ok = false;
        try {
            T ret = body.get();
            ok = true;
            return ret;
        } finally {
            if (ok) {
                ds.endTransaction();
            } else {
                ds.abortTransaction();
            }
        }
    }

    private static <V> V first(List<V> list) {
        return (list == null || list.isEmpty()) ? null : list.get(0);
    }

    private static QueryMatch<String> eq(GetName field, String value) {
        return new QueryMatch<>(field.getName(), value, RelationalOperator.EQUAL);
    }

    /**
     * Normalizes a principal ID for storage and comparison with {@link SecConst.SubjectIDFilter}
     * (trimmed, lower-cased, no invisible characters, minimum length unless it is an email).
     *
     * @return the normalized ID, or {@code null} if the filter rejects it (a rejected ID can match
     *         no stored row, so lookups treat it as unknown)
     */
    static String normalizePrincipal(String principalID) {
        if (principalID == null) {
            return null;
        }
        try {
            return SecConst.SubjectIDFilter.SINGLETON.validate(principalID);
        } catch (NullPointerException | IllegalArgumentException e) {
            return null;
        }
    }

    /** Same as {@link #normalizePrincipal} but surfaces the filter's reason as a {@link AccessSecurityException}. */
    static String requirePrincipal(String principalID) {
        try {
            return SecConst.SubjectIDFilter.SINGLETON.validate(principalID);
        } catch (NullPointerException | IllegalArgumentException e) {
            throw new AccessSecurityException("Invalid principal ID: " + e.getMessage(), e);
        }
    }

    /**
     * The scope the {@code appID} argument of the catalog lookups names: null or blank is the
     * common app, anything else the canonical {@code <domain>-<app>} id.
     */
    private static String lookupScope(String appID) {
        return SUS.isEmpty(appID) ? COMMON_SCOPE : ShiroUtil.appScope(AppIDDefault.create(appID.trim()));
    }

    /** True when the catalog row belongs to the app the lookup names (domain and app, case-insensitive). */
    private static boolean appIDMatches(AuthzInfo info, String appID) {
        return ShiroUtil.scopeLabel(info.getAppID()).equals(lookupScope(appID));
    }

    private PrincipalIdentifier resolvePrincipal(String principalID) {
        String pid = normalizePrincipal(principalID);
        if (SUS.isEmpty(pid)) {
            return null;
        }
        return first(ds().search(PrincipalIdentifier.NVC_PRINCIPAL_IDENTIFIER, null,
                new QueryMatch<>(RelationalOperator.EQUAL, pid, PrincipalIdentifier.Param.PRINCIPAL_ID)));
    }

    private String resolveSubjectGUID(String principalID) {
        PrincipalIdentifier principal = resolvePrincipal(principalID);
        return principal != null ? principal.getSubjectGUID() : null;
    }

    private int countPrincipals(String subjectGUID) {
        return ds().search(PrincipalIdentifier.NVC_PRINCIPAL_IDENTIFIER, APIDataStore.fieldNames(MetaToken.GUID),
                eq(MetaToken.SUBJECT_GUID, subjectGUID)).size();
    }

    private <V extends NVEntity> List<V> byName(NVConfigEntity nvce, String name) {
        return ds().search(nvce, null, eq(MetaToken.NAME, name));
    }

    /** Registered credential classes plus {@link SubjectAPIKey}, which login always honours. */
    private Set<Class<?>> credentialClasses() {
        Set<Class<?>> ret = new LinkedHashSet<>(credentialCollections);
        ret.add(SubjectAPIKey.class);
        return ret;
    }

    // ------------------------------------------------------------------
    // super-admin and the reserved wildcard
    // ------------------------------------------------------------------

    /**
     * @return the normalized principal ID of the super-admin account, or null while none has been
     * set. There is no default (user rule 2026-10-03): the value comes from the SecretStore's
     * reserved {@code super-admin-id} entry, through {@link #setSuperAdminPrincipalID}.
     */
    public String getSuperAdminPrincipalID() {
        return realm.getSuperAdminPrincipalID();
    }

    /**
     * @return the super-admin principal ID
     * @throws IllegalStateException when none has been set
     */
    public String requireSuperAdminPrincipalID() {
        String ret = getSuperAdminPrincipalID();
        if (SUS.isEmpty(ret)) {
            throw new IllegalStateException("No super-admin id set: it comes from the SecretStore entry super-admin-id"
                    + " and is handed to setSuperAdminPrincipalID at start-up");
        }
        return ret;
    }

    /**
     * Names the one account allowed to hold the wildcard permission {@code *}. Called by the
     * start-up code with the SecretStore's {@code super-admin-id}; nothing names it in code. The
     * value is normalized through {@link SecConst.SubjectIDFilter}; every cached authorization is
     * evicted so a former super-admin loses the wildcard on its next authorization load.
     *
     * @param principalID the super-admin principal ID
     * @return this manager, for call chaining
     */
    public ShiroDSDomainSecurityManager setSuperAdminPrincipalID(String principalID) {
        realm.setSuperAdminPrincipalID(principalID);
        return this;
    }

    /** True if the subject owns the super-admin principal ID; false for everybody while no super-admin id is set. */
    public boolean isSuperAdminSubject(String subjectGUID) {
        String superAdmin = getSuperAdminPrincipalID();
        if (SUS.isEmpty(subjectGUID) || SUS.isEmpty(superAdmin)) {
            return false;
        }
        for (PrincipalIdentifier p : lookupAllPrincipalIdentifiers(subjectGUID)) {
            if (superAdmin.equals(p.getPrincipalID())) {
                return true;
            }
        }
        return false;
    }

    /** The super-admin subject, or null when it has not been bootstrapped yet or no super-admin id is set. */
    public SubjectIdentifier lookupSuperAdminSubject() {
        String superAdmin = getSuperAdminPrincipalID();
        return SUS.isEmpty(superAdmin) ? null : lookupSubjectID(superAdmin);
    }

    /** A catalog row whose token is the wildcard: only the reserved {@code super_admin_all} row may be one. */
    private static boolean isReservedPermission(PermissionInfo permission) {
        return permission != null && SecurityModel.isWildcardToken(permission.getPermissionToken());
    }

    /** The reserved rows live in the common app only. */
    private static boolean isReservedName(AuthzInfo info, GetName reserved) {
        return info != null && reserved.getName().equals(info.getName()) && isCommonScope(info.getAppID());
    }

    /** True if the role is the reserved {@code super_admin} role or embeds a reserved permission (refs re-read by GUID). */
    private boolean isReservedRole(RoleInfo role) {
        if (role == null) {
            return false;
        }
        if (isReservedName(role, SecurityModel.Role.SUPER_ADMIN)) {
            return true;
        }
        PermissionInfo[] permissions = role.getPermissions();
        if (permissions != null) {
            for (PermissionInfo p : permissions) {
                if (p == null) {
                    continue;
                }
                PermissionInfo stored = SUS.isEmpty(p.getGUID()) ? null : lookupPermissionByGUID(p.getGUID());
                if (isReservedPermission(stored != null ? stored : p)) {
                    return true;
                }
            }
        }
        return false;
    }

    /** True if the group embeds the reserved role (roles re-read by GUID). */
    private boolean groupHasReservedRole(RoleGroupInfo group) {
        RoleInfo[] roles = group != null ? group.getRoles() : null;
        if (roles != null) {
            for (RoleInfo r : roles) {
                if (r == null) {
                    continue;
                }
                RoleInfo stored = SUS.isEmpty(r.getGUID()) ? null : lookupRoleByGUID(r.getGUID());
                if (isReservedRole(stored != null ? stored : r)) {
                    return true;
                }
            }
        }
        return false;
    }

    private PermissionInfo reservedPermissionRow() {
        return lookupPermission(null, SecurityModel.Permission.SUPER_ADMIN_ALL.getName());
    }

    private RoleInfo reservedRoleRow() {
        return lookupRole(null, SecurityModel.Role.SUPER_ADMIN.getName());
    }

    /**
     * Seeds or repairs the built-in catalog ({@link SecuritySetup#seedCatalog}): every
     * {@link SecurityModel.Permission}, {@link SecurityModel.Role} and {@link SecurityModel.RoleGroup}
     * as global rows. Idempotent; grants nothing.
     */
    public SecuritySetup.Report seedCatalog() {
        // a catalog write even when nothing turns out to need repair
        enforce(SecurityModel.PERM_ADD_PERMISSION);
        enforce(SecurityModel.PERM_ADD_ROLE);
        return SecuritySetup.seedCatalog(this);
    }

    /** A reserved permission, role or group may be granted to the super-admin subject only. */
    private void enforceReservedGrantee(String subjectGUID, String what) {
        if (!isSuperAdminSubject(subjectGUID)) {
            throw new AccessSecurityException("Only the super-admin account may hold " + what, Reason.UNAUTHORIZED);
        }
    }

    // ------------------------------------------------------------------
    // permission enforcement (opt-in)
    // ------------------------------------------------------------------

    private static Subject boundSubject() {
        return ThreadContext.getSubject();
    }

    /** Require the bound subject to hold {@code permission}; no-op unless enforcement is on. */
    private void enforce(String permission) {
        if (!enforcePermissions) {
            return;
        }
        Subject subject = boundSubject();
        if (subject == null || !subject.isAuthenticated()) {
            throw new AccessSecurityException("Authentication required for " + permission, Reason.UNAUTHORIZED);
        }
        ShiroUtil.checkPermissions(subject, permission);
    }

    /** Like {@link #enforce}, but a subject acting on itself is always allowed. */
    private void enforceSelfOr(String subjectGUID, String permission) {
        if (!enforcePermissions) {
            return;
        }
        Subject subject = boundSubject();
        if (subject != null && subject.isAuthenticated() && subjectGUID != null
                && subjectGUID.equals(DSAuthorizingRealm.subjectGUIDOf(subject.getPrincipals()))) {
            return;
        }
        enforce(permission);
    }

    /** GUID of the bound, authenticated subject; null when nobody is bound. */
    private static String currentSubjectGUID() {
        Subject subject = boundSubject();
        return subject != null && subject.isAuthenticated()
                ? DSAuthorizingRealm.subjectGUIDOf(subject.getPrincipals()) : null;
    }

    /** True if a bound, authenticated subject holds {@code permission}; never throws. */
    private static boolean holds(String permission) {
        Subject subject = boundSubject();
        return subject != null && subject.isAuthenticated() && ShiroUtil.isPermitted(subject, permission);
    }

    // ------------------------------------------------------------------
    // app scope
    // ------------------------------------------------------------------

    /** Both domain and app must be set; the canonical ID getter validates the two parts. */
    private static void requireApp(AppIDDefault app) {
        if (SUS.isEmpty(app.getDomainID()) || SUS.isEmpty(app.getAppID())) {
            throw new IllegalArgumentException("app scope needs both domain and app id: " + app);
        }
        app.getDomainAppID();
    }

    private static boolean isCommonScope(AppIDDefault app) {
        return COMMON_SCOPE.equals(ShiroUtil.scopeLabel(app));
    }

    private static boolean sameScope(AppIDDefault a, AppIDDefault b) {
        return ShiroUtil.scopeLabel(a).equals(ShiroUtil.scopeLabel(b));
    }

    /** The record of the common app ({@code xlogistx.com-common}), or null until the setup created it. */
    public AppIDDefault commonApp() {
        return lookupApp(COMMON_DOMAIN_ID, COMMON_APP_ID);
    }

    /**
     * The stored record of {@code app} — the one row every scoped grant, key and catalog row
     * references.
     *
     * @throws IllegalArgumentException if the pair is invalid or the app was never created
     */
    AppIDDefault appRecord(AppIDDefault app) {
        SUS.checkIfNulls("app can't be null", app);
        requireApp(app);
        AppIDDefault stored = lookupApp(app.getDomainID(), app.getAppID());
        if (stored == null) {
            throw new IllegalArgumentException("unknown app " + ShiroUtil.appScope(app) + ": create it first");
        }
        return stored;
    }

    /** {@link #appRecord} of {@code app}, or the common app's record for null. */
    private AppIDDefault recordOrCommon(AppIDDefault app) {
        if (app != null) {
            return appRecord(app);
        }
        AppIDDefault common = commonApp();
        if (common == null) {
            throw new IllegalStateException("the common app " + COMMON_SCOPE + " does not exist yet: run the setup first");
        }
        return common;
    }

    /** A catalog row is grantable inside its own app only; a grant with no app is a grant in the common app. */
    private static void requireGrantableIn(AuthzInfo catalogRow, AppIDDefault scope) {
        if (!sameScope(catalogRow.getAppID(), scope)) {
            throw new IllegalArgumentException(catalogRow.getName() + " belongs to app " + ShiroUtil.scopeLabel(catalogRow.getAppID())
                    + " and can not be granted in " + ShiroUtil.scopeLabel(scope));
        }
    }

    /** A role carries permissions of its own app only (nothing is shared between apps). */
    private void requireSameAppPermissions(RoleInfo role) {
        PermissionInfo[] permissions = role.getPermissions();
        if (permissions == null) {
            return;
        }
        for (PermissionInfo p : permissions) {
            PermissionInfo stored = p == null || SUS.isEmpty(p.getGUID()) ? p : lookupPermissionByGUID(p.getGUID());
            if (stored != null && !sameScope(stored.getAppID(), role.getAppID())) {
                throw new IllegalArgumentException("permission " + stored.getName() + " belongs to app " + ShiroUtil.scopeLabel(stored.getAppID())
                        + ", role " + role.getName() + " to " + ShiroUtil.scopeLabel(role.getAppID()));
            }
        }
    }

    /** A role group carries roles of its own app only. */
    private void requireSameAppRoles(RoleGroupInfo group) {
        RoleInfo[] roles = group.getRoles();
        if (roles == null) {
            return;
        }
        for (RoleInfo r : roles) {
            RoleInfo stored = r == null || SUS.isEmpty(r.getGUID()) ? r : lookupRoleByGUID(r.getGUID());
            if (stored != null && !sameScope(stored.getAppID(), group.getAppID())) {
                throw new IllegalArgumentException("role " + stored.getName() + " belongs to app " + ShiroUtil.scopeLabel(stored.getAppID())
                        + ", role group " + group.getName() + " to " + ShiroUtil.scopeLabel(group.getAppID()));
            }
        }
    }

    /**
     * The record of a domain + app: the stored {@link AppIDDefault} row carrying that pair (both
     * parts are normalized by the entity's filters, so the match is case-insensitive), or null when
     * the app was never created. Every scoped grant, key and catalog row references this one row;
     * should a database still hold copies written before 2026-10-02, the earliest row (UUID v7
     * order) is the record.
     *
     * @throws IllegalArgumentException if the domain or the app id is invalid
     */
    public AppIDDefault lookupApp(String domainID, String appID) {
        AppIDDefault probe = new AppIDDefault(domainID, appID);
        requireApp(probe);
        List<AppIDDefault> rows = ds().search(AppIDDefault.NVC_APP_ID_DEFAULT, null,
                eq(AppIDResource.Param.DOMAIN_ID.getNVConfig(), probe.getDomainID()),
                Const.LogicalOperator.AND,
                eq(AppIDResource.Param.APP_ID.getNVConfig(), probe.getAppID()));
        AppIDDefault ret = null;
        for (AppIDDefault row : rows) {
            if (ret == null || row.getGUID().compareTo(ret.getGUID()) < 0) {
                ret = row;
            }
        }
        return ret;
    }

    /** What {@link #createApp(String, String, SubjectIdentifier)} made. */
    public static final class AppCreation {
        /** The app record. */
        public AppIDDefault app;
        /** The app's registrar subject. */
        public SubjectIdentifier registrar;
        /** The registrar's API key; its secret is readable here, once, and never again from the store. */
        public SubjectAPIKey registrarKey;
        /** The {@code app_admin} grant of the first manager, when one was named. */
        public RoleGrant firstManagerGrant;

        @Override
        public String toString() {
            return "app " + (app != null ? app.getDomainAppID() : null)
                    + " registrar=" + (registrar != null ? registrar.getGUID() : null)
                    + " key=" + (registrarKey != null ? registrarKey.getSubjectID() : null)
                    + (firstManagerGrant != null ? " first manager granted " + SecurityModel.Role.APP_ADMIN.getName() : "");
        }
    }

    /**
     * Creates an app: its record (owned by the bound subject, named {@code <domain>-<app>}), its own
     * starter catalog (every non platform-only {@link SecurityModel.Role} and role group with their
     * permissions — nothing is shared with other apps), its registrar subject with an API key
     * scoped to the app, and, when named, the {@code app_admin} grant of its first manager; one
     * transaction. Under enforcement the caller needs {@code app:create} (plus the catalog and
     * subject rights the starter set takes, which {@code domain_admin} holds).
     *
     * @throws IllegalArgumentException if the pair is invalid or the app already exists
     */
    public AppCreation createApp(String domainID, String appID, SubjectIdentifier firstManager) {
        return inTransaction(() -> {
            AppIDDefault record = createAppRecord(domainID, appID, currentSubjectGUID());
            SecuritySetup.seedStarterCatalog(this, record);
            AppCreation ret = ensureRegistrar(record);
            if (firstManager != null) {
                RoleInfo appAdmin = lookupRole(ShiroUtil.scopeLabel(record), SecurityModel.Role.APP_ADMIN.getName());
                ret.firstManagerGrant = addRoleGrant(firstManager, appAdmin, record);
            }
            return ret;
        });
    }

    /** {@link #createApp(String, String, SubjectIdentifier)} without a first manager; returns the record. */
    public AppIDDefault createApp(String domainID, String appID) {
        return createApp(domainID, appID, null).app;
    }

    /**
     * The bare app record, nothing else — the setup creates the common app this way (its catalog
     * is the full one, seeded separately). Under enforcement the caller needs {@code app:create}.
     *
     * @param creatorGUID the owner of the record, null when nobody is bound yet
     * @throws IllegalArgumentException if the pair is invalid or the app already exists
     */
    AppIDDefault createAppRecord(String domainID, String appID, String creatorGUID) {
        AppIDDefault app = new AppIDDefault(domainID, appID);
        requireApp(app);
        enforce(SecurityModel.PERM_CREATE_APP_ID);
        return inTransaction(() -> {
            if (lookupApp(domainID, appID) != null) {
                throw new IllegalArgumentException("app already exists: " + ShiroUtil.appScope(app));
            }
            app.setName(app.getDomainAppID());
            app.setSubjectGUID(creatorGUID);
            return ds().insert(app);
        });
    }

    /** Sets the owner of an app record (the setup hands the common app to the super-admin once it exists). */
    void setAppOwner(AppIDDefault app, String ownerGUID) {
        app.setSubjectGUID(ownerGUID);
        ds().update(app);
    }

    /**
     * Attaches a catalog row that has no app (seeded before every row belonged to one) to
     * {@code app}: the seeder's repair, which the reserved rows' immutability does not block.
     */
    void attachToApp(AuthzInfo row, AppIDDefault app) {
        row.setAppID(appRecord(app));
        ds().update(row);
        realm.evictAllAuthorization();
    }

    /**
     * Deletes an app and everything that is only its: grants scoped to it, API keys scoped to it,
     * its registrar, its catalog rows, then the record. Subjects that merely held grants in it stay.
     * Under enforcement the caller needs {@code app:delete}; the common app is never deleted.
     */
    public boolean deleteApp(AppIDDefault app) {
        SUS.checkIfNulls("app can't be null", app);
        AppIDDefault record = appRecord(app);
        if (isCommonScope(record)) {
            throw new IllegalArgumentException("the common app " + COMMON_SCOPE + " can not be deleted");
        }
        enforce(SecurityModel.PERM_DELETE_APP_ID);
        boolean ret = inTransaction(() -> {
            String label = ShiroUtil.scopeLabel(record);
            for (RoleGrant g : ds().<RoleGrant>search(RoleGrant.NVC_ROLE_GRANT, null)) {
                if (sameApp(g, record)) ds().delete(g, false);
            }
            for (RoleGroupGrant g : ds().<RoleGroupGrant>search(RoleGroupGrant.NVC_ROLE_GROUP_GRANT, null)) {
                if (sameApp(g, record)) ds().delete(g, false);
            }
            for (PermissionGrant g : ds().<PermissionGrant>search(PermissionGrant.NVC_PERMISSION_GRANT, null)) {
                if (sameApp(g, record)) deleteGrantRows(g);
            }
            SubjectIdentifier registrar = lookupRegistrar(record);
            if (registrar != null) {
                deleteSubjectRows(registrar);
            }
            for (SubjectAPIKey key : ds().<SubjectAPIKey>search(SubjectAPIKey.NVC_SUBJECT_API_KEY, null)) {
                if (key.getAppID() != null && record.equals(key.getAppID())) ds().delete(key, false);
            }
            for (RoleGroupInfo g : lookupAllRoleGroupsByAppID(label)) ds().delete(g, false);
            for (RoleInfo r : lookupAllRolesByAppID(label)) ds().delete(r, false);
            for (PermissionInfo p : lookupAllPermissionsByAppID(label)) ds().delete(p, false);
            return ds().delete(record, false);
        });
        realm.evictAllAuthorization();
        return ret;
    }

    // ------------------------------------------------------------------
    // registrar: the app's service subject for first-time subject creation (user decision 2026-10-02)
    // ------------------------------------------------------------------

    /** The registrar principal of an app: {@code registrar.<domain>-<app>} — a handle, not an email, so it has no password-reset channel. */
    public static String registrarPrincipal(AppIDDefault app) {
        return REGISTRAR_PRINCIPAL_PREFIX + ShiroUtil.scopeLabel(app);
    }

    /** The app's registrar subject, or null when the app has none (yet). */
    public SubjectIdentifier lookupRegistrar(AppIDDefault app) {
        return lookupSubjectID(registrarPrincipal(app));
    }

    /**
     * Makes sure the app has its registrar: a {@code SYSTEM} subject whose only credential is an API
     * key scoped to the app (so its login is always a login into that app) and whose only grant is
     * the app's own {@code app_registrar} role ({@code subject:create}, nothing else). Created once;
     * a later call finds it and returns no secret. Under enforcement the caller needs the subject
     * rights ({@code subject:create}, {@code subject:update}) and {@code permission:assign:role}
     * in a login that may act on the app.
     *
     * @return the record, the registrar and — only when it was created here — its key with the secret
     */
    public AppCreation ensureRegistrar(AppIDDefault app) {
        AppIDDefault record = appRecord(app);
        return inTransaction(() -> {
            AppCreation ret = new AppCreation();
            ret.app = record;
            ret.registrar = lookupRegistrar(record);
            if (ret.registrar != null) {
                return ret;
            }
            RoleInfo registrarRole = lookupRole(ShiroUtil.scopeLabel(record), SecurityModel.Role.APP_REGISTRAR.getName());
            if (registrarRole == null) {
                throw new IllegalStateException("app " + ShiroUtil.scopeLabel(record) + " has no " + SecurityModel.Role.APP_REGISTRAR.getName() + " role");
            }
            ret.registrar = createSubjectID(registrarPrincipal(record), null, BaseSubjectID.SubjectType.SYSTEM);
            ret.registrarKey = newRegistrarKey(ret.registrar, record);
            addRoleGrant(ret.registrar, registrarRole, record);
            return ret;
        });
    }

    /**
     * Replaces the registrar's API key: the old key rows are deleted, a new secret is returned once.
     * Under enforcement the caller needs {@code subject:update} in a login that may act on the app
     * (an {@code app_admin} of the app).
     */
    public SubjectAPIKey rotateRegistrarKey(AppIDDefault app) {
        AppIDDefault record = appRecord(app);
        enforceScoped(record, SecurityModel.PERM_UPDATE_SUBJECT);
        SubjectIdentifier registrar = lookupRegistrar(record);
        if (registrar == null) {
            throw new IllegalArgumentException("app " + ShiroUtil.scopeLabel(record) + " has no registrar");
        }
        return inTransaction(() -> {
            for (NVEntity old : ds().<NVEntity>search(SubjectAPIKey.NVC_SUBJECT_API_KEY, null, eq(MetaToken.SUBJECT_GUID, registrar.getGUID()))) {
                ds().delete(old, false);
            }
            return newRegistrarKey(registrar, record);
        });
    }

    private SubjectAPIKey newRegistrarKey(SubjectIdentifier registrar, AppIDDefault record) {
        SubjectAPIKey key = new SubjectAPIKey();
        key.setName("registrar-key-" + ShiroUtil.scopeLabel(record));
        byte[] secret = new byte[32];
        RANDOM.nextBytes(secret);
        key.setAPIKeyAsBytes(secret);
        key.setStatus(Const.Status.ACTIVE);
        key.setAppID(record);
        key.setCredentialType(CredentialInfo.Type.SYMMETRIC_KEY); // the registrar logs in with JWTs signed by it
        createCredential(registrar, key);
        return key;
    }

    /**
     * Sign-up: the first-time creation of a subject by an app. The caller is the app's registrar
     * (or anyone holding {@code subject:create}) logged into the app — the app comes from the
     * caller's login scope, never from a parameter, so a registrar can only register into its own
     * app. An unknown principal is created with the password; a known one must prove the password
     * ({@link #verifyPassword}) and is not created twice — the failure is the same generic
     * {@link AccessSecurityException} either way. The subject then holds the app's {@code app_user}
     * role, always that one, chosen here and not by the caller; nothing else is granted.
     *
     * @return the subject, new or existing
     */
    public SubjectIdentifier registerSubject(String principalID, String password) {
        SUS.checkIfNulls("principal and password can't be null", principalID, password);
        enforce(SecurityModel.PERM_ADD_SUBJECT);
        AppIDDefault app = recordOrCommon(loginScope());
        RoleInfo appUser = lookupRole(ShiroUtil.scopeLabel(app), SecurityModel.Role.APP_USER.getName());
        if (appUser == null) {
            throw new IllegalStateException("app " + ShiroUtil.scopeLabel(app) + " has no " + SecurityModel.Role.APP_USER.getName() + " role");
        }
        String pid = requirePrincipal(principalID);
        return inTransaction(() -> {
            SubjectIdentifier subject = lookupSubjectID(pid);
            if (subject == null) {
                subject = createSubjectID(pid, password, CryptoConst.HashType.ARGON2);
            } else if (!verifyPassword(pid, password)) {
                throw new AccessSecurityException("Registration failed", Reason.UNAUTHORIZED);
            }
            if (!holdsRoleGrant(subject.getGUID(), appUser, app)) {
                insertRoleGrant(subject, appUser, app);
            }
            return subject;
        });
    }

    private boolean holdsRoleGrant(String subjectGUID, RoleInfo role, AppIDDefault app) {
        for (RoleGrant g : getRoleGrants(subjectGUID)) {
            if (role.getGUID().equals(g.getRoleGUID()) && sameScope(g.getAppID(), app)) {
                return true;
            }
        }
        return false;
    }

    /** True if the grant is scoped to {@code app} (domain and app compared case-insensitively). */
    private static boolean sameApp(AuthzInfo grant, AppIDDefault app) {
        return app != null && grant.getAppID() != null && app.equals(grant.getAppID());
    }

    /** The login scope of the bound, authenticated subject: null for a global login. */
    private static AppIDDefault loginScope() {
        Subject subject = boundSubject();
        return subject != null && subject.isAuthenticated() ? DSAuthorizingRealm.loginScopeOf(subject.getPrincipals()) : null;
    }

    /**
     * Whether the caller's login scope may act on {@code app}: a login into the common app (which
     * a login with no domain/app is) may act on anything, a login into another app only on that
     * same app. The super-admin subject may act from any login.
     */
    private boolean scopeAllows(AppIDDefault app) {
        String caller = currentSubjectGUID();
        if (caller != null && isSuperAdminSubject(caller)) {
            return true;
        }
        AppIDDefault session = loginScope();
        return isCommonScope(session) || sameScope(session, app);
    }

    /**
     * {@link #enforce} for a grant that may be scoped: the caller must hold the permission in its
     * current login, and that login's scope must be allowed to act on {@code app} ({@link #scopeAllows}).
     */
    private void enforceScoped(AppIDDefault app, String permission) {
        if (!enforcePermissions) {
            return;
        }
        enforce(permission);
        if (!scopeAllows(app)) {
            throw new AccessSecurityException("A login scoped to " + ShiroUtil.appScope(loginScope()) + " may not grant "
                    + (app == null ? "globally" : "in app " + ShiroUtil.appScope(app)), Reason.UNAUTHORIZED);
        }
    }

    /**
     * Who may revoke a role or role-group grant; no-op unless enforcement is on: the grantor
     * ({@code broker_guid}), or a holder of {@code permission:remove:role} whose login scope may act
     * on the grant's scope.
     */
    private void enforceRevokeRole(AuthzInfo stored) {
        if (!enforcePermissions) {
            return;
        }
        String caller = currentSubjectGUID();
        if (caller == null) {
            throw new AccessSecurityException("Authentication required for " + SecurityModel.PERM_REMOVE_ROLE, Reason.UNAUTHORIZED);
        }
        if (caller.equals(stored.getBrokerGUID())) {
            return;
        }
        if (holds(SecurityModel.PERM_REMOVE_ROLE) && scopeAllows(stored.getAppID())) {
            return;
        }
        throw new AccessSecurityException("Not permitted to revoke this grant: " + SecurityModel.PERM_REMOVE_ROLE, Reason.UNAUTHORIZED);
    }

    /**
     * The standardized resource check (user decision 2026-09-29), same two tokens as
     * {@code ShiroUtil.checkResourcePermission} but against this manager's bound subject: the caller
     * holds {@code resource:<owner guid>:<caller>:<verb>} (the owner, through its synthesized self
     * permission) or {@code resource:<resource guid>:<caller>:<verb>} (a grantee). Ownership is never
     * an equality test. Never throws.
     */
    private static boolean holdsResource(NVEntity resource, String verb) {
        Subject subject = boundSubject();
        if (subject == null || !subject.isAuthenticated() || resource == null || resource.getGUID() == null) {
            return false;
        }
        String caller = DSAuthorizingRealm.subjectGUIDOf(subject.getPrincipals());
        if (caller == null) {
            return false;
        }
        if (ownsResource(resource, verb)) {
            return true;
        }
        return ShiroUtil.isPermitted(subject, SecurityModel.toResourceToken(resource.getGUID(), caller, verb));
    }

    /**
     * The owner half of {@link #holdsResource}: the bound subject holds {@code verb} through the
     * resource's owner token {@code resource:<owner>:<caller>:<verb>} (the self permission when the
     * caller is the owner, or a wildcard holder). A grantee's share never satisfies it. Never throws.
     */
    private static boolean ownsResource(NVEntity resource, String verb) {
        Subject subject = boundSubject();
        if (subject == null || !subject.isAuthenticated() || resource == null || resource.getSubjectGUID() == null) {
            return false;
        }
        String caller = DSAuthorizingRealm.subjectGUIDOf(subject.getPrincipals());
        return caller != null
                && ShiroUtil.isPermitted(subject, SecurityModel.toResourceToken(resource.getSubjectGUID(), caller, verb));
    }

    /** The verbs of a stored {@code resource:<verbs>} token (normalized by the filter), empty for null. */
    private static Set<String> verbsOf(String resourceToken) {
        Set<String> ret = new LinkedHashSet<>();
        if (SUS.isEmpty(resourceToken)) {
            return ret;
        }
        String[] parts = resourceToken.split(SecurityModel.PART_SEP, -1);
        if (parts.length == 2) {
            for (String verb : parts[1].split(SecurityModel.SUBPART_SEP, -1)) {
                if (!verb.trim().isEmpty()) {
                    ret.add(verb.trim());
                }
            }
        }
        return ret;
    }

    /**
     * Sharing rule (user decision 2026-10-06): a sharer who is not the owner may hand out only
     * {@code read} or {@code read,share}; {@code update} and {@code delete} come from the owner
     * alone. No-op unless enforcement is on; called after {@link #enforceGrantOnResource}, so the
     * caller is known to hold {@code share} on the resource.
     */
    private void enforceSharerVerbs(NVEntity resource, String inlinedToken) {
        if (!enforcePermissions || ownsResource(resource, SecurityModel.SHARE)) {
            return;
        }
        Set<String> verbs = verbsOf(inlinedToken);
        verbs.remove(SecurityModel.READ);
        verbs.remove(SecurityModel.SHARE);
        if (!verbs.isEmpty()) {
            throw new AccessSecurityException("Not permitted to share " + resource.getGUID() + " with " + verbs
                    + ": a sharer who is not the owner may give only " + SecurityModel.READ + " or "
                    + SecurityModel.READ + SecurityModel.SUBPART_SEP + SecurityModel.SHARE, Reason.UNAUTHORIZED);
        }
    }

    /**
     * Who may change a share (user decision 2026-10-06): the owner only, through the owner token;
     * a grantee's {@code share} does not qualify. No-op unless enforcement is on.
     */
    private void enforceOwnerChange(NVEntity resource) {
        if (!enforcePermissions) {
            return;
        }
        if (currentSubjectGUID() == null) {
            throw new AccessSecurityException("Authentication required to change a share on " + resource.getGUID(), Reason.UNAUTHORIZED);
        }
        if (!ownsResource(resource, SecurityModel.SHARE)) {
            throw new AccessSecurityException("Not permitted to change a share on " + resource.getGUID()
                    + " (owner only)", Reason.UNAUTHORIZED);
        }
    }

    /**
     * Share rule for granting on a resource; no-op unless enforcement is on. The caller must hold
     * {@code share} on the resource ({@link #holdsResource}: the owner via its self permission, or
     * a grantee whose share carries {@code share}). A catalog grant scoped to the resource is also
     * allowed to a holder of the global assign permission.
     */
    private void enforceGrantOnResource(NVEntity resource, boolean inlined) {
        if (!enforcePermissions) {
            return;
        }
        String caller = currentSubjectGUID();
        if (caller == null) {
            throw new AccessSecurityException("Authentication required to grant on " + resource.getGUID(), Reason.UNAUTHORIZED);
        }
        if (holdsResource(resource, SecurityModel.SHARE)) {
            return;
        }
        if (inlined) {
            throw new AccessSecurityException("Not permitted to share " + resource.getGUID()
                    + " (needs " + SecurityModel.SHARE + " on the resource)", Reason.UNAUTHORIZED);
        }
        enforce(SecurityModel.PERM_ASSIGN_PERMISSION);
    }

    /**
     * Who may revoke a grant; no-op unless enforcement is on: a holder of the global remove
     * permission, the grantor ({@code broker_guid}), or a holder of {@code share} on the scoped
     * resource (the owner through its self permission).
     */
    private void enforceRevoke(PermissionGrant stored) {
        if (!enforcePermissions) {
            return;
        }
        String caller = currentSubjectGUID();
        if (caller == null) {
            throw new AccessSecurityException("Authentication required for " + SecurityModel.PERM_REMOVE_PERMISSION, Reason.UNAUTHORIZED);
        }
        if (caller.equals(stored.getBrokerGUID())
                || (holds(SecurityModel.PERM_REMOVE_PERMISSION) && scopeAllows(stored.getAppID()))) {
            return;
        }
        if (stored.getResourceMap() != null) {
            NVEntity resource;
            try {
                resource = loadResource(stored.getResourceMap());
            } catch (IllegalArgumentException e) {
                resource = null;
            }
            if (holdsResource(resource, SecurityModel.SHARE)) {
                return;
            }
        }
        throw new AccessSecurityException("Not permitted to revoke grant " + stored.getGUID(), Reason.UNAUTHORIZED);
    }

    // ------------------------------------------------------------------
    // lookups by GUID (used by the realm and the flattener)
    // ------------------------------------------------------------------

    @Override
    public SubjectIdentifier lookupSubjectByGUID(String subjectGUID) {
        return SUS.isEmpty(subjectGUID) ? null : first(ds().searchByID(SubjectIdentifier.NVC_SUBJECT_IDENTIFIER, subjectGUID));
    }

    /** API key by its key ID ({@link SubjectAPIKey#getSubjectID()}, the JWT {@code sub} claim). */
    @Override
    public SubjectAPIKey lookupSubjectAPIKeyByID(String keyID) {
        return SUS.isEmpty(keyID) ? null : first(ds().search(SubjectAPIKey.NVC_SUBJECT_API_KEY, null,
                eq(SubjectAPIKey.Param.PRINCIPAL_ID.getNVConfig(), keyID)));
    }

    public PermissionInfo lookupPermissionByGUID(String guid) {
        return SUS.isEmpty(guid) ? null : first(ds().searchByID(PermissionInfo.NVC_PERMISSION_INFO, guid));
    }

    public RoleInfo lookupRoleByGUID(String guid) {
        return SUS.isEmpty(guid) ? null : first(ds().searchByID(RoleInfo.NVC_ROLE_INFO, guid));
    }

    public RoleGroupInfo lookupRoleGroupByGUID(String guid) {
        return SUS.isEmpty(guid) ? null : first(ds().searchByID(RoleGroupInfo.NVC_ROLE_GROUP_INFO, guid));
    }

    // ------------------------------------------------------------------
    // subject identifier
    // ------------------------------------------------------------------

    @Override
    public SubjectIdentifier createSubjectID(String principalID, CredentialInfo credentialInfo) {
        return createSubjectID(principalID, credentialInfo, BaseSubjectID.SubjectType.USER);
    }

    /**
     * Creates a subject of the given type (the public overloads create {@code USER}; the bootstrap
     * creates the super-admin as {@code SYSTEM}).
     */
    SubjectIdentifier createSubjectID(String principalID, CredentialInfo credentialInfo, BaseSubjectID.SubjectType type) {
        SUS.checkIfNulls("subject type can't be null", type);
        enforce(SecurityModel.PERM_ADD_SUBJECT);
        String pid = requirePrincipal(principalID);
        try {
            return inTransaction(() -> {
                if (resolvePrincipal(pid) != null) {
                    throw new AccessSecurityException("Principal ID already exists: " + pid);
                }
                SubjectIdentifier subject = new SubjectIdentifier();
                subject.setGUID(UUID7.randomUUID().toString());
                subject.setSubjectType(type);
                subject.setSubjectStatus(SecConst.SecStatus.ACTIVE);
                subject = ds().insert(subject);
                createSubjectKey(subject);

                // the principal and the credential are part of the creation: subject:create, checked
                // above, covers them (a registrar holds nothing else)
                insertPrincipal(subject, pid);
                if (credentialInfo != null) {
                    insertCredential(subject.getGUID(), credentialInfo, false);
                }
                return subject;
            });
        } catch (AccessSecurityException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new AccessSecurityException("Subject creation failed: " + e.getMessage(), e);
        }
    }

    /**
     * The root of the subject's key chain (user decisions 2026-09-29 and 2026-10-02, zoxweb-core
     * {@code META-ENCRYPTED-DATA.md} §6.1): a subject is never created without its
     * {@code EncapsulatedKey} — a fresh 32-byte key wrapped under the master key of the store's
     * {@link KeyMaker}, bound to the subject — inserted in the same transaction as the subject, so
     * the entity keys the datastore mints later (encrypted fields, files) have something to hang
     * from. A store whose {@link APIDataStore} configuration carries no key maker, or a key maker
     * without a loaded master key, fails the subject creation: there is no keyless subject.
     *
     * @throws AccessSecurityException when no key maker is configured or its master key is not loaded
     */
    private void createSubjectKey(SubjectIdentifier subject) {
        KeyMaker km = ds().getAPIConfigInfo() != null ? ds().getAPIConfigInfo().getKeyMaker() : null;
        if (km == null) {
            throw new AccessSecurityException("No KeyMaker on the store configuration: a subject can't be created without its subject key");
        }
        ds().insert(km.createSubjectIDKey(subject, km.getMasterKey()));
    }

    /** Removes the subject key and every entity key of the subject ({@code encapsulated_key.subject_guid}). */
    private void deleteSubjectKeys(String subjectGUID) {
        try {
            for (NVEntity key : ds().search(EncapsulatedKey.NVCE_ENCAPSULATED_KEY, null, eq(MetaToken.SUBJECT_GUID, subjectGUID))) {
                ds().delete(key, false);
            }
        } catch (RuntimeException e) {
            // no key table yet (store never encrypted anything): nothing to remove
            if (log.isEnabled()) log.getLogger().log(Level.FINE, "no keys to remove for " + subjectGUID + ": " + e.getMessage());
        }
    }

    @Override
    public SubjectIdentifier createSubjectID(String principalID, String password, CryptoConst.HashType hashType)
            throws AccessSecurityException {
        SUS.checkIfNulls("password and hash type can't be null", password, hashType);
        CredentialHasher<CIPassword> hasher = SecUtil.lookupCredentialHasher(hashType.getName());
        return createSubjectID(principalID, hasher.hash(password));
    }

    @Override
    public SubjectIdentifier lookupSubjectID(String principalID) {
        return lookupSubjectByGUID(resolveSubjectGUID(principalID));
    }

    @Override
    public void updateSubjectID(SubjectIdentifier update) {
        if (update != null && !SUS.isEmpty(update.getGUID())) {
            enforceSelfOr(update.getGUID(), SecurityModel.PERM_UPDATE_SUBJECT);
            ds().update(update);
            realm.evictAuthorization(update.getGUID());
        }
    }

    /**
     * Atomically removes the subject and everything keyed to it: principals, every credential
     * row in the registered collections and {@link SubjectAPIKey}, and all grants.
     */
    @Override
    public boolean deleteSubjectID(SubjectIdentifier subject) {
        if (subject == null || SUS.isEmpty(subject.getGUID())) {
            return false;
        }
        String subjectGUID = subject.getGUID();
        enforce(SecurityModel.PERM_DELETE_SUBJECT);
        boolean ret = inTransaction(() -> deleteSubjectRows(subject));
        realm.evictAuthorization(subjectGUID);
        return ret;
    }

    /** The rows of a subject, unenforced and inside the caller's transaction. */
    private boolean deleteSubjectRows(SubjectIdentifier subject) {
        String subjectGUID = subject.getGUID();
        {
            for (PrincipalIdentifier p : lookupAllPrincipalIdentifiers(subjectGUID)) {
                ds().delete(p, false);
            }
            for (Class<?> credColl : credentialClasses()) {
                List<NVEntity> credentials = ds().search(credColl.getName(), null, eq(MetaToken.SUBJECT_GUID, subjectGUID));
                for (NVEntity ci : credentials) {
                    ds().delete(ci, false);
                }
            }
            for (PermissionGrant g : getPermissionGrants(subjectGUID)) {
                deleteGrantRows(g);
            }
            for (RoleGrant g : getRoleGrants(subjectGUID)) {
                ds().delete(g, false);
            }
            for (RoleGroupGrant g : getRoleGroupGrants(subjectGUID)) {
                ds().delete(g, false);
            }
            for (PasswordResetToken t : resetTokensOf(subjectGUID)) {
                ds().delete(t, false);
            }
            deleteSubjectKeys(subjectGUID);
            return ds().delete(subject, false);
        }
    }

    // ------------------------------------------------------------------
    // credentials
    // ------------------------------------------------------------------

    @Override
    public CredentialInfo createCredential(String principalID, CredentialInfo credential) {
        String subjectGUID = resolveSubjectGUID(principalID);
        if (subjectGUID == null) {
            throw new AccessSecurityException("Unknown principal: " + principalID);
        }
        return insertCredential(subjectGUID, credential);
    }

    @Override
    public CredentialInfo createCredential(SubjectIdentifier subjectIdentifier, CredentialInfo credential) {
        SUS.checkIfNulls("subject can't be null", subjectIdentifier);
        String subjectGUID = subjectIdentifier.getGUID();
        if (SUS.isEmpty(subjectGUID)) {
            throw new AccessSecurityException("Unknown subject");
        }
        return insertCredential(subjectGUID, credential);
    }

    private CredentialInfo insertCredential(String subjectGUID, CredentialInfo credential) {
        return insertCredential(subjectGUID, credential, true);
    }

    /** @param enforced false inside the creation of the subject, whose own check already passed */
    private CredentialInfo insertCredential(String subjectGUID, CredentialInfo credential, boolean enforced) {
        if (enforced) {
            enforceSelfOr(subjectGUID, SecurityModel.PERM_UPDATE_SUBJECT);
        }
        if (!(credential instanceof NVEntity)) {
            throw new IllegalArgumentException("Credential must be an NVEntity to be persisted");
        }
        NVEntity nve = (NVEntity) credential;
        nve.setSubjectGUID(subjectGUID);
        if (credential.getCredentialStatus() == null) {
            credential.setCredentialStatus(SecConst.SecStatus.ACTIVE);
        }
        if (credential instanceof SubjectAPIKey) {
            SubjectAPIKey key = (SubjectAPIKey) credential;
            if (SUS.isEmpty(key.getSubjectID())) {
                // key ID: what a JWT's sub claim names; never left empty so every key can sign tokens
                key.setSubjectID(UUID7.randomUUID().toString());
            }
            if (key.getAppID() instanceof AppIDDefault) {
                key.setAppID(appRecord((AppIDDefault) key.getAppID())); // a scoped key references the app record, never a copy
            }
        }
        ds().insert(nve);
        return credential;
    }

    @Override
    public CredentialInfo lookupCredential(String principalID, CredentialInfo.Type type) {
        String subjectGUID = resolveSubjectGUID(principalID);
        if (subjectGUID == null) {
            return null;
        }
        CredentialInfo[] ret = lookupCredentialsBySubjectGUID(subjectGUID, type);
        return ret.length > 0 ? ret[0] : null;
    }

    /**
     * Two paths. A persisted credential (has a GUID) is updated in place after verifying that both
     * the given entity and the stored row belong to {@code subjectIdentifier}. A new
     * {@link CIPassword} (no GUID) replaces every existing password credential of the subject in
     * one transaction. Anything else is rejected.
     *
     * @throws AccessSecurityException        if the credential belongs to another subject or is unknown
     * @throws IllegalArgumentException if the credential is not a persistable entity, or a new
     *                                  non-password credential
     */
    @Override
    public void updateCredential(SubjectIdentifier subjectIdentifier, CredentialInfo update) {
        SUS.checkIfNulls("subjectIdentifier and credential info can't be null", subjectIdentifier, update);
        String subjectGUID = subjectIdentifier.getGUID();
        if (SUS.isEmpty(subjectGUID)) {
            throw new IllegalArgumentException("Subject has no GUID");
        }
        enforceSelfOr(subjectGUID, SecurityModel.PERM_UPDATE_SUBJECT);
        if (!(update instanceof NVEntity)) {
            throw new IllegalArgumentException("Credential must be an NVEntity to be persisted");
        }
        NVEntity nve = (NVEntity) update;

        if (!SUS.isEmpty(nve.getGUID())) {
            if (nve.getSubjectGUID() == null) {
                nve.setSubjectGUID(subjectGUID);
            } else if (!subjectGUID.equals(nve.getSubjectGUID())) {
                throw new AccessSecurityException("Credential does not belong to the subject");
            }
            inTransaction(() -> {
                NVEntity stored = first(ds().searchByID(nve.getClass().getName(), nve.getGUID()));
                if (stored == null) {
                    throw new AccessSecurityException("Unknown credential");
                }
                if (!subjectGUID.equals(stored.getSubjectGUID())) {
                    throw new AccessSecurityException("Credential does not belong to the subject");
                }
                ds().update(nve);
                return null;
            });
            return;
        }

        if (!(update instanceof CIPassword)) {
            throw new IllegalArgumentException("Only CIPassword replacement is supported for a new credential; got "
                    + update.getClass().getName());
        }
        CIPassword newPassword = (CIPassword) update;
        newPassword.setSubjectGUID(subjectGUID);
        if (newPassword.getCredentialStatus() == null) {
            newPassword.setCredentialStatus(SecConst.SecStatus.ACTIVE);
        }
        replacePassword(subjectGUID, newPassword);
    }

    /**
     * Deletes every PASSWORD row of the subject and inserts the new one, in one transaction.
     * Unenforced: the callers decide who may do this ({@link #updateCredential} enforces self-or-admin,
     * {@link #completePasswordReset} is authorized by the reset token).
     */
    private void replacePassword(String subjectGUID, CIPassword newPassword) {
        newPassword.setSubjectGUID(subjectGUID);
        if (newPassword.getCredentialStatus() == null) {
            newPassword.setCredentialStatus(SecConst.SecStatus.ACTIVE);
        }
        inTransaction(() -> {
            for (CredentialInfo old : lookupCredentialsBySubjectGUID(subjectGUID, CredentialInfo.Type.PASSWORD)) {
                if (old instanceof NVEntity) {
                    ds().delete((NVEntity) old, false);
                }
            }
            ds().insert(newPassword);
            return null;
        });
    }

    @Override
    public void deleteCredential(CredentialInfo credential) {
        if (credential instanceof NVEntity) {
            NVEntity nve = (NVEntity) credential;
            enforceSelfOr(nve.getSubjectGUID(), SecurityModel.PERM_UPDATE_SUBJECT);
            ds().delete(nve, false);
        }
    }

    @Override
    public CredentialInfo[] lookupAllPrincipalCredentials(String principalID) {
        return lookupCredentialsBySubjectGUID(resolveSubjectGUID(principalID), null);
    }

    @Override
    public CredentialInfo[] lookupCredentialsBySubjectGUID(String subjectGUID, CredentialInfo.Type type) {
        List<CredentialInfo> ret = new ArrayList<>();
        if (SUS.isEmpty(subjectGUID)) {
            return ret.toArray(new CredentialInfo[0]);
        }
        for (Class<?> credColl : credentialClasses()) {
            List<NVEntity> rows = ds().search(credColl.getName(), null, eq(MetaToken.SUBJECT_GUID, subjectGUID));
            for (NVEntity nve : rows) {
                if (nve instanceof CredentialInfo) {
                    CredentialInfo ci = (CredentialInfo) nve;
                    if (type == null || ci.getCredentialType() == type) {
                        ret.add(ci);
                    }
                }
            }
        }
        return ret.toArray(new CredentialInfo[0]);
    }

    // ------------------------------------------------------------------
    // principal identifier
    // ------------------------------------------------------------------

    @Override
    public PrincipalIdentifier addPrincipalID(SubjectIdentifier subject, String principalID) {
        SUS.checkIfNulls("subject can't be null", subject);
        String pid = requirePrincipal(principalID);
        enforceSelfOr(subject.getGUID(), SecurityModel.PERM_UPDATE_SUBJECT);
        return insertPrincipal(subject, pid);
    }

    /** The principal row, unenforced: {@link #addPrincipalID} and the subject creation decide who may. */
    private PrincipalIdentifier insertPrincipal(SubjectIdentifier subject, String pid) {
        PrincipalIdentifier principal = new PrincipalIdentifier(pid);
        principal.setSubjectGUID(subject.getGUID());
        principal.setStatus(SecConst.SecStatus.ACTIVE);
        try {
            return ds().insert(principal);
        } catch (RuntimeException e) {
            throw new AccessSecurityException("Principal ID already exists: " + pid, e);
        }
    }

    @Override
    public PrincipalIdentifier lookupPrincipalID(String principalID) {
        return resolvePrincipal(principalID);
    }

    /**
     * Removes one principal, never the subject's last one. Runs in a transaction that first
     * updates the owning subject row, taking a row lock so concurrent removals on the same subject
     * serialize; then counts, deletes, and re-counts.
     *
     * @return {@code true} if removed; {@code false} if {@code null}, unknown, or the last principal
     */
    @Override
    public boolean deletePrincipalID(PrincipalIdentifier principal) {
        if (principal == null || SUS.isEmpty(principal.getGUID()) || SUS.isEmpty(principal.getSubjectGUID())) {
            return false;
        }
        String subjectGUID = principal.getSubjectGUID();
        enforceSelfOr(subjectGUID, SecurityModel.PERM_UPDATE_SUBJECT);
        return inTransaction(() -> {
            SubjectIdentifier subject = lookupSubjectByGUID(subjectGUID);
            if (subject == null) {
                return false;
            }
            ds().update(subject); // row lock for the rest of the transaction
            if (countPrincipals(subjectGUID) <= 1) {
                return false;
            }
            boolean deleted = ds().delete(principal, false);
            if (deleted && countPrincipals(subjectGUID) == 0) {
                throw new AccessSecurityException("Subject would be left without a principal");
            }
            return deleted;
        });
    }

    @Override
    public PrincipalIdentifier[] lookupAllPrincipalIdentifiers(String subjectGUID) {
        if (SUS.isEmpty(subjectGUID)) {
            return new PrincipalIdentifier[0];
        }
        List<PrincipalIdentifier> list = ds().search(PrincipalIdentifier.NVC_PRINCIPAL_IDENTIFIER, null,
                eq(MetaToken.SUBJECT_GUID, subjectGUID));
        return list.toArray(new PrincipalIdentifier[0]);
    }

    // ------------------------------------------------------------------
    // permissions
    // ------------------------------------------------------------------

    /**
     * A wildcard token is accepted only for the reserved {@code super_admin_all} global row, and
     * only while none exists.
     */
    @Override
    public PermissionInfo createPermission(PermissionInfo permission) {
        SUS.checkIfNulls("permission can't be null", permission);
        AppIDDefault app = recordOrCommon(permission.getAppID()); // the row belongs to an app: the given one, else the common app
        enforceScoped(app, SecurityModel.PERM_ADD_PERMISSION);
        permission.setAppID(app);
        if (SUS.isEmpty(permission.getBrokerGUID())) {
            permission.setBrokerGUID(currentSubjectGUID());
        }
        if (isReservedPermission(permission)) {
            if (!isReservedName(permission, SecurityModel.Permission.SUPER_ADMIN_ALL)) {
                throw new IllegalArgumentException("wildcard permission tokens are reserved for "
                        + SecurityModel.Permission.SUPER_ADMIN_ALL.getName());
            }
            if (reservedPermissionRow() != null) {
                throw new IllegalArgumentException("reserved permission already exists: "
                        + SecurityModel.Permission.SUPER_ADMIN_ALL.getName());
            }
        }
        return ds().insert(permission);
    }

    @Override
    public PermissionInfo lookupPermission(String appID, String permissionName) {
        for (PermissionInfo p : this.<PermissionInfo>byName(PermissionInfo.NVC_PERMISSION_INFO, permissionName)) {
            if (appIDMatches(p, appID)) {
                return p;
            }
        }
        return null;
    }

    @Override
    public PermissionInfo[] lookupAllPermissionsByAppID(String appID) {
        List<PermissionInfo> ret = new ArrayList<>();
        for (PermissionInfo p : getPermissions()) {
            if (appIDMatches(p, appID)) {
                ret.add(p);
            }
        }
        return ret.toArray(new PermissionInfo[0]);
    }

    /** The reserved row is immutable; no other row may acquire a wildcard token. */
    @Override
    public void updatePermission(PermissionInfo update) {
        if (update != null && !SUS.isEmpty(update.getGUID())) {
            PermissionInfo stored = lookupPermissionByGUID(update.getGUID());
            if (stored == null) {
                throw new IllegalArgumentException("unknown permission " + update.getGUID());
            }
            enforceScoped(stored.getAppID(), SecurityModel.PERM_UPDATE_PERMISSION);
            update.setAppID(stored.getAppID()); // a row never changes app
            if (isReservedPermission(stored)) {
                throw new IllegalArgumentException("the reserved permission is immutable: " + stored.getName());
            }
            if (isReservedPermission(update)) {
                throw new IllegalArgumentException("wildcard permission tokens are reserved for "
                        + SecurityModel.Permission.SUPER_ADMIN_ALL.getName());
            }
            ds().update(update);
            realm.evictAllAuthorization();
        }
    }

    @Override
    public boolean deletePermission(PermissionInfo permission) {
        if (permission == null) {
            return false;
        }
        PermissionInfo stored = SUS.isEmpty(permission.getGUID()) ? null : lookupPermissionByGUID(permission.getGUID());
        enforceScoped(stored != null ? stored.getAppID() : permission.getAppID(), SecurityModel.PERM_DELETE_PERMISSION);
        if (isReservedPermission(stored != null ? stored : permission)) {
            throw new IllegalArgumentException("the reserved permission cannot be deleted");
        }
        boolean ret = ds().delete(permission, false);
        realm.evictAllAuthorization();
        return ret;
    }

    @Override
    public PermissionInfo[] getPermissions() {
        List<PermissionInfo> list = ds().search(PermissionInfo.NVC_PERMISSION_INFO, null);
        return list.toArray(new PermissionInfo[0]);
    }

    // ------------------------------------------------------------------
    // roles
    // ------------------------------------------------------------------

    /**
     * A role embedding the reserved permission is accepted only as the reserved global
     * {@code super_admin} role, and only while none exists.
     */
    @Override
    public RoleInfo createRole(RoleInfo role) {
        SUS.checkIfNulls("role can't be null", role);
        AppIDDefault app = recordOrCommon(role.getAppID());
        enforceScoped(app, SecurityModel.PERM_ADD_ROLE);
        role.setAppID(app);
        if (SUS.isEmpty(role.getBrokerGUID())) {
            role.setBrokerGUID(currentSubjectGUID());
        }
        requireSameAppPermissions(role);
        if (isReservedRole(role)) {
            if (!isReservedName(role, SecurityModel.Role.SUPER_ADMIN)) {
                throw new IllegalArgumentException("the reserved permission may only be carried by the role "
                        + SecurityModel.Role.SUPER_ADMIN.getName());
            }
            if (reservedRoleRow() != null) {
                throw new IllegalArgumentException("reserved role already exists: " + SecurityModel.Role.SUPER_ADMIN.getName());
            }
        }
        return ds().insert(role);
    }

    @Override
    public RoleInfo lookupRole(String appID, String roleName) {
        for (RoleInfo r : this.<RoleInfo>byName(RoleInfo.NVC_ROLE_INFO, roleName)) {
            if (appIDMatches(r, appID)) {
                return r;
            }
        }
        return null;
    }

    @Override
    public RoleInfo[] lookupAllRolesByAppID(String appID) {
        List<RoleInfo> ret = new ArrayList<>();
        for (RoleInfo r : getRoles()) {
            if (appIDMatches(r, appID)) {
                ret.add(r);
            }
        }
        return ret.toArray(new RoleInfo[0]);
    }

    /** The reserved role is immutable through this call; no other role may acquire a reserved permission. */
    @Override
    public void updateRole(RoleInfo update) {
        if (update != null && !SUS.isEmpty(update.getGUID())) {
            RoleInfo stored = lookupRoleByGUID(update.getGUID());
            if (stored == null) {
                throw new IllegalArgumentException("unknown role " + update.getGUID());
            }
            enforceScoped(stored.getAppID(), SecurityModel.PERM_UPDATE_ROLE);
            update.setAppID(stored.getAppID());
            requireSameAppPermissions(update);
            if (isReservedRole(stored)) {
                throw new IllegalArgumentException("the reserved role is immutable: " + stored.getName());
            }
            if (isReservedRole(update)) {
                throw new IllegalArgumentException("the reserved permission may only be carried by the role "
                        + SecurityModel.Role.SUPER_ADMIN.getName());
            }
            updateRoleInternal(update);
        }
    }

    /** Update without the immutability check: the seeder's path for repairing built-in roles. */
    void updateRoleInternal(RoleInfo update) {
        enforceScoped(update.getAppID(), SecurityModel.PERM_UPDATE_ROLE);
        requireSameAppPermissions(update);
        ds().update(update);
        realm.evictAllAuthorization();
    }

    @Override
    public boolean deleteRole(RoleInfo role) {
        if (role == null) {
            return false;
        }
        RoleInfo stored = SUS.isEmpty(role.getGUID()) ? null : lookupRoleByGUID(role.getGUID());
        enforceScoped(stored != null ? stored.getAppID() : role.getAppID(), SecurityModel.PERM_DELETE_ROLE);
        if (isReservedRole(stored != null ? stored : role)) {
            throw new IllegalArgumentException("the reserved role cannot be deleted");
        }
        boolean ret = ds().delete(role, false);
        realm.evictAllAuthorization();
        return ret;
    }

    @Override
    public RoleInfo[] getRoles() {
        List<RoleInfo> list = ds().search(RoleInfo.NVC_ROLE_INFO, null);
        return list.toArray(new RoleInfo[0]);
    }

    // ------------------------------------------------------------------
    // role groups
    // ------------------------------------------------------------------

    /** A role group may never embed the reserved role. */
    @Override
    public RoleGroupInfo createRoleGroup(RoleGroupInfo roleGroup) {
        SUS.checkIfNulls("role group can't be null", roleGroup);
        AppIDDefault app = recordOrCommon(roleGroup.getAppID());
        enforceScoped(app, SecurityModel.PERM_ADD_ROLE);
        roleGroup.setAppID(app);
        if (SUS.isEmpty(roleGroup.getBrokerGUID())) {
            roleGroup.setBrokerGUID(currentSubjectGUID());
        }
        requireSameAppRoles(roleGroup);
        if (groupHasReservedRole(roleGroup)) {
            throw new IllegalArgumentException("a role group may not embed " + SecurityModel.Role.SUPER_ADMIN.getName());
        }
        return ds().insert(roleGroup);
    }

    @Override
    public RoleGroupInfo lookupRoleGroup(String appID, String roleGroupName) {
        for (RoleGroupInfo g : this.<RoleGroupInfo>byName(RoleGroupInfo.NVC_ROLE_GROUP_INFO, roleGroupName)) {
            if (appIDMatches(g, appID)) {
                return g;
            }
        }
        return null;
    }

    @Override
    public RoleGroupInfo[] lookupAllRoleGroupsByAppID(String appID) {
        List<RoleGroupInfo> ret = new ArrayList<>();
        for (RoleGroupInfo g : getRoleGroups()) {
            if (appIDMatches(g, appID)) {
                ret.add(g);
            }
        }
        return ret.toArray(new RoleGroupInfo[0]);
    }

    @Override
    public void updateRoleGroup(RoleGroupInfo update) {
        if (update != null && !SUS.isEmpty(update.getGUID())) {
            RoleGroupInfo stored = lookupRoleGroupByGUID(update.getGUID());
            if (stored == null) {
                throw new IllegalArgumentException("unknown role group " + update.getGUID());
            }
            enforceScoped(stored.getAppID(), SecurityModel.PERM_UPDATE_ROLE);
            update.setAppID(stored.getAppID());
            requireSameAppRoles(update);
            if (groupHasReservedRole(update)) {
                throw new IllegalArgumentException("a role group may not embed " + SecurityModel.Role.SUPER_ADMIN.getName());
            }
            ds().update(update);
            realm.evictAllAuthorization();
        }
    }

    @Override
    public boolean deleteRoleGroup(RoleGroupInfo roleGroup) {
        if (roleGroup == null) {
            return false;
        }
        RoleGroupInfo stored = SUS.isEmpty(roleGroup.getGUID()) ? null : lookupRoleGroupByGUID(roleGroup.getGUID());
        enforceScoped(stored != null ? stored.getAppID() : roleGroup.getAppID(), SecurityModel.PERM_DELETE_ROLE);
        boolean ret = ds().delete(roleGroup, false);
        realm.evictAllAuthorization();
        return ret;
    }

    @Override
    public RoleGroupInfo[] getRoleGroups() {
        List<RoleGroupInfo> list = ds().search(RoleGroupInfo.NVC_ROLE_GROUP_INFO, null);
        return list.toArray(new RoleGroupInfo[0]);
    }

    // ------------------------------------------------------------------
    // grants
    // ------------------------------------------------------------------

    /**
     * Global catalog grant: requires the global assign permission under enforcement. The reserved
     * wildcard permission may only be granted to the super-admin subject.
     */
    @Override
    public PermissionGrant addPermissionGrant(SubjectIdentifier subject, PermissionInfo permissionInfo) {
        SUS.checkIfNulls("subject and permission can't be null", subject, permissionInfo);
        PermissionGrant grant = new PermissionGrant(permissionInfo.getGUID());
        grant.setSubjectGUID(subject.getGUID());
        grant.validateShape();
        enforce(SecurityModel.PERM_ASSIGN_PERMISSION);
        PermissionInfo stored = SUS.isEmpty(permissionInfo.getGUID()) ? null : lookupPermissionByGUID(permissionInfo.getGUID());
        requireGrantableIn(stored != null ? stored : permissionInfo, null); // no app = the common app's own rows only
        if (isReservedPermission(stored != null ? stored : permissionInfo)) {
            enforceReservedGrantee(subject.getGUID(), "the wildcard permission");
        }
        return insertGrant(grant);
    }

    /**
     * Catalog grant scoped to an app: it applies only to a login made with that domain and app
     * (plain token, see {@link GrantFlattener}). Under enforcement the caller must hold the assign
     * permission in a login whose scope is global or that same app; the caller is recorded as
     * {@code broker_guid}. The reserved wildcard permission is never scoped.
     */
    public PermissionGrant addPermissionGrant(SubjectIdentifier subject, PermissionInfo permissionInfo, AppIDDefault app) {
        SUS.checkIfNulls("subject, permission and app can't be null", subject, permissionInfo, app);
        AppIDDefault scope = appRecord(app);
        PermissionGrant grant = new PermissionGrant(permissionInfo.getGUID());
        grant.setSubjectGUID(subject.getGUID());
        grant.setAppID(scope);
        grant.validateShape();
        enforceScoped(scope, SecurityModel.PERM_ASSIGN_PERMISSION);
        PermissionInfo stored = SUS.isEmpty(permissionInfo.getGUID()) ? null : lookupPermissionByGUID(permissionInfo.getGUID());
        if (isReservedPermission(stored != null ? stored : permissionInfo)) {
            throw new AccessSecurityException("The wildcard permission is never app-scoped", Reason.UNAUTHORIZED);
        }
        requireGrantableIn(stored != null ? stored : permissionInfo, scope);
        return insertGrant(grant);
    }

    /**
     * Catalog grant scoped to one resource: the permission token must be {@code <namespace>:<verbs>}
     * (flattened to {@code resource:<resource guid>:<grantee guid>:<verbs>}), the resource must exist, and under
     * enforcement the caller must own it, hold {@code share} on it (resource:<guid>:<caller>:share), or hold the global
     * assign permission.
     */
    @Override
    public PermissionGrant addPermissionGrant(SubjectIdentifier subject, PermissionInfo permissionInfo, ResourceMap resource) {
        SUS.checkIfNulls("subject, permission and resource can't be null", subject, permissionInfo, resource);
        PermissionGrant grant = new PermissionGrant(permissionInfo.getGUID(), resource);
        grant.setSubjectGUID(subject.getGUID());
        grant.validateShape();
        checkCatalogTokenForScope(permissionInfo.getGUID());
        NVEntity res = loadResource(resource);
        enforceGrantOnResource(res, false);
        return insertGrant(grant);
    }

    /**
     * Inlined grant, the form of a share: {@code resource:<verbs>} with read, update, share and
     * delete only, always scoped; the resource must exist and, under enforcement, the caller must hold {@code share} on it.
     */
    @Override
    public PermissionGrant addPermissionGrant(SubjectIdentifier subject, ResourceMap resource, String permissionToken) {
        SUS.checkIfNulls("subject and resource can't be null", subject, resource);
        if (SUS.isEmpty(permissionToken)) {
            throw new IllegalArgumentException("permission token required for an inlined grant");
        }
        PermissionGrant grant = new PermissionGrant(resource, permissionToken);
        grant.setSubjectGUID(subject.getGUID());
        grant.validateShape();
        NVEntity res = loadResource(resource);
        enforceGrantOnResource(res, true);
        enforceSharerVerbs(res, grant.getPermissionToken());
        return inTransaction(() -> {
            PermissionGrant existing = inlinedShareOf(subject.getGUID(), res.getGUID());
            if (existing != null) {
                throw new IllegalArgumentException("Subject " + subject.getGUID() + " already holds share " + existing.getGUID()
                        + " (" + existing.getPermissionToken() + ") on " + res.getGUID()
                        + ": one share per grantee per resource; the owner changes it with updatePermissionGrant");
            }
            return insertGrant(grant);
        });
    }

    /**
     * Changes an inlined share in place (user decision 2026-10-06): the grant keeps its GUID,
     * grantee, resource and grantor; only {@code permission_token} changes. Owner only under
     * enforcement. When the new token drops {@code share}, the shares the grantee issued on the
     * resource are revoked recursively in the same transaction. Catalog-scoped grants are not
     * shares and are refused. No key row is touched.
     */
    @Override
    public PermissionGrant updatePermissionGrant(PermissionGrant permissionGrant, String permissionToken) {
        SUS.checkIfNulls("grant can't be null", permissionGrant);
        if (SUS.isEmpty(permissionGrant.getGUID())) {
            throw new IllegalArgumentException("grant GUID required");
        }
        if (SUS.isEmpty(permissionToken)) {
            throw new IllegalArgumentException("permission token required for an inlined grant");
        }
        PermissionGrant stored = first(ds().searchByID(PermissionGrant.NVC_PERMISSION_GRANT, permissionGrant.getGUID()));
        if (stored == null) {
            throw new IllegalArgumentException("Unknown grant " + permissionGrant.getGUID());
        }
        if (SUS.isEmpty(stored.getPermissionToken()) || stored.getResourceMap() == null) {
            throw new IllegalArgumentException("Grant " + stored.getGUID() + " is not an inlined share; only a share can be changed in place");
        }
        String token = SecurityModel.ResourcePermissionTokenFilter.SINGLETON.validate(permissionToken);
        NVEntity res = loadResource(stored.getResourceMap());
        enforceOwnerChange(res);
        boolean dropsShare = verbsOf(stored.getPermissionToken()).contains(SecurityModel.SHARE)
                && !verbsOf(token).contains(SecurityModel.SHARE);
        stored.setPermissionToken(token);
        Set<String> evicted = new LinkedHashSet<>();
        PermissionGrant ret = inTransaction(() -> {
            PermissionGrant updated = ds().update(stored);
            if (dropsShare) {
                revokeIssuedShares(res.getGUID(), stored.getSubjectGUID(), evicted, new HashSet<>());
            }
            return updated;
        });
        evicted.add(stored.getSubjectGUID());
        for (String guid : evicted) {
            realm.evictAuthorization(guid);
        }
        return ret;
    }

    /**
     * Revokes a grant together with its embedded resource map. The grant is reloaded by GUID so a
     * caller-supplied shell still cascades to the stored map; a grant that no longer exists yields false.
     */
    @Override
    public boolean deletePermissionGrant(PermissionGrant permissionGrant) {
        if (permissionGrant == null || SUS.isEmpty(permissionGrant.getGUID())) {
            return false;
        }
        PermissionGrant stored = first(ds().searchByID(PermissionGrant.NVC_PERMISSION_GRANT, permissionGrant.getGUID()));
        if (stored == null) {
            return false;
        }
        enforceRevoke(stored);
        if (SUS.isEmpty(stored.getPermissionToken()) || stored.getResourceMap() == null) {
            return deleteGrantAndMap(stored);
        }
        // an inlined share: revoking it revokes what the grantee handed out on the resource (user decision 2026-10-06)
        Set<String> evicted = new LinkedHashSet<>();
        String resourceGUID = stored.getResourceMap().getResourceGUID();
        boolean ret = inTransaction(() -> {
            boolean deleted = deleteGrantRows(stored);
            revokeIssuedShares(resourceGUID, stored.getSubjectGUID(), evicted, new HashSet<>());
            return deleted;
        });
        evicted.add(stored.getSubjectGUID());
        for (String guid : evicted) {
            realm.evictAuthorization(guid);
        }
        return ret;
    }

    /**
     * Cascade of a revoke or of a lost {@code share} (user decision 2026-10-06): every inlined share
     * on {@code resourceGUID} issued by {@code brokerGUID} is revoked, and first what its grantee
     * issued in turn. Catalog-scoped grants are left alone. Runs inside the caller's transaction;
     * the grantees are collected in {@code evicted} for the caller to evict after the commit.
     * {@code visited} guards against cycles in pre-rule data.
     */
    private void revokeIssuedShares(String resourceGUID, String brokerGUID, Set<String> evicted, Set<String> visited) {
        if (SUS.isEmpty(resourceGUID) || SUS.isEmpty(brokerGUID) || !visited.add(brokerGUID)) {
            return;
        }
        for (PermissionGrant g : getPermissionGrantsByResource(resourceGUID)) {
            if (!SUS.isEmpty(g.getPermissionToken()) && brokerGUID.equals(g.getBrokerGUID())) {
                revokeIssuedShares(resourceGUID, g.getSubjectGUID(), evicted, visited);
                deleteGrantRows(g);
                evicted.add(g.getSubjectGUID());
            }
        }
    }

    /** The inlined share {@code granteeGUID} holds on {@code resourceGUID}, or null (one per grantee per resource). */
    private PermissionGrant inlinedShareOf(String granteeGUID, String resourceGUID) {
        for (PermissionGrant g : getPermissionGrantsByResource(resourceGUID)) {
            if (!SUS.isEmpty(g.getPermissionToken()) && granteeGUID.equals(g.getSubjectGUID())) {
                return g;
            }
        }
        return null;
    }

    @Override
    public PermissionGrant[] getPermissionGrants(String subjectGUID) {
        if (SUS.isEmpty(subjectGUID)) {
            return new PermissionGrant[0];
        }
        List<PermissionGrant> list = ds().search(PermissionGrant.NVC_PERMISSION_GRANT, null,
                eq(MetaToken.SUBJECT_GUID, subjectGUID));
        return list.toArray(new PermissionGrant[0]);
    }

    /**
     * Grants scoped to one resource, whatever the grantee: resource-map rows naming the GUID first,
     * then the grants embedding one of them (the query formatter has no joins).
     */
    @Override
    public PermissionGrant[] getPermissionGrantsByResource(String resourceGUID) {
        List<String> mapGUIDs = mapGUIDsForResource(resourceGUID);
        if (mapGUIDs.isEmpty()) {
            return new PermissionGrant[0];
        }
        List<PermissionGrant> list = ds().search(PermissionGrant.NVC_PERMISSION_GRANT, null,
                new QueryMatchIn<>(PermissionGrant.Param.RESOURCE_MAP.getNVConfig().getName(), mapGUIDs));
        return list.toArray(new PermissionGrant[0]);
    }

    /** Revokes every grant scoped to the resource, each subject to {@link #enforceRevoke}; atomic. */
    @Override
    public int deletePermissionGrantsByResource(String resourceGUID) {
        PermissionGrant[] grants = getPermissionGrantsByResource(resourceGUID);
        if (grants.length == 0) {
            return 0;
        }
        return inTransaction(() -> {
            int count = 0;
            for (PermissionGrant g : grants) {
                enforceRevoke(g);
                if (deleteGrantAndMap(g)) {
                    count++;
                }
            }
            return count;
        });
    }

    /** Records the grantor, writes map row + grant row atomically, evicts the grantee. */
    private PermissionGrant insertGrant(PermissionGrant grant) {
        grant.setBrokerGUID(currentSubjectGUID());
        PermissionGrant ret = inTransaction(() -> ds().insert(grant));
        realm.evictAuthorization(grant.getSubjectGUID());
        return ret;
    }

    /** Deletes the grant and its map row atomically, then evicts the grantee. */
    private boolean deleteGrantAndMap(PermissionGrant stored) {
        boolean ret = inTransaction(() -> deleteGrantRows(stored));
        realm.evictAuthorization(stored.getSubjectGUID());
        return ret;
    }

    /** Grant row first (it references the map), then the map row if the grant embeds one. */
    private boolean deleteGrantRows(PermissionGrant grant) {
        boolean ret = ds().delete(grant, false);
        ResourceMap map = grant.getResourceMap();
        if (map != null && !SUS.isEmpty(map.getGUID())) {
            ds().delete(map, false);
        }
        return ret;
    }

    /**
     * Loads the entity a resource map names, by class name and GUID.
     *
     * @throws IllegalArgumentException if the map is incomplete, the class is unknown, or no row matches
     */
    private NVEntity loadResource(ResourceMap resource) {
        SUS.checkIfNulls("resource map null", resource);
        String type = resource.getResourceType();
        String guid = resource.getResourceGUID();
        if (SUS.isEmpty(type) || SUS.isEmpty(guid)) {
            throw new IllegalArgumentException("resource_map requires both resource_type and resource_guid");
        }
        NVEntity ret;
        try {
            ret = first(ds().searchByID(type, guid));
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("Unknown resource type " + type, e);
        }
        if (ret == null) {
            throw new IllegalArgumentException("Resource not found " + type + ":" + guid);
        }
        return ret;
    }

    /**
     * A catalog permission used with a resource must exist and its token must be the stored resource
     * form {@code resource:<verbs>} ({@link SecurityModel.ResourcePermissionTokenFilter}), the only
     * shape the flattener can compose into {@code resource:<resource guid>:<grantee guid>:<verbs>}.
     */
    private void checkCatalogTokenForScope(String permissionGUID) {
        PermissionInfo permission = lookupPermissionByGUID(permissionGUID);
        if (permission == null) {
            throw new IllegalArgumentException("Unknown permission " + permissionGUID);
        }
        String token = permission.getPermissionToken();
        if (!SecurityModel.isInstanceScopable(token)) {
            throw new IllegalArgumentException("permission token cannot be scoped to a resource: " + token);
        }
        try {
            SecurityModel.ResourcePermissionTokenFilter.SINGLETON.validate(token);
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("permission token cannot be scoped to a resource (must be "
                    + SecurityModel.RESOURCE + ":<verbs>): " + token, e);
        }
    }

    /** GUIDs of the resource-map rows naming the given resource GUID. */
    private List<String> mapGUIDsForResource(String resourceGUID) {
        List<String> ret = new ArrayList<>();
        if (SUS.isEmpty(resourceGUID)) {
            return ret;
        }
        List<ResourceMap> maps = ds().search(ResourceMap.NVC_RESOURCE_MAP, null,
                eq(MetaToken.RESOURCE_GUID, resourceGUID));
        for (ResourceMap m : maps) {
            if (!SUS.isEmpty(m.getGUID())) {
                ret.add(m.getGUID());
            }
        }
        return ret;
    }

    /** The reserved {@code super_admin} role may only be granted to the super-admin subject. */
    @Override
    public RoleGrant addRoleGrant(SubjectIdentifier subject, RoleInfo roleInfo) {
        return addRoleGrant(subject, roleInfo, (AppIDDefault) null);
    }

    /**
     * Role grant scoped to an app, the unit of "assigning a subject to an app": the role's name
     * and permissions apply only to a login made with that domain and app. Under enforcement the
     * caller must hold {@code permission:assign:role} in a login whose scope is global or that same
     * app (an app login never grants globally or into another app); the caller is recorded as
     * {@code broker_guid} and may later revoke what it granted. {@code super_admin} is never scoped.
     * Passing a null app is the global grant.
     */
    public RoleGrant addRoleGrant(SubjectIdentifier subject, RoleInfo roleInfo, AppIDDefault app) {
        SUS.checkIfNulls("subject and role can't be null", subject, roleInfo);
        AppIDDefault scope = app != null ? appRecord(app) : null;
        enforceScoped(scope, SecurityModel.PERM_ASSIGN_ROLE);
        RoleInfo stored = SUS.isEmpty(roleInfo.getGUID()) ? null : lookupRoleByGUID(roleInfo.getGUID());
        if (isReservedRole(stored != null ? stored : roleInfo)) {
            if (scope != null) {
                throw new AccessSecurityException("The " + SecurityModel.Role.SUPER_ADMIN.getName() + " role is never app-scoped", Reason.UNAUTHORIZED);
            }
            enforceReservedGrantee(subject.getGUID(), "the " + SecurityModel.Role.SUPER_ADMIN.getName() + " role");
        }
        requireGrantableIn(stored != null ? stored : roleInfo, scope);
        return insertRoleGrant(subject, roleInfo, scope);
    }

    /** Writes a role grant with the caller as grantor and evicts the grantee; unenforced, the callers decide who may. */
    private RoleGrant insertRoleGrant(SubjectIdentifier subject, RoleInfo roleInfo, AppIDDefault scope) {
        RoleGrant grant = new RoleGrant(roleInfo.getGUID());
        grant.setSubjectGUID(subject.getGUID());
        grant.setAppID(scope);
        grant.setBrokerGUID(currentSubjectGUID());
        RoleGrant ret = ds().insert(grant);
        realm.evictAuthorization(subject.getGUID());
        return ret;
    }

    /**
     * Revokes a role grant. The row is reloaded by GUID; under enforcement the caller must be its
     * {@code broker_guid}, or hold {@code permission:remove:role} in a login whose scope may act on
     * the grant's scope (see {@link #scopeAllows}).
     */
    @Override
    public boolean deleteRoleGrant(RoleGrant roleGrant) {
        if (roleGrant == null || SUS.isEmpty(roleGrant.getGUID())) {
            return false;
        }
        RoleGrant stored = first(ds().searchByID(RoleGrant.NVC_ROLE_GRANT, roleGrant.getGUID()));
        if (stored == null) {
            return false;
        }
        enforceRevokeRole(stored);
        boolean ret = ds().delete(stored, false);
        realm.evictAuthorization(stored.getSubjectGUID());
        return ret;
    }

    /** The subject's role grants scoped to {@code app} (never the global ones). */
    public RoleGrant[] getRoleGrants(String subjectGUID, AppIDDefault app) {
        List<RoleGrant> ret = new ArrayList<>();
        for (RoleGrant g : getRoleGrants(subjectGUID)) {
            if (sameApp(g, app)) {
                ret.add(g);
            }
        }
        return ret.toArray(new RoleGrant[0]);
    }

    /**
     * Removes the subject from an app: deletes every role, role-group and permission grant of the
     * subject scoped to {@code app}, each under the revoke rules of its kind, in one transaction.
     *
     * @return the number of grants deleted
     */
    public int revokeAppGrants(String subjectGUID, AppIDDefault app) {
        SUS.checkIfNulls("subject GUID and app can't be null", subjectGUID, app);
        requireApp(app); // a label is enough here: an app that was never created simply has no grants
        List<RoleGrant> roles = new ArrayList<>();
        for (RoleGrant g : getRoleGrants(subjectGUID)) {
            if (sameApp(g, app)) roles.add(g);
        }
        List<RoleGroupGrant> groups = new ArrayList<>();
        for (RoleGroupGrant g : getRoleGroupGrants(subjectGUID)) {
            if (sameApp(g, app)) groups.add(g);
        }
        List<PermissionGrant> permissions = new ArrayList<>();
        for (PermissionGrant g : getPermissionGrants(subjectGUID)) {
            if (sameApp(g, app)) permissions.add(g);
        }
        for (RoleGrant g : roles) enforceRevokeRole(g);
        for (RoleGroupGrant g : groups) enforceRevokeRole(g);
        for (PermissionGrant g : permissions) enforceRevoke(g);
        int count = inTransaction(() -> {
            int n = 0;
            for (RoleGrant g : roles) if (ds().delete(g, false)) n++;
            for (RoleGroupGrant g : groups) if (ds().delete(g, false)) n++;
            for (PermissionGrant g : permissions) if (deleteGrantRows(g)) n++;
            return n;
        });
        realm.evictAuthorization(subjectGUID);
        return count;
    }

    @Override
    public RoleGrant[] getRoleGrants(String subjectGUID) {
        if (SUS.isEmpty(subjectGUID)) {
            return new RoleGrant[0];
        }
        List<RoleGrant> list = ds().search(RoleGrant.NVC_ROLE_GRANT, null,
                eq(MetaToken.SUBJECT_GUID, subjectGUID));
        return list.toArray(new RoleGrant[0]);
    }

    /** A group that (illegitimately) embeds the reserved role may only be granted to the super-admin subject. */
    @Override
    public RoleGroupGrant addRoleGroupGrant(SubjectIdentifier subject, RoleGroupInfo roleGroupInfo) {
        return addRoleGroupGrant(subject, roleGroupInfo, (AppIDDefault) null);
    }

    /** Role-group grant scoped to an app; same rules as {@link #addRoleGrant(SubjectIdentifier, RoleInfo, AppIDDefault)}. */
    public RoleGroupGrant addRoleGroupGrant(SubjectIdentifier subject, RoleGroupInfo roleGroupInfo, AppIDDefault app) {
        SUS.checkIfNulls("subject and role group can't be null", subject, roleGroupInfo);
        AppIDDefault scope = app != null ? appRecord(app) : null;
        enforceScoped(scope, SecurityModel.PERM_ASSIGN_ROLE);
        RoleGroupInfo stored = SUS.isEmpty(roleGroupInfo.getGUID()) ? null : lookupRoleGroupByGUID(roleGroupInfo.getGUID());
        if (groupHasReservedRole(stored != null ? stored : roleGroupInfo)) {
            if (scope != null) {
                throw new AccessSecurityException("A role group containing " + SecurityModel.Role.SUPER_ADMIN.getName() + " is never app-scoped", Reason.UNAUTHORIZED);
            }
            enforceReservedGrantee(subject.getGUID(), "a role group containing " + SecurityModel.Role.SUPER_ADMIN.getName());
        }
        requireGrantableIn(stored != null ? stored : roleGroupInfo, scope);
        RoleGroupGrant grant = new RoleGroupGrant(roleGroupInfo.getGUID());
        grant.setSubjectGUID(subject.getGUID());
        grant.setAppID(scope);
        grant.setBrokerGUID(currentSubjectGUID());
        RoleGroupGrant ret = ds().insert(grant);
        realm.evictAuthorization(subject.getGUID());
        return ret;
    }

    /** Revokes a role-group grant; reload and revoke rules as in {@link #deleteRoleGrant}. */
    @Override
    public boolean deleteRoleGroupGrant(RoleGroupGrant roleGroupGrant) {
        if (roleGroupGrant == null || SUS.isEmpty(roleGroupGrant.getGUID())) {
            return false;
        }
        RoleGroupGrant stored = first(ds().searchByID(RoleGroupGrant.NVC_ROLE_GROUP_GRANT, roleGroupGrant.getGUID()));
        if (stored == null) {
            return false;
        }
        enforceRevokeRole(stored);
        boolean ret = ds().delete(stored, false);
        realm.evictAuthorization(stored.getSubjectGUID());
        return ret;
    }

    @Override
    public RoleGroupGrant[] getRoleGroupGrants(String subjectGUID) {
        if (SUS.isEmpty(subjectGUID)) {
            return new RoleGroupGrant[0];
        }
        List<RoleGroupGrant> list = ds().search(RoleGroupGrant.NVC_ROLE_GROUP_GRANT, null,
                eq(MetaToken.SUBJECT_GUID, subjectGUID));
        return list.toArray(new RoleGroupGrant[0]);
    }

    // ------------------------------------------------------------------
    // data store
    // ------------------------------------------------------------------

    /** Replaces the backing store; cached authorization info is dropped since it came from the old one. */
    @Override
    public DomainSecurityManager setDataStore(APIDataStore<?, ?> dataStore) {
        SUS.checkIfNulls("dataStore can't be null", dataStore);
        this.dataStore = dataStore;
        this.systemStore = systemView(dataStore);
        realm.evictAllAuthorization();
        return this;
    }

    @Override
    public APIDataStore<?, ?> getDataStore() {
        return dataStore;
    }

    @Override
    public DomainSecurityManager addCredentialType(Class<? extends CredentialInfo> clazz) {
        if (clazz != null) {
            credentialCollections.add(clazz);
        }
        return this;
    }
}
