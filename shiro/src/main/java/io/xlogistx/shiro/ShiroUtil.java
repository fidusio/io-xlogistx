/*
 * Copyright (c) 2012-2026 ZoxWeb.com LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package io.xlogistx.shiro;


import io.xlogistx.shiro.authc.DomainUsernamePasswordToken;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.ShiroException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.config.Ini;
import org.apache.shiro.env.BasicIniEnvironment;
import org.apache.shiro.env.Environment;
import org.apache.shiro.mgt.RealmSecurityManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.mgt.DefaultSessionKey;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.support.DefaultSubjectContext;
import org.apache.shiro.util.ThreadContext;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.shared.app.AppIDDefault;
import org.zoxweb.shared.http.HTTPAuthScheme;
import org.zoxweb.shared.http.HTTPAuthorization;
import org.zoxweb.shared.security.*;
import org.zoxweb.shared.security.model.SecurityModel;
import org.zoxweb.shared.util.*;
import org.zoxweb.shared.util.ExceptionReason.Reason;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.UUID;
import java.util.function.Supplier;


/**
 * Static helpers around Apache Shiro's {@link SecurityUtils} for the xlogistx security stack.
 * <p>Everything here acts on the subject bound to the calling thread unless a {@link Subject} or a
 * {@link SecurityManager} is passed explicitly. Shiro's own {@link ShiroException}s are converted to
 * {@link AccessSecurityException} so callers above the security layer never depend on Shiro types.
 * The helpers fall into these groups:
 * <ul>
 * <li>platform constants and scope labels: {@link #REALM_NAME}, {@link #COMMON_SCOPE},
 * {@link #appScope(AppIDDefault)}, {@link #scopeLabel(AppIDDefault)};</li>
 * <li>the system context: {@link #runAsSystem(Supplier)}, {@link #isSystemContext()};</li>
 * <li>login: {@link #login(AuthenticationToken)}, {@link #login(String, char[], String, String, boolean)},
 * {@link #tryLogin(String, char[], String, String)}, {@link #loginBySessionID(String)},
 * {@link #httpAuthorizationToAuthToken(HTTPAuthorization)};</li>
 * <li>the current subject and its domain principals: {@link #subject()}, {@link #subjectPrincipalID()},
 * {@link #subjectDomainID()}, {@link #subjectAppID()}, {@link #subjectJWTID()}, {@link #subjectSessionID()};</li>
 * <li>authorization: the resource access check {@link #checkResourcePermission(String, String, String)},
 * the plain permission and role checks ({@code checkPermission(s)}, {@code checkRoles}, {@code isPermitted})
 * and the annotation-driven {@link #isAuthorizedCheckPoint(ResourceSecurity)};</li>
 * <li>security manager and realms: {@link #loadSecurityManager(String)}, {@link #getRealm(Class)},
 * {@link #getAllRealms(SecurityManager, Class)}, {@link #lookupAuthorizationInfo(Class, PrincipalCollection)};</li>
 * <li>sessions: {@link #lookupSessionByID(String)}, {@link #getShiroSession(Session)},
 * {@link #getAssociatedSession(Session)}, {@link #touchSession(Session)}, {@link #toString(Session)}.</li>
 * </ul>
 * All permission and role strings are lower-cased before they reach Shiro, matching the realms, which
 * store them lower-cased.
 */
public class ShiroUtil {

    /**
     * Logger of this class; also used by the shiro module's tests to toggle security logging.
     */
    public static final LogWrapper log = new LogWrapper(ShiroUtil.class);

    private ShiroUtil() {
    }

    /**
     * Default name of the datastore-backed realm, {@code io.xlogistx.shiro.ds.DSAuthorizingRealm}.
     */
    public static final String REALM_NAME = "shiro-ds";

    /**
     * Domain of the platform's own app: the record that owns the built-in catalog.
     */
    public static final String COMMON_DOMAIN_ID = "xlogistx.com";
    /**
     * App id of the platform's own app: with the domain, {@code xlogistx.com-common}.
     */
    public static final String COMMON_APP_ID = "common";
    /**
     * Scope label of the common app, the meaning of "no domain/app" in logins, grants and catalog rows.
     */
    public static final String COMMON_SCOPE = SUS.toLowerCase(AppID.toDomainAppID(COMMON_DOMAIN_ID, COMMON_APP_ID));

    /**
     * The label of an app scope: the lower-cased {@code <domain>-<app>} canonical ID, or null for
     * no app. Used in cache keys, logs and the CLI; grants are never prefixed with it.
     */
    public static String appScope(AppIDDefault app) {
        return app == null ? null : SUS.toLowerCase(app.getDomainAppID());
    }

    /**
     * The label of a scope under the platform convention: no domain/app is the common app
     * ({@link #COMMON_SCOPE}). Used wherever a login scope, a grant scope or a catalog row's app is
     * compared.
     */
    public static String scopeLabel(AppIDDefault app) {
        return app == null ? COMMON_SCOPE : appScope(app);
    }

    /**
     * Depth of {@link #runAsSystem(Supplier)} on the calling thread; absent outside the system context.
     */
    private static final ThreadLocal<int[]> SYSTEM_DEPTH = new ThreadLocal<>();

    /**
     * Runs {@code work} in the system context of the calling thread: every resource access check
     * ({@link #checkResourcePermission(String, String, String)}) passes for its duration. For the
     * code that must reach the datastore with nobody logged in, or on behalf of every subject —
     * login, grant loading, key-chain lookups, setup. Re-entrant; the context ends with the
     * outermost call, also when {@code work} throws. Never wrap an application request in it.
     */
    public static <V> V runAsSystem(Supplier<V> work) {
        SUS.checkIfNulls("work can't be null", work);
        int[] depth = SYSTEM_DEPTH.get();
        if (depth == null) {
            depth = new int[1];
            SYSTEM_DEPTH.set(depth);
        }
        depth[0]++;
        try {
            return work.get();
        } finally {
            if (--depth[0] == 0) {
                SYSTEM_DEPTH.remove();
            }
        }
    }

    /**
     * @return true while the calling thread is inside {@link #runAsSystem(Supplier)}
     */
    public static boolean isSystemContext() {
        int[] depth = SYSTEM_DEPTH.get();
        return depth != null && depth[0] > 0;
    }

    /**
     * {@link #tryLogin(String, char[], String, String)} with the password as a {@code String}.
     *
     * @param principalID the login id (username or email)
     * @param password    the password; converted to a {@code char[]} that the login clears
     * @param domain      the domain id of the token, may be null
     * @param realm       unused, kept for signature compatibility
     * @return true when the thread's subject is authenticated afterwards
     * @throws NullPointerException if {@code password} is null
     */
    public static boolean tryLogin(String principalID, String password, String domain, String realm) {
        return tryLogin(principalID, password.toCharArray(), domain, realm);
    }

    /**
     * Best-effort password login of the thread's subject. Already authenticated: nothing is done and
     * true is returned, whoever that subject is. Otherwise a {@link DomainUsernamePasswordToken} for
     * {@code domain} and no app is submitted to {@link #login(AuthenticationToken)}; a failure is
     * printed to stderr and swallowed.
     *
     * @param principalID the login id (username or email)
     * @param password    the password; cleared by the login
     * @param domain      the domain id of the token, may be null
     * @param realm       unused, kept for signature compatibility
     * @return true when the thread's subject is authenticated afterwards, false when the login failed
     */
    public static boolean tryLogin(String principalID, char[] password, String domain, String realm) {
        Subject subject = subject();
        if (!subject.isAuthenticated()) {
            try {
                login(new DomainUsernamePasswordToken(principalID, password, false, null, domain));
                return true;
            } catch (AccessSecurityException e) {
                e.printStackTrace();
            }
        } else {
            return true;
        }

        return false;
    }


    /**
     * Authenticates the thread's subject with {@code token} through the global security manager.
     * The credentials of a {@link UsernamePasswordToken} (and so of a {@link DomainUsernamePasswordToken})
     * are cleared once the attempt is over, successful or not, so the token cannot be reused.
     *
     * @param token the authentication token
     * @return the authenticated subject bound to the calling thread
     * @throws AccessSecurityException when Shiro rejects the token (bad credentials, unknown account,
     *                                 locked account, ...) or no security manager is available
     */
    public static Subject login(AuthenticationToken token)
            throws AccessSecurityException {
        Subject subject = subject();
        try {
            subject.login(token);
        } catch (ShiroException e) {
            throw new AccessSecurityException(e);
        } finally {
            if (token instanceof UsernamePasswordToken) {
                ((UsernamePasswordToken) token).clear();
            }
        }
        return subject();
    }

    /**
     * Installs {@code securityManager} as the VM-wide static security manager that {@link #subject()}
     * and every other thread-based helper here resolve against. Call once at start-up, typically with
     * the result of {@link #loadSecurityManager(String)}.
     *
     * @param securityManager the security manager, null to clear it
     */
    public static void setSecurityManager(SecurityManager securityManager) {
        SecurityUtils.setSecurityManager(securityManager);
    }

    /**
     * @return the security manager of the calling thread, or the VM-wide one set by
     * {@link #setSecurityManager(SecurityManager)}
     * @throws org.apache.shiro.UnavailableSecurityManagerException if neither is set
     */
    public static SecurityManager getSecurityManager() {
        return SecurityUtils.getSecurityManager();
    }


    /**
     * Reads a value from Shiro's {@link ThreadContext}, the per-thread map that holds the bound
     * subject and security manager.
     *
     * @param key the key, e.g. {@link ThreadContext#SUBJECT_KEY}
     * @param <V> the expected type; the cast is unchecked
     * @return the value, or null when the key is absent
     */
    @SuppressWarnings("unchecked")
    public static <V> V getFromThreadContext(Object key) {
        return (V) ThreadContext.get(key);
    }

    /**
     * Password login scoped to a domain and an app. Already authenticated: the current subject is
     * returned as is, without checking that it is {@code principalID}. Otherwise a
     * {@link DomainUsernamePasswordToken} is built with remember-me off and submitted to
     * {@link #login(AuthenticationToken)}, which clears {@code credentials}.
     *
     * @param principalID the login id (username or email)
     * @param credentials the password
     * @param domainID    the domain id, may be null
     * @param appID       the app id, may be null; with {@code domainID} null this is the common app
     * @param autoLogin   sets {@link DomainUsernamePasswordToken#setAutoAuthenticationEnabled(boolean)}:
     *                    {@link io.xlogistx.shiro.authc.CredentialsInfoMatcher} then accepts the token
     *                    once the principal matches, without checking the password. For trusted
     *                    server-side callers only, never for a password typed by a user
     * @return the authenticated subject bound to the calling thread
     * @throws AccessSecurityException when the login is rejected
     */
    public static Subject login(String principalID, char[] credentials, String domainID, String appID, boolean autoLogin)
            throws AccessSecurityException {

        Subject currentUser = subject();
        if (!currentUser.isAuthenticated()) {
            //collect user principals and credentials in a gui specific manner
            //such as username/password html form, X509 certificate, OpenID, etc.
            //We'll use the username/password example here since it is the most common.
            DomainUsernamePasswordToken token = new DomainUsernamePasswordToken(principalID, credentials, false, null, domainID, appID);
            token.setAutoAuthenticationEnabled(autoLogin);

            //this is all you have to do to support 'remember me' (no config - built in!):
            token.setRememberMe(false);
            return login(token);
        }
        return currentUser;

    }


    /**
     * The JWT subject id of the authenticated subject, as carried by its {@link DomainPrincipalCollection}.
     *
     * @return the JWT subject id, may be null when the login did not set one
     * @throws AccessSecurityException if nobody is authenticated, or the principals are not a
     *                                 {@link DomainPrincipalCollection}
     */
    public static String subjectJWTID() {
        try {
            Subject subject = subject();

            if (subject.isAuthenticated()) {
                if (subject.getPrincipals() instanceof DomainPrincipalCollection) {
                    return ((DomainPrincipalCollection) subject.getPrincipals()).getJWSubjectID();
                }
            }

            throw new AccessSecurityException("Subject not authenticated");
        } catch (ShiroException e) {
            throw new AccessSecurityException(e.getMessage());
        }
    }

    public static String subjectGUID()
    {
        try {
            Subject subject = subject();

            if (subject.isAuthenticated()) {
                if (subject.getPrincipals() instanceof DomainPrincipalCollection) {
                    return ((DomainPrincipalCollection) subject.getPrincipals()).getSubjectGUID();
                }
            }

            throw new AccessSecurityException("Subject not authenticated");
        } catch (ShiroException e) {
            throw new AccessSecurityException(e.getMessage());
        }
    }

    /**
     * The login id of the authenticated subject: the user id of its {@link DomainPrincipalCollection},
     * or the primary principal when a plain realm (e.g. an ini realm) authenticated with a {@code String}.
     *
     * @return the principal id
     * @throws AccessSecurityException if nobody is authenticated, or the principal is of neither form
     */
    public static String subjectPrincipalID()
            throws AccessSecurityException {
        try {
            Subject subject = subject();

            if (subject.isAuthenticated()) {
                if (subject.getPrincipals() instanceof DomainPrincipalCollection) {
                    return ((DomainPrincipalCollection) subject.getPrincipals()).getPrincipalID();
                } else if (subject.getPrincipal() instanceof String) {
                    return (String) subject.getPrincipal();
                }

            }

            throw new AccessSecurityException("Subject not authenticated");
        } catch (ShiroException e) {
            throw new AccessSecurityException(e.getMessage());
        }
    }

    /**
     * {@link #getRealm(SecurityManager, Class)} on the global security manager.
     *
     * @param c   the realm type wanted; null for any realm, i.e. the first one configured
     * @param <V> the realm type the caller expects
     * @return the first matching realm, or null
     */
    public static <V extends Realm> V getRealm(Class<? extends Realm> c) {
        if (c == null)
            c = Realm.class;
        return getRealm(SecurityUtils.getSecurityManager(), c);
    }

    /**
     * The first realm of {@code sm} that is an instance of {@code c}, in the configured realm order.
     *
     * @param sm  the security manager; must be a {@link RealmSecurityManager} to hold realms
     * @param c   the realm type wanted, a class or an interface
     * @param <V> the realm type the caller expects; the cast is unchecked
     * @return the realm, or null when {@code sm} has no realms or none matches
     */
    @SuppressWarnings("unchecked")
    public static <V extends Realm> V getRealm(SecurityManager sm, Class<? extends Realm> c) {
        if (sm instanceof RealmSecurityManager) {
            Collection<Realm> realms = ((RealmSecurityManager) sm).getRealms();

            if (realms != null) {
                for (Realm realm : realms) {
                    if (c.isAssignableFrom(realm.getClass())) {
                        return (V) realm;
                    }
                }
            }
        }

        return null;
    }

//    public static RealmController<AuthorizationInfo, PrincipalCollection> getRealmController() {
//        return getRealmController(SecurityUtils.getSecurityManager());
//    }
//
//    public static RealmController<AuthorizationInfo, PrincipalCollection> getRealmController(SecurityManager sm) {
//        if (sm instanceof RealmSecurityManager) {
//            Collection<Realm> realms = ((RealmSecurityManager) sm).getRealms();
//
//            if (realms != null) {
//                for (Realm realm : realms) {
//                    if (realm instanceof RealmControllerHolder) {
//                        return ((RealmControllerHolder<AuthorizationInfo, PrincipalCollection>) realm).getRealmController();
//                    }
//                    if (realm instanceof RealmController) {
//                        return (RealmController<AuthorizationInfo, PrincipalCollection>) realm;
//                    }
//                }
//            }
//        }
//        throw new NotFoundException("No shiro realm manager found.");
//    }

    /**
     * Every realm of {@code sm} that is an instance of {@code c}, in the configured realm order.
     *
     * @param sm  the security manager; must be a {@link RealmSecurityManager} to hold realms
     * @param c   the realm type wanted, a class or an interface
     * @param <V> the realm type the caller expects; the cast is unchecked
     * @return the matching realms, empty when there are none; never null
     */
    @SuppressWarnings("unchecked")
    public static <V extends Realm> List<V> getAllRealms(SecurityManager sm, Class<? extends Realm> c) {
        List<V> ret = new ArrayList<V>();

        if (sm instanceof RealmSecurityManager) {
            Collection<Realm> realms = ((RealmSecurityManager) sm).getRealms();

            if (realms != null) {
                for (Realm realm : realms) {
                    if (c.isAssignableFrom(realm.getClass())) {
                        ret.add((V) realm);
                    }
                }
            }
        }

        return ret;
    }

    /**
     * The domain id the subject logged into, from its {@link DomainPrincipalCollection}.
     *
     * @return the domain id, may be null for a login without domain (the common app)
     * @throws AccessSecurityException if nobody is authenticated, or the principals are not a
     *                                 {@link DomainPrincipalCollection}
     */
    public static String subjectDomainID()
            throws AccessSecurityException {

        try {
            Subject subject = subject();

            if (subject.isAuthenticated()) {
                if (subject.getPrincipals() instanceof DomainPrincipalCollection) {
                    return ((DomainPrincipalCollection) subject.getPrincipals()).getDomainID();
                }
            }

            throw new AccessSecurityException("Subject not authenticated");
        } catch (ShiroException e) {
            throw new AccessSecurityException(e.getMessage());
        }
    }

    /**
     * Whether an endpoint declared with these authentication types needs an authenticated subject.
     * {@link SecConst.AuthenticationType#NONE} anywhere in the list wins: the endpoint is public.
     * Otherwise any listed type requires authentication. Null or empty means no requirement.
     *
     * @param authTypes the types, typically {@link ResourceSecurity#authenticationTypes()}
     * @return true when the caller must be authenticated
     */
    public static boolean isAuthenticationRequired(SecConst.AuthenticationType... authTypes) {
        if (SUS.genContains(SecConst.AuthenticationType.NONE, authTypes))
            return false;

        if (authTypes != null && authTypes.length > 0) {

            for (SecConst.AuthenticationType authType : authTypes) {
                switch (authType) {
                    case ALL:
                    case API_KEY:
                    case BASIC:
                    case BEARER:
                    case DIGEST:
                    case DOMAIN:
                    case JWT:
                    case LDAP:
                    case HOBA:
                    case OAUTH:
                        return true;
                }
            }
        }

        return false;
    }


    /**
     * Converts a parsed HTTP {@code Authorization} header to a Shiro token. Only
     * {@link HTTPAuthScheme#BASIC} is handled: the {@code user} and {@code password} token properties
     * become a plain {@link UsernamePasswordToken} (no domain, no app). Bearer/JWT and the other
     * schemes are resolved elsewhere and yield null here.
     *
     * @param httpAuthorization the parsed header, not null
     * @return the token, or null for a scheme other than Basic
     */
    public static AuthenticationToken httpAuthorizationToAuthToken(HTTPAuthorization httpAuthorization) {
        if (httpAuthorization.authSchemeAsEnum() == HTTPAuthScheme.BASIC) {
            return new UsernamePasswordToken(httpAuthorization.getTokenProperties().getValue("user"), (String) httpAuthorization.getTokenProperties().getValue("password"));
        }

        return null;
    }

    /**
     * The id of the authenticated subject's Shiro session, usable with {@link #lookupSessionByID(String)}
     * and {@link #loginBySessionID(String)}.
     *
     * @return the session id as a string
     * @throws AccessSecurityException if nobody is authenticated, or the session is invalid
     */
    public static String subjectSessionID()
            throws AccessSecurityException {
        try {
            Subject subject = subject();
            if (subject.isAuthenticated()) {
                return subject.getSession().getId().toString();
            }

            throw new AccessSecurityException("Subject not authenticated");
        } catch (ShiroException e) {
            throw new AccessSecurityException(e.getMessage());
        }
    }

    /**
     * The subject bound to the calling thread, created anonymous (not authenticated) and bound on
     * first use. Every thread-based helper of this class starts here.
     *
     * @return the current subject, never null
     * @throws AccessSecurityException when no security manager is available to build it
     */
    public static Subject subject()
            throws AccessSecurityException {
        try {
            return SecurityUtils.getSubject();
        } catch (ShiroException e) {
            throw new AccessSecurityException(e);
        }
    }

    /**
     * The app id the subject logged into, from its {@link DomainPrincipalCollection}.
     *
     * @return the app id, may be null for a login without app (the common app)
     * @throws AccessSecurityException if nobody is authenticated, or the principals are not a
     *                                 {@link DomainPrincipalCollection}
     */
    public static String subjectAppID()
            throws AccessSecurityException {
        try {
            Subject subject = subject();

            if (subject.isAuthenticated()) {
                if (subject.getPrincipals() instanceof DomainPrincipalCollection) {
                    return ((DomainPrincipalCollection) subject.getPrincipals()).getAppID();
                }
            }

            throw new AccessSecurityException("Subject not authenticated");
        } catch (ShiroException e) {
            throw new AccessSecurityException(e.getMessage());
        }
    }

    /**
     * Builds a security manager from a {@code shiro.ini}. The manager is only returned, not installed:
     * pass it to {@link #setSecurityManager(SecurityManager)} to make it the global one.
     *
     * @param shiroInitFile the ini location in Shiro resource syntax: {@code classpath:shiro.ini},
     *                      {@code file:/etc/app/shiro.ini}, {@code url:...}, or a plain file path
     * @return the configured security manager, with its realms, session manager and cache manager
     * @throws org.apache.shiro.config.ConfigurationException if the ini cannot be read or is invalid
     */
    public static SecurityManager loadSecurityManager(String shiroInitFile) {
        Environment env = new BasicIniEnvironment(shiroInitFile);
        SecurityManager securityManager = env.getSecurityManager();
        if (log.isEnabled()) log.getLogger().info("Class:" + securityManager.getClass());
        return securityManager;

    }

    /**
     * Same as {@link #loadSecurityManager(String)} from an already open stream of the ini text. The
     * stream is read to its end and left to the caller to close.
     *
     * @param is the ini content
     * @return the configured security manager, not installed
     * @throws org.apache.shiro.config.ConfigurationException if the ini is invalid
     */
    public static SecurityManager loadSecurityManager(InputStream is) {
        Ini ini = new Ini();
        ini.load(is);
        Environment env = new BasicIniEnvironment(ini);
        SecurityManager securityManager = env.getSecurityManager();
        if (log.isEnabled()) log.getLogger().info("Class:" + securityManager.getClass());
        return securityManager;
    }

    /**
     * The standardized resource access check (user decision 2026-09-29). Access to an NVEntity is a
     * permission, never an equality test: the bound subject {@code C} may act on the resource when it
     * holds either
     * <ol>
     * <li>the owner token {@code resource:<owner guid>:<C>:<permission>} — every subject {@code S}
     * implicitly holds {@code resource:S:S:create,read,update,delete,share} (synthesized by the
     * realm), so the owner passes here; or</li>
     * <li>the grant token {@code resource:<resource guid>:<C>:<permission>} — a share of this
     * resource to {@code C}.</li>
     * </ol>
     * Both tokens are composed by {@link SecurityModel#toResourceToken(String, String, String)}.
     *
     * @param nve        the resource; its GUID and subject GUID must be set
     * @param permission the verb, e.g. {@link SecurityModel#READ}
     * @return the owner's subject GUID ({@code nve.getSubjectGUID()}), the root of the resource's key chain
     * @throws NullPointerException    if an argument, the GUID or the subject GUID is null
     * @throws AccessSecurityException if nobody is authenticated, the subject has no GUID principal,
     *                                 or neither token is held
     */
    public static String checkResourcePermission(NVEntity nve, String permission)
            throws NullPointerException, AccessSecurityException {
        SUS.checkIfNulls("nve, its guid and subject_guid cannot be null", nve, nve.getGUID(), nve.getSubjectGUID());
        return checkResourcePermission(nve.getGUID(), nve.getSubjectGUID(), permission);
    }

    /**
     * Same as {@link #checkResourcePermission(NVEntity, String)} without loading the entity. This is
     * the check behind the datastore access control: every row read, updated or deleted through a
     * store configured with the Shiro controller ends here.
     * <p>In the system context ({@link #runAsSystem(Supplier)}) the check passes without a subject.
     * A resource without owner ({@code ownerGUID} null) has no owner token: only a grant on the
     * resource itself — or a wildcard such as {@code resource:*:*:<verb>} or {@code *} — reaches it.
     *
     * @param resourceGUID the resource GUID
     * @param ownerGUID    the resource's {@code subject_guid}, null for a resource without owner
     * @param permission   the verb
     * @return {@code ownerGUID}
     */
    public static String checkResourcePermission(String resourceGUID, String ownerGUID, String permission)
            throws NullPointerException, AccessSecurityException {
        SUS.checkIfNulls("resourceGUID and permission cannot be null", resourceGUID, permission);
        if (isSystemContext()) {
            return ownerGUID;
        }
        Subject subject = subject();
        if (!subject.isAuthenticated()) {
            throw new AccessSecurityException("Subject not authenticated");
        }
        UUID uuid = subject.getPrincipals().oneByType(UUID.class);
        if (uuid == null) throw new AccessSecurityException("Subject has no GUID principal");
        String subjectGUID = uuid.toString();

        // 1. owner rights: resource:<owner>:<subject>:<permission> (implied by the self permission)
        if (ownerGUID != null && isPermitted(subject, SecurityModel.toResourceToken(ownerGUID, subjectGUID, permission)))
            return ownerGUID;

        // 2. granted rights: resource:<resource>:<subject>:<permission>
        String granted = SecurityModel.toResourceToken(resourceGUID, subjectGUID, permission);
        if (!isPermitted(subject, granted))
            throw new AccessSecurityException("Access denied " + granted, Reason.UNAUTHORIZED);
        return ownerGUID;
    }

    /**
     * Non-throwing form of {@link #checkResourcePermission(String, String, String)}, the test behind
     * {@code ShiroSecurityController.isNVEntityAccessible}: true in the system context or when the
     * subject holds the owner token or the grant token; false when nobody is authenticated, the
     * subject has no GUID principal, neither token is held, {@code resourceGUID} or {@code permission}
     * is null, or {@code permission} is not a valid verb. Never throws.
     *
     * @param resourceGUID the resource GUID
     * @param ownerGUID    the resource's {@code subject_guid}, null for a resource without owner
     * @param permission   the verb, e.g. {@link SecurityModel#READ}
     * @return true when access is allowed
     */
    public static boolean isResourcePermitted(String resourceGUID, String ownerGUID, String permission) {
        try {
            checkResourcePermission(resourceGUID, ownerGUID, permission);
            return true;
        } catch (AccessSecurityException | NullPointerException | IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * {@link #checkPermission(Subject, String, SecTokenReplacement)} on the thread's subject.
     *
     * @param permission the permission, may contain the placeholder of {@code str}
     * @param str        the placeholder to substitute with the subject's primary principal
     * @throws NullPointerException    if an argument is null
     * @throws AccessSecurityException if the subject does not hold the permission
     */
    public static void checkPermission(String permission, SecTokenReplacement str)
            throws NullPointerException, AccessSecurityException {
        checkPermission(SecurityUtils.getSubject(), permission, str);
    }


    /**
     * Throwing form of {@link #isAuthorizedCheckPoint(ResourceSecurity)}: the gate an endpoint or a
     * method annotated with {@link ResourceSecurity} goes through before it runs.
     *
     * @param rs the declared security of the resource, null for an unrestricted one
     * @throws AccessSecurityException with {@link Reason#UNAUTHORIZED} when the current subject
     *                                 holds none of the declared permissions or roles
     */
    public static void authorizationCheckPoint(ResourceSecurity rs) {
        if (!isAuthorizedCheckPoint(rs))
            throw new AccessSecurityException("Subject not role or permission not Authorized", Reason.UNAUTHORIZED);

    }

    /**
     * Decides whether the thread's subject may use a resource declared with {@code rs}. In order:
     * <ol>
     * <li>{@code rs} null: unrestricted, true;</li>
     * <li>{@code rs.authenticationTypes()} null: malformed declaration, false;</li>
     * <li>{@link SecConst.AuthenticationType#NONE} among the types: public, true;</li>
     * <li>no permissions and no roles declared: authentication alone is enough, true;</li>
     * <li>otherwise true as soon as the subject holds <em>any one</em> declared permission
     * ({@link #isPermitted(String)}) or has <em>any one</em> declared role; false when it holds none.</li>
     * </ol>
     * The authentication itself is not verified here; {@link #isAuthenticationRequired} and the
     * login filter take care of it before this check runs. {@code rs.restrictions()} is not evaluated.
     *
     * @param rs the declared security of the resource
     * @return true when access is allowed
     */
    public static boolean isAuthorizedCheckPoint(ResourceSecurity rs) {


        if (rs != null && rs.authenticationTypes() != null) {

            if (SUS.genContains(SecConst.AuthenticationType.NONE, rs.authenticationTypes()))
                return true;

            if (rs.permissions().length == 0 && rs.roles().length == 0) {
                return true;
            }
            // check if at
            // check permission and roles
            // with the current subject
            Subject subject = subject();
            for (String perm : rs.permissions()) {
                // try to match any permission
                if (isPermitted(perm))
                    return true;
            }
            for (String role : rs.roles()) {
                // try to match any role
                if (subject.hasRole(role))
                    return true;
            }
        }

        if (rs == null)
            return true;

        return false;
    }

    /**
     * Checks one permission after substituting a subject-specific placeholder: {@code str}'s token
     * (e.g. {@code $$SUBJECT_ID$$}) in {@code permission} is replaced by the subject's primary
     * principal, the result is lower-cased and handed to {@link Subject#checkPermission(String)}.
     * Lets a static declaration such as {@code user:$$SUBJECT_ID$$:read} mean "read your own record".
     *
     * @param subject    the subject to check
     * @param permission the permission template
     * @param str        the placeholder to substitute
     * @throws NullPointerException    if an argument is null
     * @throws AccessSecurityException if the subject does not hold the resulting permission
     * @throws ClassCastException      if the subject's primary principal is not a {@code String}
     */
    public static void checkPermission(Subject subject, String permission, SecTokenReplacement str)
            throws NullPointerException, AccessSecurityException {
        SUS.checkIfNulls("Null parameters not allowed", subject, permission, str);

        permission = str.replace(permission, (String) subject.getPrincipal());
        {
            try {
                subject.checkPermission(SUS.toLowerCase(permission));
            } catch (ShiroException e) {
                throw new AccessSecurityException(e.getMessage());
            }
        }
    }

    /**
     * {@link #checkRoles(boolean, Subject, String...)} on the thread's subject, requiring all roles.
     *
     * @param roles the roles the subject must have, all of them
     * @throws NullPointerException    if {@code roles} is null
     * @throws AccessSecurityException at the first missing role
     */
    public static void checkRoles(String... roles)
            throws NullPointerException, AccessSecurityException {
        checkRoles(SecurityUtils.getSubject(), roles);
    }

    /**
     * {@link #checkRoles(boolean, Subject, String...)} requiring all roles.
     *
     * @param subject the subject to check
     * @param roles   the roles the subject must have, all of them
     * @throws NullPointerException    if an argument is null
     * @throws AccessSecurityException at the first missing role
     */
    public static void checkRoles(Subject subject, String... roles)
            throws NullPointerException, AccessSecurityException {
//		SUS.checkIfNulls("Null parameters not allowed", subject, roles);
//
//		for (String role : roles)
//		{
//			try
//            {
//				subject.checkRole(SUS.toLowerCase(role));
//			}
//			catch (ShiroException e)
//            {
//			    throw new AccessSecurityException( e.getMessage());
//			}
//		}

        checkRoles(false, subject, roles);
    }

//    public static <V> V invokeMethod(boolean strict, Object bean, Method method, Object... parameters)
//            throws InvocationTargetException, IllegalAccessSecurityException {
//        authorizationCheckPoint(SecUtil.SINGLETON.lookupCachedResourceSecurity(method));
//        return (V)ReflectionUtil.invokeMethod(strict, bean, method, parameters);
//    }


    /**
     * Checks roles, lower-cased, against {@link Subject#checkRole(String)}.
     * <ul>
     * <li>{@code partial} false: every role is required; the first missing one throws.</li>
     * <li>{@code partial} true: at least one role is required; it throws only when all are missing.</li>
     * </ul>
     * An empty {@code roles} array throws in both modes ("All roles failed"), so callers must not
     * pass an empty list to mean "no requirement".
     *
     * @param partial true for "any of", false for "all of"
     * @param subject the subject to check
     * @param roles   the role names
     * @throws NullPointerException    if {@code subject} or {@code roles} is null
     * @throws AccessSecurityException when the requirement is not met
     */
    public static void checkRoles(boolean partial, Subject subject, String... roles)
            throws NullPointerException, AccessSecurityException {
        SUS.checkIfNulls("Null parameters not allowed", subject, roles);
        int failureCount = 0;
        for (String role : roles) {
            try {
                subject.checkRole(SUS.toLowerCase(role));
            } catch (ShiroException e) {
                failureCount++;
                if (!partial)
                    throw new AccessSecurityException(e.getMessage());
            }
        }

        if (failureCount == roles.length) {
            throw new AccessSecurityException("All roles failed");
        }
    }

    /**
     * The {@link ShiroSession} wrapper a login stored in this Shiro session under
     * {@link ShiroSession#SHIRO_SESSION}.
     *
     * @param session the Shiro session, may be null
     * @param <V>     the type of the associated (application) session carried by the wrapper
     * @return the wrapper, or null when {@code session} is null or holds none
     */
    @SuppressWarnings("unchecked")
    public static <V> ShiroSession<V> getShiroSession(Session session) {
        if (session != null)
            return (ShiroSession<V>) session.getAttribute(ShiroSession.SHIRO_SESSION);

        return null;
    }

    /**
     * Whether two session handles denote the same Shiro session, compared by id. Shiro hands out a
     * fresh {@link Session} object per lookup, so identity is not a usable test.
     *
     * @param session1 a session, may be null
     * @param session2 a session, may be null
     * @return true when both are non-null and have equal ids
     */
    public static boolean areSessionsEquals(Session session1, Session session2) {
        if (session1 == null || session2 == null)
            return false;
        return session1.getId().equals(session2.getId());
    }

    /**
     * Resolves a session by id through the global security manager, e.g. from a session cookie or a
     * WebSocket handshake.
     *
     * @param id the session id
     * @return the live session
     * @throws AccessSecurityException when the id is unknown, or the session expired or was stopped
     */
    public static Session lookupSessionByID(String id)
            throws AccessSecurityException {
        try {
            return SecurityUtils.getSecurityManager().getSession(new DefaultSessionKey(id));

        } catch (ShiroException e) {
            throw new AccessSecurityException(e.getMessage());
        }
    }

    /**
     * The application-level session (HTTP session, WebSocket session, ...) a login attached to this
     * Shiro session under {@link ShiroSession#ASSOCIATED_SESSION}. The Shiro session is touched first,
     * so reading the association counts as activity against its idle timeout.
     *
     * @param session the Shiro session, may be null
     * @param <V>     the associated session type; the cast is unchecked
     * @return the associated session, or null when {@code session} is null or holds none
     */
    @SuppressWarnings("unchecked")
    public static <V> V getAssociatedSession(Session session) {
        if (session != null) {
            touchSession(session);
            return (V) session.getAttribute(ShiroSession.ASSOCIATED_SESSION);
        }

        return null;
    }

    /**
     * Resets the idle timeout of a session ({@link Session#touch()}), swallowing any failure such as
     * an expired or stopped session.
     *
     * @param session the session, may be null
     * @return true when the session was touched, false when it is null or could not be touched
     */
    public static boolean touchSession(Session session) {
        if (session != null)
            try {
                session.touch();
                return true;
            } catch (Exception e) {
            }

        return false;
    }


    /**
     * {@link #checkPermissions(boolean, Subject, String...)} on the thread's subject, requiring all
     * permissions.
     *
     * @param permissions the permissions the subject must hold, all of them
     * @throws NullPointerException    if {@code permissions} is null
     * @throws AccessSecurityException at the first missing permission
     */
    public static void checkPermissions(String... permissions)
            throws NullPointerException, AccessSecurityException {
        checkPermissions(SecurityUtils.getSubject(), permissions);
    }

    /**
     * {@link #checkPermissions(boolean, Subject, String...)} requiring all permissions.
     *
     * @param subject     the subject to check
     * @param permissions the permissions the subject must hold, all of them
     * @throws NullPointerException    if an argument is null
     * @throws AccessSecurityException at the first missing permission
     */
    public static void checkPermissions(Subject subject, String... permissions)
            throws NullPointerException, AccessSecurityException {
//		SUS.checkIfNulls("Null parameters not allowed", subject, permissions);
//
//		for (String permission : permissions)
//		{
//			try
//            {
//				subject.checkPermission(SUS.toLowerCase(permission));
//			}
//			catch (ShiroException e)
//            {
//			    throw new AccessSecurityException( e.getMessage());
//			}
//		}
        checkPermissions(false, subject, permissions);
    }

    /**
     * Checks permissions, lower-cased, against {@link Subject#checkPermission(String)}.
     * <ul>
     * <li>{@code partial} false: every permission is required; the first missing one throws.</li>
     * <li>{@code partial} true: at least one is required; it throws only when all are missing.</li>
     * </ul>
     * An empty {@code permissions} array throws in both modes ("All permissions failed"). Unlike
     * {@link #isPermitted(Subject, String)}, the wildcard {@code any} gets no special treatment here.
     *
     * @param partial     true for "any of", false for "all of"
     * @param subject     the subject to check
     * @param permissions the permission strings, Shiro wildcard syntax
     * @throws NullPointerException    if {@code subject} or {@code permissions} is null
     * @throws AccessSecurityException with {@link Reason#UNAUTHORIZED} when the requirement is not met
     */
    public static void checkPermissions(boolean partial, Subject subject, String... permissions)
            throws NullPointerException, AccessSecurityException {
        SUS.checkIfNulls("Null parameters not allowed", subject, permissions);

        int failureCount = 0;
        for (String permission : permissions) {
            try {
                subject.checkPermission(SUS.toLowerCase(permission));
            } catch (ShiroException e) {
                failureCount++;
                if (!partial)
                    throw new AccessSecurityException(e.getMessage(), Reason.UNAUTHORIZED);
            }
        }

        if (failureCount == permissions.length) {
            throw new AccessSecurityException("All permissions failed", Reason.UNAUTHORIZED);
        }
    }


    /**
     * {@link #isPermitted(Subject, String)} on the thread's subject.
     *
     * @param permission the permission string
     * @return true when held
     * @throws NullPointerException    if {@code permission} is null
     * @throws AccessSecurityException when no subject can be resolved
     */
    public static boolean isPermitted(String permission)
            throws NullPointerException, AccessSecurityException {
        return isPermitted(subject(), permission);
    }


    /**
     * Non-throwing permission test. {@link SecurityModel#PERM_RESOURCE_ANY} ({@code any}) is a
     * declaration that no specific permission is needed and is always true; every other string is
     * lower-cased and asked of {@link Subject#isPermitted(String)}. An anonymous subject holds nothing.
     *
     * @param subject    the subject to check
     * @param permission the permission string, Shiro wildcard syntax
     * @return true when held
     * @throws NullPointerException if an argument is null
     */
    public static boolean isPermitted(Subject subject, String permission)
            throws NullPointerException, AccessSecurityException {
        SUS.checkIfNulls("Null parameters not allowed", subject, permission);
        if (SecurityModel.PERM_RESOURCE_ANY.equals(permission))
            return true;
        return subject.isPermitted(DataEncoder.StringLower.encode(permission));
    }

    /**
     * {@link #isPermitted(String)} for a permission carried by a {@link GetValue}, such as a
     * {@link SecurityModel} permission enum.
     *
     * @param gv the holder of the permission string
     * @return true when the thread's subject holds it
     * @throws NullPointerException    if {@code gv} or its value is null
     * @throws AccessSecurityException when no subject can be resolved
     */
    public static boolean isPermitted(GetValue<String> gv)
            throws NullPointerException, AccessSecurityException {
        SUS.checkIfNulls("Null parameters not allowed", gv, gv.getValue());
        return isPermitted(gv.getValue());
    }

    /**
     * {@link #lookupAuthorizationInfo(PrincipalCollection)} for a subject's principals.
     *
     * @param subject the subject, not null
     * @return its roles and permissions as the ini realm sees them, or null
     */
    public static AuthorizationInfo lookupAuthorizationInfo(Subject subject) {
        return lookupAuthorizationInfo(subject.getPrincipals());
    }

    /**
     * {@link #lookupAuthorizationInfo(Class, PrincipalCollection)} against the {@link XlogistXIniRealm},
     * the realm of ini-configured deployments and tests. Datastore deployments pass
     * {@code io.xlogistx.shiro.ds.DSAuthorizingRealm.class} to the three-argument form instead.
     *
     * @param pc the principals
     * @return the roles and permissions, or null
     */
    public static AuthorizationInfo lookupAuthorizationInfo(PrincipalCollection pc) {
        return lookupAuthorizationInfo(XlogistXIniRealm.class, pc);
    }

    /**
     * The roles and permissions a realm resolves for {@code pc}, read directly rather than through
     * the subject, so a caller can list or cache what a subject holds. The realm is found with
     * {@link #getRealm(Class)} and must implement {@link AuthorizationInfoLookup}.
     *
     * @param realmClass the realm type to query
     * @param pc         the principals
     * @return the realm's {@link AuthorizationInfo}, or null when no such realm is configured or it
     * does not expose a lookup
     */
    @SuppressWarnings("unchecked")
    public static AuthorizationInfo lookupAuthorizationInfo(Class<? extends Realm> realmClass, PrincipalCollection pc) {
        Realm realm = getRealm(realmClass);
        // set the permission manually
        if (realm instanceof AuthorizationInfoLookup)
            return (AuthorizationInfo) ((AuthorizationInfoLookup<PrincipalCollection, AuthorizationInfo>) realm).lookupAuthorizationInfo(pc);
        return null;
    }


    /**
     * {@link #lookupSessionAttribute(Subject, Object)} on the thread's subject.
     *
     * @param key the attribute key
     * @return the attribute, or null
     */
    public static Object lookupSessionAttribute(Object key) {
        return lookupSessionAttribute(SecurityUtils.getSubject(), key);
    }

    /**
     * Reads an attribute of the subject's session. Uses {@link Subject#getSession()}, which creates
     * the session when the subject has none yet.
     *
     * @param subject the subject, not null
     * @param key     the attribute key, null yields null
     * @return the attribute, or null when absent
     */
    public static Object lookupSessionAttribute(Subject subject, Object key) {
        if (key != null) {
            Session session = subject.getSession();
            if (session != null) {
                return session.getAttribute(key);
            }
        }

        return null;
    }

    /**
     * Resumes an existing login on the calling thread from its Shiro session id, without
     * re-authenticating: the principals and the authenticated flag Shiro stored in the session are
     * read back, a {@link Subject} is built from them and bound to the thread, replacing whatever was
     * bound before. For request threads that carry the session id out of band (a cookie, a
     * WebSocket handshake, a resumed connection) rather than a Shiro web filter.
     *
     * @param sessionID the session id, from {@link #subjectSessionID()} or a client cookie
     * @return true when a subject was bound; false when the id is null or unknown, the session
     * expired or was stopped, or it holds no principals (an anonymous session). Every failure is
     * swallowed into false.
     */
    public static boolean loginBySessionID(String sessionID) {
        if (sessionID == null) {
            return false;
        }

        try {
            // Get session by ID
            Session session = SecurityUtils.getSecurityManager()
                    .getSession(new DefaultSessionKey(sessionID));

            if (session == null) {
                return false;
            }

            // Extract principals from session
            PrincipalCollection principals = (PrincipalCollection)
                    session.getAttribute(DefaultSubjectContext.PRINCIPALS_SESSION_KEY);

            if (principals == null || principals.isEmpty()) {
                return false;
            }

            Boolean authenticated = (Boolean)
                    session.getAttribute(DefaultSubjectContext.AUTHENTICATED_SESSION_KEY);

            // Build the Subject
            Subject subject = new Subject.Builder()
                    .sessionId(sessionID)
                    .principals(principals)
                    .authenticated(authenticated != null && authenticated)
                    .buildSubject();

            // Bind to current thread
            ThreadContext.bind(subject);

            return true;

        } catch (Exception e) {
            // Session doesn't exist or is expired
            return false;
        }
    }

    /**
     * One-line description of a session for logs: the session object, its id, its idle timeout in
     * human-readable form, the stored principals and the stored authenticated flag, comma separated.
     *
     * @param session the session, may be null
     * @return the description, {@code "NO SESSION"} for null
     */
    public static String toString(Session session) {
        if (session == null)
            return "NO SESSION";

        return SUS.toCanonicalID(',', session, session.getId(), Const.TimeInMillis.toString(session.getTimeout()), session.getAttribute(DefaultSubjectContext.PRINCIPALS_SESSION_KEY),
                session.getAttribute(DefaultSubjectContext.AUTHENTICATED_SESSION_KEY));
    }

    /**
     * The subject bound to the calling thread, or, when there is none, a new anonymous subject built
     * on {@code securityManager} and bound to the thread. Unlike {@link #subject()} it does not need
     * the VM-wide manager of {@link #setSecurityManager(SecurityManager)}, which lets several
     * managers coexist in one VM (tests, embedded servers).
     *
     * @param securityManager the manager to build the subject on when the thread has none
     * @return the thread's subject, never null
     */
    public static Subject getSubject(SecurityManager securityManager) {
        // need to check with session context if the actual subject is found
        Subject subject = ThreadContext.getSubject();

        if (subject == null) {
            subject = (new Subject.Builder(securityManager)).buildSubject();
            ThreadContext.bind(subject);
        }

        return subject;
    }

}