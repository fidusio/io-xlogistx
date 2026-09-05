package io.xlogistx.shiro.authc;

import io.xlogistx.shiro.DomainPrincipalCollection;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.security.SecUtil;
import org.zoxweb.server.util.cache.JWTTokenCache;
import org.zoxweb.shared.crypto.CIPassword;
import org.zoxweb.shared.security.JWT;
import org.zoxweb.shared.security.JWTPayload;
import org.zoxweb.shared.security.SecConst;
import org.zoxweb.shared.security.SubjectAPIKey;
import org.zoxweb.shared.util.Const;
import org.zoxweb.shared.util.SUS;
import org.zoxweb.shared.util.SharedStringUtil;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;

/**
 * The credentials matcher for every xlogistx realm. Three token kinds:
 * <ul>
 *   <li><b>Password</b> ({@link DomainUsernamePasswordToken} or any token whose realm info carries a
 *       {@link CIPassword} / canonical password string): the token principal must equal the primary
 *       principal, {@code autoAuthenticationEnabled} skips the check (trusted-caller path), otherwise
 *       {@link SecUtil#isPasswordValid}.</li>
 *   <li><b>Raw API key</b> ({@link APIKeyAuthenticationToken}): constant-time compare against the
 *       stored {@link SubjectAPIKey}, then {@link #isUsable(SubjectAPIKey)} (status / expiry).</li>
 *   <li><b>JWT bearer token</b> ({@link JWTAuthenticationToken}) against the {@link SubjectAPIKey} the
 *       realm resolved from the {@code sub} claim: HMAC signature with the key's secret bytes,
 *       {@code sub} equal to the key ID, {@code exp} / {@code nbf} honoured within
 *       {@link #setClockSkewMillis(long)}, the key's domain / app scope (when set) matching the
 *       claims, and, for keys flagged {@link SubjectAPIKey#isTimeStampRequired()}, an {@code iat}
 *       inside {@link #setJWTTimestampWindowMillis(long)} plus an optional replay cache
 *       ({@link #setJWTReplayCache(JWTTokenCache)}).</li>
 * </ul>
 * Status rules treat {@code null} as ACTIVE (rows created before statuses were stamped). All knobs
 * are bean properties, so they can be set from {@code shiro.ini}.
 * <p>
 * History: the raw-key and JWT rules were written for the datastore-backed realm
 * ({@code DSCredentialsMatcher}, merged here 2026-09-03); the previous JWT branch of this class
 * required {@code Status == ACTIVE} (null rejected), ignored {@code exp} / {@code nbf}, and failed
 * with an NPE-turned-false on unscoped keys.
 */
public class CredentialsInfoMatcher
        implements CredentialsMatcher {

    public static final LogWrapper log = new LogWrapper(CredentialsInfoMatcher.class).setEnabled(false);

    /** Default tolerance for {@code exp} / {@code nbf}: one minute. */
    public static final long DEFAULT_CLOCK_SKEW_MILLIS = 60_000L;
    /** Default freshness window for {@code iat} when the key requires timestamps: five minutes. */
    public static final long DEFAULT_TIMESTAMP_WINDOW_MILLIS = 5 * 60_000L;

    private volatile long clockSkewMillis = DEFAULT_CLOCK_SKEW_MILLIS;
    private volatile long jwtTimestampWindowMillis = DEFAULT_TIMESTAMP_WINDOW_MILLIS;
    private volatile JWTTokenCache jwtReplayCache;

    // ------------------------------------------------------------------
    // configuration (bean properties, INI-settable)
    // ------------------------------------------------------------------

    public long getClockSkewMillis() {
        return clockSkewMillis;
    }

    /** Tolerance applied to {@code exp} and {@code nbf}; negative values are treated as 0. */
    public CredentialsInfoMatcher setClockSkewMillis(long clockSkewMillis) {
        this.clockSkewMillis = Math.max(0, clockSkewMillis);
        return this;
    }

    public long getJWTTimestampWindowMillis() {
        return jwtTimestampWindowMillis;
    }

    /** Maximum |now - iat| for keys with {@link SubjectAPIKey#isTimeStampRequired()}; must be positive. */
    public CredentialsInfoMatcher setJWTTimestampWindowMillis(long windowMillis) {
        if (windowMillis <= 0) {
            throw new IllegalArgumentException("Timestamp window must be positive: " + windowMillis);
        }
        this.jwtTimestampWindowMillis = windowMillis;
        return this;
    }

    public JWTTokenCache getJWTReplayCache() {
        return jwtReplayCache;
    }

    /**
     * Optional replay protection for timestamp-required keys: every accepted token's signature is
     * recorded and a second presentation inside the cache's expiration period is rejected.
     * {@code null} (the default) disables it.
     */
    public CredentialsInfoMatcher setJWTReplayCache(JWTTokenCache cache) {
        this.jwtReplayCache = cache;
        return this;
    }

    // ------------------------------------------------------------------
    // matching
    // ------------------------------------------------------------------

    @Override
    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
        if (token == null || info == null) {
            return reject("null token or info");
        }
        try {
            if (log.isEnabled() && info.getCredentials() != null)
                log.getLogger().info("credentials " + info.getCredentials() + " " + info.getCredentials().getClass());

            if (token instanceof APIKeyAuthenticationToken) {
                return apiKeyMatches((APIKeyAuthenticationToken) token, info);
            }
            if (token instanceof JWTAuthenticationToken) {
                return jwtMatches((JWTAuthenticationToken) token, info);
            }
            return passwordMatches(token, info);
        } catch (RuntimeException e) {
            return reject("unexpected failure: " + e);
        }
    }

    private boolean passwordMatches(AuthenticationToken token, AuthenticationInfo info) {
        CIPassword ciPassword = null;
        if (info.getCredentials() instanceof CIPassword) {
            ciPassword = (CIPassword) info.getCredentials();
        } else if (info.getCredentials() instanceof String) {
            try {
                ciPassword = SecUtil.fromCanonicalID((String) info.getCredentials());
            } catch (GeneralSecurityException e) {
                return reject("stored password uses an unsupported hash: " + e);
            }
        }
        if (ciPassword == null) {
            return reject("no password credential for " + token.getClass().getSimpleName());
        }
        if (token.getPrincipal() == null || info.getPrincipals() == null
                || !token.getPrincipal().equals(info.getPrincipals().getPrimaryPrincipal())) {
            return reject("token principal does not match the primary principal");
        }
        if (token instanceof DomainUsernamePasswordToken
                && ((DomainUsernamePasswordToken) token).isAutoAuthenticationEnabled()) {
            return true; // trusted caller: password not checked
        }

        String password = null;
        if (token.getCredentials() instanceof char[]) {
            password = new String((char[]) token.getCredentials());
        } else if (token.getCredentials() instanceof byte[]) {
            password = SharedStringUtil.toString((byte[]) token.getCredentials());
        } else if (token.getCredentials() instanceof String) {
            password = (String) token.getCredentials();
        }
        return SecUtil.isPasswordValid(ciPassword, password);
    }

    private boolean apiKeyMatches(APIKeyAuthenticationToken token, AuthenticationInfo info) {
        if (!(info.getCredentials() instanceof SubjectAPIKey)) {
            return reject("no API key resolved");
        }
        SubjectAPIKey sak = (SubjectAPIKey) info.getCredentials();
        String stored = sak.getAPIKey();
        String given = token.getAPIKey();
        if (stored == null || given == null) {
            return reject("missing API key");
        }
        if (!MessageDigest.isEqual(stored.getBytes(StandardCharsets.UTF_8), given.getBytes(StandardCharsets.UTF_8))) {
            return reject("API key mismatch");
        }
        return isUsable(sak) || reject("API key not usable");
    }

    private boolean jwtMatches(JWTAuthenticationToken token, AuthenticationInfo info) {
        if (!(info.getCredentials() instanceof SubjectAPIKey)) {
            return reject("no API key resolved");
        }
        SubjectAPIKey sak = (SubjectAPIKey) info.getCredentials();
        if (!isUsable(sak)) {
            return reject("API key not usable");
        }
        String raw = token.getCredentials() instanceof String ? (String) token.getCredentials() : null;
        if (SUS.isEmpty(raw)) {
            return reject("empty token");
        }
        JWT jwt;
        try {
            byte[] secret = sak.getAPIKeyAsBytes();
            if (secret == null || secret.length == 0) {
                return reject("API key has no secret");
            }
            // SecUtil directly rather than JWTProvider: same check, but the provider prints a stack
            // trace on every bad signature
            jwt = SecUtil.decodeJWT(secret, raw);
        } catch (Exception e) {
            return reject("signature check failed: " + e);
        }
        JWTPayload payload = jwt != null ? jwt.getPayload() : null;
        String keyID = sak.getSubjectID();
        if (payload == null || SUS.isEmpty(keyID) || !keyID.equals(payload.getSubjectID())) {
            return reject("sub does not match the key ID");
        }

        long now = System.currentTimeMillis();
        long skew = clockSkewMillis;
        long exp = claim(payload, "exp");
        if (exp != 0 && now > exp * 1000L + skew) {
            return reject("token expired");
        }
        long nbf = claim(payload, "nbf");
        if (nbf != 0 && now + skew < nbf * 1000L) {
            return reject("token not yet valid");
        }
        if (timestampRequired(sak)) {
            long iat = claim(payload, "iat");
            if (iat == 0 || Math.abs(now - iat * 1000L) > jwtTimestampWindowMillis) {
                return reject("iat missing or outside the freshness window");
            }
            JWTTokenCache cache = jwtReplayCache;
            if (cache != null) {
                try {
                    cache.put(signatureOf(raw), jwt);
                } catch (SecurityException e) {
                    return reject("replay: " + e.getMessage());
                }
            }
        }

        if (info.getPrincipals() instanceof DomainPrincipalCollection) {
            DomainPrincipalCollection dpc = (DomainPrincipalCollection) info.getPrincipals();
            if (!scopeMatches(dpc.getDomainID(), payload.getDomainID())
                    || !scopeMatches(dpc.getAppID(), payload.getAppID())) {
                return reject("domain/app claims outside the key's scope");
            }
        }
        return true;
    }

    // ------------------------------------------------------------------
    // helpers (public where realms need the same rule)
    // ------------------------------------------------------------------

    /** Lifecycle status ACTIVE or unset, credential status ACTIVE or unset, and not expired. */
    public static boolean isUsable(SubjectAPIKey sak) {
        if (sak == null) {
            return false;
        }
        if (sak.getStatus() != null && sak.getStatus() != Const.Status.ACTIVE) {
            return false;
        }
        if (sak.getCredentialStatus() != null && sak.getCredentialStatus() != SecConst.SecStatus.ACTIVE) {
            return false;
        }
        long expiry = expiryOf(sak);
        return expiry == 0 || System.currentTimeMillis() <= expiry;
    }

    /** Expiry timestamp, or 0 when unset (the backing value may be absent on older rows). */
    public static long expiryOf(SubjectAPIKey sak) {
        try {
            return sak.getExpiryDate();
        } catch (NullPointerException e) {
            return 0;
        }
    }

    /** A scope the key does not constrain matches anything; a constrained one must be claimed exactly (case-insensitive). */
    public static boolean scopeMatches(String keyScope, String claimed) {
        return SUS.isEmpty(keyScope) || (claimed != null && keyScope.equalsIgnoreCase(claimed));
    }

    /** Signature segment of a compact JWT, used as the replay-cache key. */
    public static String signatureOf(String compactJWT) {
        int dot = compactJWT.lastIndexOf('.');
        return dot >= 0 ? compactJWT.substring(dot + 1) : compactJWT;
    }

    /**
     * Numeric-date claim in seconds, or 0 when absent or unreadable. Read through the property map
     * rather than the typed getters: a parsed token holds these as {@link Integer} when they fit,
     * and the getters unbox straight to {@code long}.
     */
    public static long claim(JWTPayload payload, String name) {
        try {
            Object value = payload.getProperties() != null ? payload.getProperties().getValue(name) : null;
            if (value instanceof Number) {
                return ((Number) value).longValue();
            }
            if (value instanceof String && !((String) value).isEmpty()) {
                return Long.parseLong(((String) value).trim());
            }
        } catch (RuntimeException e) {
            if (log.isEnabled()) log.getLogger().info("unreadable claim " + name + ": " + e);
        }
        return 0;
    }

    private static boolean timestampRequired(SubjectAPIKey sak) {
        try {
            return sak.isTimeStampRequired();
        } catch (NullPointerException e) {
            return false;
        }
    }

    private static boolean reject(String why) {
        if (log.isEnabled()) log.getLogger().info("credentials rejected: " + why);
        return false;
    }
}
