package io.xlogistx.shiro.authc;

import org.apache.shiro.authc.HostAuthenticationToken;

/**
 * Shiro token for a raw API key (as opposed to {@code JWTAuthenticationToken}, which carries a
 * signed JWT). The credential is the key itself; the principal is the owning subject GUID, which
 * the realm fills in once the key row has been resolved, so an unresolved token exposes no
 * principal and {@link #toString()} never prints the key.
 */
public class APIKeyAuthenticationToken
        implements HostAuthenticationToken {

    private final String apiKey;
    private final String domainID;
    private final String appID;
    private final String host;
    private volatile String subjectGUID;

    public APIKeyAuthenticationToken(String apiKey) {
        this(apiKey, null, null, null);
    }

    public APIKeyAuthenticationToken(String apiKey, String domainID, String appID, String host) {
        this.apiKey = apiKey;
        this.domainID = domainID;
        this.appID = appID;
        this.host = host;
    }

    public String getAPIKey() {
        return apiKey;
    }

    public String getDomainID() {
        return domainID;
    }

    public String getAppID() {
        return appID;
    }

    /** Owning subject GUID, set by the realm after the key has been resolved; {@code null} before. */
    public String getSubjectGUID() {
        return subjectGUID;
    }

    public void setSubjectGUID(String subjectGUID) {
        this.subjectGUID = subjectGUID;
    }

    @Override
    public String getHost() {
        return host;
    }

    @Override
    public Object getPrincipal() {
        return subjectGUID;
    }

    @Override
    public Object getCredentials() {
        return apiKey;
    }

    @Override
    public String toString() {
        return "APIKeyAuthenticationToken{subjectGUID=" + subjectGUID + ", domainID=" + domainID + ", appID=" + appID + "}";
    }
}
