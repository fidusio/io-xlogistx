package io.xlogistx.opsec;

import org.bouncycastle.jsse.BCSSLEngine;
import org.bouncycastle.jsse.BCSSLParameters;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.security.SSLGroupSetterInt;
import org.zoxweb.shared.util.SUS;

import javax.net.ssl.SSLEngine;
import java.security.GeneralSecurityException;

public class BCSSLGroupSetter
implements SSLGroupSetterInt {
    public static final LogWrapper log = new LogWrapper(BCSSLGroupSetter.class);
    /**
     * Array of named groups (elliptic curves) to be configured on SSLEngine instances.
     * <p>These groups are used for key exchange during the TLS handshake.</p>
     */
    private final String[] groups;


    /**
     * Constructs an SSLGroupSetter with the specified named groups.
     *
     * <p>The groups array defines the elliptic curves or finite field groups that will be
     * enabled on SSLEngine instances. The order of groups in the array typically indicates
     * preference order during TLS negotiation.</p>
     *
     * @param groups array of named group identifiers (e.g., "x25519", "secp256r1").
     *               Must not be null and must contain at least one element.
     * @throws NullPointerException     if groups is null
     * @throws IllegalArgumentException if groups array is empty
     */
    public BCSSLGroupSetter(String[] groups) {
        SUS.checkIfNull("nulls", groups);
        if (groups.length == 0)
            throw new IllegalArgumentException("groups is empty");

        this.groups = groups;
    }

    /**
     * Returns the configured named groups.
     *
     * @return array of named group identifiers configured for this setter.
     *         Never returns null.
     */
    public String[] getGroups(){
        return groups;
    }

    /**
     * Applies the configured named groups to the specified SSLEngine.
     *
     * <p>Implementations should configure the SSLEngine's SSL parameters to use
     * the named groups specified during construction. This typically involves
     * getting the current SSLParameters, setting the named groups, and applying
     * the parameters back to the engine.</p>
     *
     * <p>The implementation may return the same SSLEngine instance after modification,
     * or a wrapped/proxy instance if needed.</p>
     *
     * @param sslEngine the SSLEngine to configure with named groups. Must not be null.
     * @return the configured SSLEngine instance (may be the same instance or a new one)
     * @throws GeneralSecurityException if an error occurs while configuring the groups,
     *                                  such as unsupported groups or security restrictions
     */
    public SSLEngine setGroups(SSLEngine sslEngine)
            throws GeneralSecurityException {
        if(sslEngine instanceof BCSSLEngine) {
            BCSSLEngine bcEngine = (BCSSLEngine) sslEngine;
            BCSSLParameters bcParams = bcEngine.getParameters();
            bcParams.setNamedGroups(groups);
            bcEngine.setParameters(bcParams);
        }
        else
            log.getLogger().info("SSLGroupSetter requires BCSSLEngine current engine" + (sslEngine != null ? " " + sslEngine.getClass().getName() : ""));
        return sslEngine;
    }
}
