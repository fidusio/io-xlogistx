package io.xlogistx.opsec.ssl;

import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.security.SSLGroupSetterInt;
import org.zoxweb.shared.util.SUS;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import java.lang.reflect.Method;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * {@link SSLGroupSetterInt} for the JDK's own TLS stack (SunJSSE). Pins the named
 * groups offered/accepted by an {@link SSLEngine} through
 * {@code SSLParameters.setNamedGroups(String[])}, which exists since JDK 20 and is
 * therefore reached by reflection so this class still compiles and loads on JDK 8.
 * On a runtime without that method the groups are left at the provider default
 * and a warning is logged once. Any engine type is accepted; unlike
 * {@code org.zoxweb.server.security.BCSSLGroupSetter} it does not require a
 * BouncyCastle engine.
 */
public class JDKSSLGroupSetter
        implements SSLGroupSetterInt {

    public static final LogWrapper log = new LogWrapper(JDKSSLGroupSetter.class).setEnabled(false);

    private static final Method SET_NAMED_GROUPS = lookupSetNamedGroups();
    private static volatile boolean warned = false;

    private final String[] groups;

    /**
     * @param groups named groups in preference order, e.g. {@code "x25519"},
     *               {@code "secp256r1"} or, on JDK 24+, {@code "X25519MLKEM768"}
     * @throws NullPointerException     if groups is null
     * @throws IllegalArgumentException if groups is empty
     */
    public JDKSSLGroupSetter(String[] groups) {
        SUS.checkIfNull("groups", groups);
        if (groups.length == 0)
            throw new IllegalArgumentException("groups is empty");
        this.groups = groups;
    }

    @Override
    public String[] getGroups() {
        return groups;
    }

    @Override
    public SSLEngine setGroups(SSLEngine sslEngine)
            throws GeneralSecurityException {
        if (sslEngine == null)
            return null;
        if (SET_NAMED_GROUPS == null) {
            if (!warned) {
                warned = true;
                log.getLogger().warning("SSLParameters.setNamedGroups not available on this JVM, groups "
                        + Arrays.toString(groups) + " ignored");
            }
            return sslEngine;
        }
        try {
            SSLParameters params = sslEngine.getSSLParameters();
            SET_NAMED_GROUPS.invoke(params, (Object) groups.clone());
            sslEngine.setSSLParameters(params);
            if (log.isEnabled()) log.getLogger().info("named groups set to " + Arrays.toString(groups));
        } catch (Exception e) {
            throw new GeneralSecurityException("failed to set named groups " + Arrays.toString(groups), e);
        }
        return sslEngine;
    }

    private static Method lookupSetNamedGroups() {
        try {
            return SSLParameters.class.getMethod("setNamedGroups", String[].class);
        } catch (NoSuchMethodException e) {
            return null;
        }
    }
}
