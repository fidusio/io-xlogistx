package io.xlogistx.opsec.ssl;

import io.xlogistx.opsec.OPSecUtil;
import org.bouncycastle.asn1.x500.X500Name;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Covers the host-&gt;identity resolution use cases of {@link DomainIdentityMatcher}:
 * exact (case-insensitive) lookup, single-label wildcard + apex, multiple
 * identities per host, exact/wildcard de-duplication, load-order preservation, and
 * the no-match / null cases. Identities are fabricated with chosen name lists via
 * the {@link Identity} constructor (sharing one dummy key/cert), so the tests
 * isolate matching from certificate generation.
 */
public class DomainIdentityMatcherTest {

    private static PrivateKey dummyKey;
    private static X509Certificate[] dummyChain;

    @BeforeAll
    static void setup() throws Exception {
        OPSecUtil.SINGLETON.loadProviders();
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC", "BC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = g.generateKeyPair();
        X500Name dn = new X500Name("CN=dummy");
        X509Certificate cert = OPSecUtil.SINGLETON.generateSelfSignedCertificate(kp, dn, dn, "1year");
        dummyKey = kp.getPrivate();
        dummyChain = new X509Certificate[]{ cert };
    }

    private static Identity id(String token, String... names) {
        return new Identity(dummyKey, dummyChain, Arrays.asList(names), token);
    }

    private static DomainIdentityMatcher matcher(Identity... ids) {
        return new DomainIdentityMatcher(Arrays.asList(ids));
    }

    @Test
    void exact_caseInsensitive_andNoMatch() {
        Identity a = id("a", "alpha.test");
        Identity b = id("b", "beta.test");
        DomainIdentityMatcher m = matcher(a, b);

        assertSame(a, m.resolveFirst("alpha.test"));
        assertSame(a, m.resolveFirst("ALPHA.Test"));            // case-insensitive
        assertEquals(Arrays.asList(a), m.resolveAll("alpha.test"));
        assertTrue(m.matches("beta.test"));

        assertNull(m.resolveFirst("nope.test"));
        assertFalse(m.matches("nope.test"));
        assertTrue(m.resolveAll("nope.test").isEmpty());

        // null host
        assertNull(m.resolveFirst(null));
        assertTrue(m.resolveAll(null).isEmpty());
    }

    @Test
    void wildcard_singleLabelAndApex_only() {
        Identity w = id("w", "*.foo.com");
        DomainIdentityMatcher m = matcher(w);

        assertSame(w, m.resolveFirst("a.foo.com"));   // one label deep
        assertSame(w, m.resolveFirst("foo.com"));     // apex
        assertSame(w, m.resolveFirst("A.FOO.COM"));   // case-insensitive

        assertNull(m.resolveFirst("a.b.foo.com"));    // two labels -> NOT matched
        assertNull(m.resolveFirst("bar.com"));        // unrelated
        assertNull(m.resolveFirst("xfoo.com"));       // not a label boundary
    }

    @Test
    void multipleIdentitiesPerHost_loadOrderPreserved() {
        Identity ec = id("ec", "example.test");
        Identity rsa = id("rsa", "example.test");
        DomainIdentityMatcher m = matcher(ec, rsa);

        List<Identity> hits = m.resolveAll("example.test");
        assertEquals(2, hits.size());
        assertSame(ec, hits.get(0));                  // load order
        assertSame(rsa, hits.get(1));
        assertSame(ec, m.resolveFirst("example.test"));
    }

    @Test
    void exactAndWildcardOnSameIdentity_deduped() {
        Identity both = id("both", "a.foo.com", "*.foo.com");
        DomainIdentityMatcher m = matcher(both);

        // host matches via BOTH the exact name and the wildcard -> returned once.
        List<Identity> hits = m.resolveAll("a.foo.com");
        assertEquals(1, hits.size());
        assertSame(both, hits.get(0));
    }

    @Test
    void resolveFirst_picksLowestLoadIndex_acrossExactAndWildcard() {
        Identity wildFirst = id("w", "*.foo.com");   // index 0
        Identity exactSecond = id("e", "a.foo.com");  // index 1
        DomainIdentityMatcher m = matcher(wildFirst, exactSecond);

        // both cover a.foo.com; first by load order is the wildcard identity.
        assertSame(wildFirst, m.resolveFirst("a.foo.com"));
        assertEquals(Arrays.asList(wildFirst, exactSecond), m.resolveAll("a.foo.com"));
    }
}
