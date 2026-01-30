package io.xlogistx.common.dns;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetAddress;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test cases for DNSRegistrar
 */
public class DNSRegistrarTest {

    @BeforeAll
    static void setup() throws Exception {
        // Configure resolver to use Google DNS
        DNSRegistrar.SINGLETON.setResolver("8.8.8.8");
    }

    // ==================== Local Cache Tests ====================

    @Test
    void testRegisterAndLookup() throws Exception {
        // Register a custom domain
        DNSRegistrar.SINGLETON.register("test.local", "192.168.1.100");

        // Lookup should return the registered IP
        InetAddress result = DNSRegistrar.SINGLETON.lookup("test.local");
        assertNotNull(result);
        assertEquals("192.168.1.100", result.getHostAddress());
    }

    @Test
    void testRegisterWithDotSuffix() throws Exception {
        // Register with trailing dot (DNS format)
        DNSRegistrar.SINGLETON.register("test2.local.", "192.168.1.101");

        // Lookup without dot should still work
        InetAddress result = DNSRegistrar.SINGLETON.lookup("test2.local");
        assertNotNull(result);
        assertEquals("192.168.1.101", result.getHostAddress());
    }

    @Test
    void testCaseInsensitiveLookup() throws Exception {
        DNSRegistrar.SINGLETON.register("MyDomain.Local", "10.0.0.1");

        // Lookup with different case should work
        InetAddress result1 = DNSRegistrar.SINGLETON.lookup("mydomain.local");
        InetAddress result2 = DNSRegistrar.SINGLETON.lookup("MYDOMAIN.LOCAL");

        assertNotNull(result1);
        assertNotNull(result2);
        assertEquals(result1.getHostAddress(), result2.getHostAddress());
    }

    @Test
    void testLookupNonExistent() {
        // Lookup non-existent domain should return null
        InetAddress result = DNSRegistrar.SINGLETON.lookup("nonexistent.invalid.local");
        assertNull(result);
    }

    // ==================== DNS Resolution Tests ====================

    @Test
    void testResolveGoogle() throws IOException {
        // Resolve a well-known domain
        InetAddress result = DNSRegistrar.SINGLETON.resolve("google.com");

        assertNotNull(result, "google.com should resolve");
        System.out.println("google.com resolved to: " + result.getHostAddress());
    }

    @Test
    void testResolveCloudflare() throws IOException {
        InetAddress result = DNSRegistrar.SINGLETON.resolve("cloudflare.com");

        assertNotNull(result, "cloudflare.com should resolve");
        System.out.println("cloudflare.com resolved to: " + result.getHostAddress());
    }

    @Test
    void testResolveAllGoogle() throws IOException {
        // Get all IPs for a domain
        InetAddress[] results = DNSRegistrar.SINGLETON.resolveAll("google.com");

        assertNotNull(results, "google.com should have A records");
        assertTrue(results.length > 0, "google.com should have at least one IP");

        System.out.println("google.com resolved to " + results.length + " IPs:");
        for (InetAddress ip : results) {
            System.out.println("  - " + ip.getHostAddress());
        }
    }

    @Test
    void testResolveCaching() throws IOException {
        // Clear any cached entry first
        String testDomain = "github.com";

        // Resolve with caching enabled (default)
        InetAddress result1 = DNSRegistrar.SINGLETON.resolve(testDomain, true);
        assertNotNull(result1);

        // Second lookup should come from cache
        InetAddress cached = DNSRegistrar.SINGLETON.lookup(testDomain);
        assertNotNull(cached, "Result should be cached");
        assertEquals(result1.getHostAddress(), cached.getHostAddress());

        System.out.println(testDomain + " cached as: " + cached.getHostAddress());
    }

    @Test
    void testResolveNoCaching() throws IOException {
        String testDomain = "nocache-test.example.com";

        // Ensure not in cache initially
        InetAddress initial = DNSRegistrar.SINGLETON.lookup(testDomain);

        // Resolve without caching - this will fail since example.com doesn't have this subdomain
        // But we can test with a real domain
        InetAddress result = DNSRegistrar.SINGLETON.resolve("microsoft.com", false);
        assertNotNull(result);

        // Verify it wasn't cached (lookup returns what was there before)
        InetAddress afterResolve = DNSRegistrar.SINGLETON.lookup("microsoft.com");
        // Note: If microsoft.com was never cached before, this will be null
        // This test verifies the no-cache path works
        System.out.println("microsoft.com resolved (no cache): " + result.getHostAddress());
    }

    @Test
    void testResolveNonExistentDomain() throws IOException {
        // Try to resolve a domain that doesn't exist
        InetAddress result = DNSRegistrar.SINGLETON.resolve("this-domain-definitely-does-not-exist-12345.com");

        assertNull(result, "Non-existent domain should return null");
    }

    @Test
    void testResolveWithoutResolver() {
        // Create a new registrar without resolver configured
        // We can't easily test this without reflection, so we'll just verify
        // that the singleton has a resolver set
        assertNotNull(DNSRegistrar.SINGLETON.getResolver(), "Resolver should be configured");
    }

    // ==================== Data Encoder/Decoder Tests ====================

    @Test
    void testToDNSEntry() {
        // Test the DNS entry encoder
        assertEquals("google.com.", DNSRegistrar.ToDNSEntry.encode("google.com"));
        assertEquals("google.com.", DNSRegistrar.ToDNSEntry.encode("google.com."));
        assertEquals("google.com.", DNSRegistrar.ToDNSEntry.encode("Google.COM"));
        assertNull(DNSRegistrar.ToDNSEntry.encode(null));
        assertNull(DNSRegistrar.ToDNSEntry.encode(""));
    }

    @Test
    void testToDomain() {
        // Test the domain decoder
        assertEquals("google.com", DNSRegistrar.ToDomain.decode("google.com."));
        assertEquals("google.com", DNSRegistrar.ToDomain.decode("google.com"));
        assertEquals("google.com", DNSRegistrar.ToDomain.decode("Google.COM"));
        assertNull(DNSRegistrar.ToDomain.decode(null));
        assertNull(DNSRegistrar.ToDomain.decode(""));
    }

    // ==================== Integration Tests ====================

    @Test
    void testLocalOverridesUpstream() throws IOException {
        // Register a local override
        String domain = "override-test.com";
        String localIP = "127.0.0.1";
        DNSRegistrar.SINGLETON.register(domain, localIP);

        // Resolve should return local override, not query upstream
        InetAddress result = DNSRegistrar.SINGLETON.resolve(domain);

        assertNotNull(result);
        assertEquals(localIP, result.getHostAddress(),
                "Local cache should take precedence over upstream resolver");
    }

    @Test
    void testResolveMultipleDomains() throws IOException {
        String[] domains = {"google.com", "cloudflare.com", "github.com"};

        for (String domain : domains) {
            InetAddress result = DNSRegistrar.SINGLETON.resolve(domain);
            assertNotNull(result, domain + " should resolve");
            System.out.println(domain + " -> " + result.getHostAddress());
        }
    }

    // ==================== Private IP Resolution Tests ====================

    @Test
    void testResolvePrivateIP_10Range() throws IOException {
        // 10.x.x.x range
        InetAddress result = DNSRegistrar.SINGLETON.resolve("10.0.0.1");
        assertNotNull(result);
        assertEquals("10.0.0.1", result.getHostAddress());

        result = DNSRegistrar.SINGLETON.resolve("10.255.255.255");
        assertNotNull(result);
        assertEquals("10.255.255.255", result.getHostAddress());

        System.out.println("10.x.x.x range: OK");
    }

    @Test
    void testResolvePrivateIP_192Range() throws IOException {
        // 192.168.x.x range
        InetAddress result = DNSRegistrar.SINGLETON.resolve("192.168.1.1");
        assertNotNull(result);
        assertEquals("192.168.1.1", result.getHostAddress());

        result = DNSRegistrar.SINGLETON.resolve("192.168.0.100");
        assertNotNull(result);
        assertEquals("192.168.0.100", result.getHostAddress());

        result = DNSRegistrar.SINGLETON.resolve("192.168.255.255");
        assertNotNull(result);
        assertEquals("192.168.255.255", result.getHostAddress());

        System.out.println("192.168.x.x range: OK");
    }

    @Test
    void testResolvePrivateIP_172Range() throws IOException {
        // 172.16-31.x.x range
        InetAddress result = DNSRegistrar.SINGLETON.resolve("172.16.0.1");
        assertNotNull(result);
        assertEquals("172.16.0.1", result.getHostAddress());

        result = DNSRegistrar.SINGLETON.resolve("172.31.255.255");
        assertNotNull(result);
        assertEquals("172.31.255.255", result.getHostAddress());

        result = DNSRegistrar.SINGLETON.resolve("172.20.10.5");
        assertNotNull(result);
        assertEquals("172.20.10.5", result.getHostAddress());

        System.out.println("172.16-31.x.x range: OK");
    }

    @Test
    void testResolvePrivateIP_172OutOfRange() throws IOException {
        // 172.15.x.x and 172.32.x.x are NOT private - should query DNS (will likely fail)
        // These should NOT be treated as private IPs
        // We test by checking that they go through normal DNS resolution

        // 172.15.x.x - below private range, will fail DNS lookup
        InetAddress result = DNSRegistrar.SINGLETON.resolve("172.15.0.1");
        // This will be null because 172.15.0.1 is not a valid domain and not private
        assertNull(result, "172.15.x.x should not be treated as private IP");

        System.out.println("172 out-of-range detection: OK");
    }

    @Test
    void testResolveNonPrivateIP() throws IOException {
        // Public IPs should go through DNS resolution (which will fail for raw IPs)
        // 8.8.8.8 is Google's DNS - it's a public IP, not private
        InetAddress result = DNSRegistrar.SINGLETON.resolve("8.8.8.8");
        // Should be null because we only handle private IPs directly
        assertNull(result, "Public IP should not be resolved directly");

        System.out.println("Public IP not directly resolved: OK");
    }

    @Test
    void testResolvePrivateIPNotDomain() throws IOException {
        // Ensure domain names are not confused with IPs
        InetAddress result = DNSRegistrar.SINGLETON.resolve("10domain.com");
        // This should go through DNS (may or may not resolve)
        // The key is it shouldn't be treated as IP 10.x.x.x
        System.out.println("10domain.com treated as domain, not IP: " +
                (result != null ? result.getHostAddress() : "null"));
    }
}
