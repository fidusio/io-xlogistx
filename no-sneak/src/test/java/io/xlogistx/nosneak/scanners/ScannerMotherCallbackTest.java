package io.xlogistx.nosneak.scanners;

import io.xlogistx.common.dns.DNSRegistrar;
import io.xlogistx.opsec.OPSecUtil;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.zoxweb.server.http.HTTPNIOSocket;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.net.NIOSocket;
import org.zoxweb.server.task.TaskUtil;
import org.zoxweb.shared.net.IPAddress;
import org.zoxweb.shared.util.Const;

import java.io.IOException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test ScannerMotherCallback against real TLS servers.
 */
public class ScannerMotherCallbackTest {

    public static final LogWrapper log = new LogWrapper(ScannerMotherCallbackTest.class).setEnabled(true);

    private static final IPAddress[] serversToTest = IPAddress.parseList(
            "https://xlogistx.io",
            "google.com:443",
            "https://cloudflare.com:443",
            "https://backend.zoxweb.com:4443",
            "zoxweb.com:1024",
            "khara:8080",
            "https://10.0.0.8",
            "https://dbs.xlogistx.io");

    private static HTTPNIOSocket httpNIOSocket;

    @BeforeAll
    static void setup() throws IOException {
        OPSecUtil.singleton();
        DNSRegistrar.SINGLETON.setResolver("10.0.0.1");
        httpNIOSocket = new HTTPNIOSocket(new NIOSocket(TaskUtil.defaultTaskProcessor(), TaskUtil.defaultTaskScheduler()));
    }

    @Test
    void testBasicScan() throws Exception {
        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<PQCScanResult> resultRef = new AtomicReference<>();

        IPAddress address = new IPAddress("google.com", 443);
        ScannerMotherCallback mother = new ScannerMotherCallback(address, result -> {
            log.getLogger().info("Basic scan result:\n" + result);
            resultRef.set(result);
            latch.countDown();
        }, null, httpNIOSocket);
        mother.dnsResolver(DNSRegistrar.SINGLETON);
        mother.timeoutInSec(10);
        mother.start();

        boolean completed = latch.await(30, TimeUnit.SECONDS);
        assertTrue(completed, "Scan should complete within timeout");

        PQCScanResult result = resultRef.get();
        assertNotNull(result, "Result should not be null");
        assertTrue(result.isSuccess(), "Scan should succeed: " + result.getErrorMessage());
        assertNotNull(result.getTlsVersion(), "TLS version should be captured");
        assertNotNull(result.getCipherSuite(), "Cipher suite should be captured");

        log.getLogger().info("========== Basic Scan Result ==========");
        log.getLogger().info("Host: " + result.getHost() + ":" + result.getPort());
        log.getLogger().info("TLS Version: " + result.getTlsVersion());
        log.getLogger().info("Cipher Suite: " + result.getCipherSuite());
        log.getLogger().info("Key Exchange: " + result.getKeyExchangeType() + " (" + result.getKeyExchangeAlgorithm() + ")");
        log.getLogger().info("Overall Status: " + result.getOverallStatus());
        log.getLogger().info("========================================");
    }

    @Test
    void testComprehensiveScan() throws Exception {
        PQCScanOptions options = PQCScanOptions.builder()
                .checkRevocation(true)
                .revocationTimeoutMs(10000)
                .enumerateCiphers(true)
                .testProtocolVersions(true)
                .testTLS10(true)
                .testTLS11(true)
                .testSSLv3(false)
                .build();

        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<PQCScanResult> resultRef = new AtomicReference<>();

        IPAddress address = new IPAddress("google.com", 443);
        ScannerMotherCallback mother = new ScannerMotherCallback(address, result -> {
            log.getLogger().info("Comprehensive scan result:\n" + result);
            resultRef.set(result);
            latch.countDown();
        }, options, httpNIOSocket);
        mother.dnsResolver(DNSRegistrar.SINGLETON);
        mother.timeoutInSec(60);
        mother.start();

        boolean completed = latch.await(90, TimeUnit.SECONDS);
        assertTrue(completed, "Scan should complete within timeout");

        PQCScanResult result = resultRef.get();
        assertNotNull(result, "Result should not be null");
        assertTrue(result.isSuccess(), "Scan should succeed: " + result.getErrorMessage());
        assertNotNull(result.getTlsVersion(), "TLS version should be captured");
        assertNotNull(result.getCipherSuite(), "Cipher suite should be captured");

        log.getLogger().info("========== Comprehensive Scan Result ==========");
        log.getLogger().info("Host: " + result.getHost() + ":" + result.getPort());
        log.getLogger().info("TLS Version: " + result.getTlsVersion());
        log.getLogger().info("Cipher Suite: " + result.getCipherSuite());
        log.getLogger().info("Key Exchange: " + result.getKeyExchangeType() + " (" + result.getKeyExchangeAlgorithm() + ")");

        // Revocation
        log.getLogger().info("Revocation Method: " + result.getRevocationMethod());
        log.getLogger().info("Cert Revoked: " + result.isCertRevoked());

        // Ciphers
        if (result.getSupportedCipherSuites() != null) {
            log.getLogger().info("Supported Cipher Suites: " + result.getSupportedCipherSuites().size());
            for (CipherSuiteEnumerator.CipherInfo cipher : result.getSupportedCipherSuites()) {
                log.getLogger().info("  - " + cipher.getName() + " [" + cipher.getStrength() + "]");
            }
            log.getLogger().info("Server Cipher Preference: " + result.getServerCipherPreference());
        }

        // Versions
        if (result.getSupportedProtocolVersions() != null) {
            log.getLogger().info("Supported Protocol Versions: " + result.getSupportedProtocolVersions());
            log.getLogger().info("SSLv3 Supported: " + result.isSslv3Supported());
            log.getLogger().info("Deprecated Protocols: " + result.isDeprecatedProtocolsSupported());
        }

        log.getLogger().info("Overall Status: " + result.getOverallStatus());
        log.getLogger().info("Recommendations: " + result.getRecommendations());
        log.getLogger().info("=================================================");
    }

    @Test
    void testRevocationOnly() throws Exception {
        PQCScanOptions options = PQCScanOptions.builder()
                .checkRevocation(true)
                .revocationTimeoutMs(15000)
                .build();

        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<PQCScanResult> resultRef = new AtomicReference<>();

        IPAddress address = new IPAddress("cloudflare.com", 443);
        ScannerMotherCallback mother = new ScannerMotherCallback(address, result -> {
            resultRef.set(result);
            latch.countDown();
        }, options, httpNIOSocket);
        mother.dnsResolver(DNSRegistrar.SINGLETON);
        mother.timeoutInSec(30);
        mother.start();

        boolean completed = latch.await(45, TimeUnit.SECONDS);
        assertTrue(completed, "Scan should complete within timeout");

        PQCScanResult result = resultRef.get();
        assertNotNull(result, "Result should not be null");
        assertTrue(result.isSuccess(), "Scan should succeed: " + result.getErrorMessage());

        log.getLogger().info("=== Revocation Only Results ===");
        log.getLogger().info("Host: " + result.getHost());
        log.getLogger().info("Revocation Method: " + result.getRevocationMethod());
        log.getLogger().info("Cert Revoked: " + result.isCertRevoked());
    }

    @Test
    void testNonTLSPort() throws Exception {
        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<PQCScanResult> resultRef = new AtomicReference<>();

        IPAddress address = new IPAddress("google.com", 80);
        ScannerMotherCallback mother = new ScannerMotherCallback(address, result -> {
            log.getLogger().info("Port 80 scan result:\n" + result);
            resultRef.set(result);
            latch.countDown();
        }, null, httpNIOSocket);
        mother.dnsResolver(DNSRegistrar.SINGLETON);
        mother.timeoutInSec(10);
        mother.start();

        boolean completed = latch.await(15, TimeUnit.SECONDS);
        assertTrue(completed, "Scan should complete within timeout");

        PQCScanResult result = resultRef.get();
        assertNotNull(result, "Result should not be null");
        assertFalse(result.isSuccess(), "Scan should fail on non-TLS port");
        assertFalse(result.isSecure(), "Port 80 should not be secure");
        assertNotNull(result.getErrorMessage(), "Error message should be present");

        log.getLogger().info("testNonTLSPort passed - port 80 correctly identified as non-secure");
    }

    @Test
    void testMultipleTargets() throws Exception {
        long overAllTS = System.currentTimeMillis();
        AtomicInteger counter = new AtomicInteger();

        for (IPAddress address : serversToTest) {
            log.getLogger().info("Scanning: " + address);

            long ts = System.currentTimeMillis();
            ScannerMotherCallback mother = new ScannerMotherCallback(address, result -> {
                log.getLogger().info("Result for " + result.getHost() + ":" + result.getPort() +
                        " - " + result.getOverallStatus() + " in " +
                        Const.TimeInMillis.toString(System.currentTimeMillis() - ts));
                counter.incrementAndGet();
            }, null, httpNIOSocket);
            mother.dnsResolver(DNSRegistrar.SINGLETON);
            mother.timeoutInSec(5);

            try {
                mother.start();
            } catch (IOException e) {
                counter.incrementAndGet();
                log.getLogger().info(e + " " + Const.TimeInMillis.toString(System.currentTimeMillis() - ts));
            }
        }

        while (counter.get() < serversToTest.length)
            TaskUtil.sleep(25);

        log.getLogger().info("========== Multiple Targets Result ==========  took overAll: " +
                Const.TimeInMillis.toString(System.currentTimeMillis() - overAllTS));
    }

    @AfterAll
    static void tearDownAll() {
        IOUtil.close(httpNIOSocket.getNIOSocket());
        TaskUtil.close();
    }
}
