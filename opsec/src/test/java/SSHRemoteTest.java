import io.xlogistx.opsec.SSHRemote;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.zoxweb.shared.security.SShURI;
import org.zoxweb.shared.util.SUS;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link SSHRemote}.
 *
 * <p>{@code SSHRemote} is a {@code main}-only CLI utility: it parses arguments, resolves an optional
 * PEM key, parses the {@code ssh-uris} list into {@link SShURI}s, and for each host decides whether to
 * authenticate with a key, a password/credential, or to skip the host when no credential is available.
 * The actual {@code OPSecUtil.sshCommand(...)} calls open real SSH sockets, so they are not exercised
 * here. Instead these tests pin down the two deterministic, network-free surfaces SSHRemote is built on:</p>
 *
 * <ol>
 *   <li>The {@link SShURI#parse(String)} contract that drives SSHRemote's credential-vs-key branching.</li>
 *   <li>{@link SSHRemote#main(String...)} error handling and the "no credentials" branch, which never
 *       touch the network and must not let exceptions escape (every failure is caught and reported).</li>
 * </ol>
 */
public class SSHRemoteTest {

    private static final String UTF_8 = "UTF-8";

    private PrintStream originalOut;
    private PrintStream originalErr;
    private ByteArrayOutputStream outBuf;
    private ByteArrayOutputStream errBuf;

    @BeforeEach
    public void redirectStreams() throws UnsupportedEncodingException {
        originalOut = System.out;
        originalErr = System.err;
        outBuf = new ByteArrayOutputStream();
        errBuf = new ByteArrayOutputStream();
        System.setOut(new PrintStream(outBuf, true, UTF_8));
        System.setErr(new PrintStream(errBuf, true, UTF_8));
    }

    @AfterEach
    public void restoreStreams() {
        System.setOut(originalOut);
        System.setErr(originalErr);
    }

    private String out() {
        try {
            return outBuf.toString(UTF_8);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    private String err() {
        try {
            return errBuf.toString(UTF_8);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    // ------------------------------------------------------------------
    // SShURI parsing — the input contract SSHRemote relies on
    // ------------------------------------------------------------------

    @Test
    @DisplayName("user:password@host -> credential present (password branch), default port 22")
    public void parse_userPasswordHost() {
        SShURI uri = SShURI.parse("root:secret@192.168.1.1");

        assertEquals("root", uri.subject);
        assertEquals("secret", uri.credential);
        assertEquals("192.168.1.1", uri.host);
        assertEquals(22, uri.port);
        // SSHRemote uses !SUS.isEmpty(credential) to pick the password-auth path.
        assertFalse(SUS.isEmpty(uri.credential));
    }

    @Test
    @DisplayName("user@host:port -> no credential (key branch), custom port")
    public void parse_userHostPort_noCredential() {
        SShURI uri = SShURI.parse("root@google.com:2022");

        assertEquals("root", uri.subject);
        assertNull(uri.credential);
        assertEquals("google.com", uri.host);
        assertEquals(2022, uri.port);
        // SSHRemote uses SUS.isEmpty(credential) && keys != null to pick the key-auth path.
        assertTrue(SUS.isEmpty(uri.credential));
    }

    @Test
    @DisplayName("user@host -> no credential, default port 22")
    public void parse_userHost_defaultPort() {
        SShURI uri = SShURI.parse("root@example.com");

        assertEquals("root", uri.subject);
        assertNull(uri.credential);
        assertEquals("example.com", uri.host);
        assertEquals(22, uri.port);
    }

    @Test
    @DisplayName("password containing '@' is split at the LAST '@'")
    public void parse_passwordWithAtSign() {
        SShURI uri = SShURI.parse("root:p@ss@host.com:2200");

        assertEquals("root", uri.subject);
        assertEquals("p@ss", uri.credential);
        assertEquals("host.com", uri.host);
        assertEquals(2200, uri.port);
    }

    @Test
    @DisplayName("bracketed IPv6 with port")
    public void parse_ipv6Bracketed() {
        SShURI uri = SShURI.parse("root@[fe80::1]:2022");

        assertEquals("root", uri.subject);
        assertEquals("fe80::1", uri.host);
        assertEquals(2022, uri.port);
        assertFalse(uri.ipV4);
    }

    @Test
    @DisplayName("bare unbracketed IPv6 (multiple colons) is treated entirely as host, default port")
    public void parse_ipv6BareNoPort() {
        SShURI uri = SShURI.parse("root@fe80::1");

        assertEquals("fe80::1", uri.host);
        assertEquals(22, uri.port);
        assertFalse(uri.ipV4);
    }

    @ParameterizedTest
    @DisplayName("malformed URIs throw IllegalArgumentException")
    @ValueSource(strings = {
            "",                 // empty
            "   ",              // blank
            "no-at-sign",       // missing '@'
            "root@",            // missing host
            "@host.com",        // missing user
            "root@host:0",      // port below range
            "root@host:70000",  // port above range
            "root@host:abc"     // non-numeric port
    })
    public void parse_invalidThrows(String bad) {
        assertThrows(IllegalArgumentException.class, () -> SShURI.parse(bad));
    }

    @Test
    @DisplayName("null URI throws IllegalArgumentException")
    public void parse_nullThrows() {
        assertThrows(IllegalArgumentException.class, () -> SShURI.parse(null));
    }

    // ------------------------------------------------------------------
    // SSHRemote.main — deterministic, network-free behavior
    // ------------------------------------------------------------------

    @Test
    @DisplayName("missing required args: usage is printed and no exception escapes main")
    public void main_missingArgs_printsUsage() {
        // Required 'ssh-uris' is absent -> stringValue(...) throws -> caught by main -> usage printed.
        assertDoesNotThrow(() -> SSHRemote.main());
        assertTrue(err().contains("Usage:"), "expected usage banner on stderr, got: " + err());
    }

    @Test
    @DisplayName("missing 'command' arg: usage is printed and no exception escapes main")
    public void main_missingCommand_printsUsage() {
        assertDoesNotThrow(() -> SSHRemote.main("ssh-uris=root@example.com"));
        assertTrue(err().contains("Usage:"), "expected usage banner on stderr, got: " + err());
    }

    @Test
    @DisplayName("host with no credential and no pem: reported as 'no credentials', no network, no throw")
    public void main_noCredentialNoKey_skipsHost() {
        assertDoesNotThrow(() ->
                SSHRemote.main("ssh-uris=root@example.com", "command=ls"));

        String out = out();
        assertTrue(out.contains("has no credentials"),
                "expected 'has no credentials' on stdout, got: " + out);
        // The argument echo line is always printed before the per-host loop.
        assertTrue(out.contains("sshURIs:"), "expected parsed sshURIs echo, got: " + out);
        // Nothing fatal should have reached stderr.
        assertFalse(err().contains("Usage:"), "did not expect usage banner, got: " + err());
    }

    @Test
    @DisplayName("multiple credential-less hosts are each reported and the run completes")
    public void main_multipleNoCredentialHosts() {
        assertDoesNotThrow(() ->
                SSHRemote.main("ssh-uris=root@a.example.com,admin@b.example.com:2222", "command=uptime"));

        String out = out();
        int occurrences = out.split("has no credentials", -1).length - 1;
        assertEquals(2, occurrences, "expected both hosts reported as credential-less, got: " + out);
    }

    @Test
    @DisplayName("a malformed URI in the list aborts parsing before any host loop runs")
    public void main_malformedUriInList_printsUsage() {
        // SShURI.parse throws inside main's outer try (before the per-host loop), so usage is printed
        // and no host is contacted.
        assertDoesNotThrow(() ->
                SSHRemote.main("ssh-uris=root@example.com,not-a-valid-uri", "command=ls"));
        assertTrue(err().contains("Usage:"), "expected usage banner on stderr, got: " + err());
        assertFalse(out().contains("has no credentials"),
                "host loop should not have produced output, got: " + out());
    }
}
