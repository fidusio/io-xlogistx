package io.xlogistx.mcp.services;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import io.xlogistx.http.NIOHTTPServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.zoxweb.server.security.HashUtil;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.shared.http.HTTPServerConfig;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.ServerSocket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

/**
 * End to end: the real {@link NIOHTTPServer} with Shiro, the {@link MCPEndpoint} mapped from
 * the server configuration, and plain HTTP requests.
 */
public class MCPEndpointHTTPTest {

    private static final String PASSWORD = "Mcp-Test-Pa55word!";
    private static final String MODERN = "2026-07-28";

    @TempDir
    static Path work;

    private static NIOHTTPServer server;
    private static int port;
    private static Path root;

    @BeforeAll
    public static void start() throws Exception {
        // HttpURLConnection silently drops a restricted header such as Origin without this
        System.setProperty("sun.net.http.allowRestrictedHeaders", "true");
        root = Files.createDirectories(work.resolve("root"));
        Files.write(root.resolve("hello.txt"), "hello mcp\n".getBytes(StandardCharsets.UTF_8));

        String hash = HashUtil.toBCryptPassword(PASSWORD, 4).getCanonicalID();
        Path users = work.resolve("users.ini");
        Files.write(users, ("[users]\n"
                + "mcp-user = " + hash + ", mcp\n"
                + "other-user = " + hash + ", device\n"
                + "[roles]\n"
                + "mcp = mcp:access\n"
                + "device = device:ping\n").getBytes(StandardCharsets.UTF_8));
        Path shiro = work.resolve("shiro.ini");
        Files.write(shiro, ("[main]\n"
                + "iniRealm = io.xlogistx.shiro.XlogistXIniRealm\n"
                + "iniRealm.resourcePath = file:" + slashes(users) + "\n"
                + "iniRealm.name = mcp-test-realm\n"
                + "credentialsMatcher = io.xlogistx.shiro.authc.CredentialsInfoMatcher\n"
                + "iniRealm.credentialsMatcher = $credentialsMatcher\n"
                + "securityManager.realm = $iniRealm\n").getBytes(StandardCharsets.UTF_8));

        try (ServerSocket s = new ServerSocket(0)) {
            port = s.getLocalPort();
        }

        String config = ("{"
                + "'name':'mcp-test','thread_pool_size':8,'tls_only':false,"
                + "'properties':{"
                + "  'shiro':{'config':'file:" + slashes(shiro) + "'},"
                + "  'keep-alive':{'time_out':'5s','maximum':100}"
                + "},"
                + "'connections':[{'name':'http','schemes':['http'],'socket_config':{'port':" + port + ",'backlog':64}}],"
                + "'endpoints':[{'bean':'io.xlogistx.mcp.services.MCPEndpoint',"
                + "  'properties':{'roots':['" + slashes(root) + "'],'read-only':false,'allowed-origins':['https://trusted.example']}}]"
                + "}").replace('\'', '"');

        HTTPServerConfig hsc = GSONUtil.fromJSON(config, HTTPServerConfig.class);
        server = new NIOHTTPServer(hsc);
        server.start();
    }

    @AfterAll
    public static void stop() throws IOException {
        if (server != null)
            server.close();
    }

    private static String slashes(Path p) {
        return p.toAbsolutePath().toString().replace('\\', '/');
    }

    private static final class Resp {
        final int status;
        final String body;

        Resp(int status, String body) {
            this.status = status;
            this.body = body;
        }

        JsonObject json() {
            return JsonParser.parseString(body).getAsJsonObject();
        }

        @Override
        public String toString() {
            return status + " " + body;
        }
    }

    private static Resp send(String method, String user, String body, String... headers) throws IOException {
        HttpURLConnection c = (HttpURLConnection) new URL("http://127.0.0.1:" + port + "/mcp").openConnection();
        c.setRequestMethod(method);
        c.setConnectTimeout(5000);
        c.setReadTimeout(10000);
        if (user != null)
            c.setRequestProperty("Authorization", "Basic " + Base64.getEncoder()
                    .encodeToString((user + ":" + PASSWORD).getBytes(StandardCharsets.UTF_8)));
        c.setRequestProperty("Accept", "application/json, text/event-stream");
        for (int i = 0; i < headers.length; i += 2)
            c.setRequestProperty(headers[i], headers[i + 1]);
        if (body != null) {
            byte[] bytes = body.replace('\'', '"').getBytes(StandardCharsets.UTF_8);
            c.setDoOutput(true);
            c.setRequestProperty("Content-Type", "application/json");
            try (OutputStream os = c.getOutputStream()) {
                os.write(bytes);
            }
        }
        int status = c.getResponseCode();
        InputStream in = status < 400 ? c.getInputStream() : c.getErrorStream();
        String text = "";
        if (in != null) {
            try (InputStream is = in) {
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                byte[] buf = new byte[4096];
                int n;
                while ((n = is.read(buf)) > 0)
                    bos.write(buf, 0, n);
                text = new String(bos.toByteArray(), StandardCharsets.UTF_8);
            }
        }
        c.disconnect();
        return new Resp(status, text);
    }

    @Test
    public void legacyInitialize() throws IOException {
        Resp r = send("POST", "mcp-user", "{'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-11-25','capabilities':{},'clientInfo':{'name':'t','version':'1'}}}");
        assertEquals(200, r.status, r.toString());
        assertEquals("2025-11-25", r.json().getAsJsonObject("result").get("protocolVersion").getAsString());
    }

    @Test
    public void aNotificationGets202WithNoBody() throws IOException {
        Resp r = send("POST", "mcp-user", "{'jsonrpc':'2.0','method':'notifications/initialized'}");
        assertEquals(202, r.status, r.toString());
        assertEquals("", r.body);
    }

    @Test
    public void modernToolCallReadsAFileInsideTheRoot() throws IOException {
        String body = "{'jsonrpc':'2.0','id':2,'method':'tools/call','params':{'name':'read_file','arguments':{'path':'hello.txt'},"
                + "'_meta':{'io.modelcontextprotocol/protocolVersion':'" + MODERN + "'}}}";
        Resp r = send("POST", "mcp-user", body,
                "MCP-Protocol-Version", MODERN, "Mcp-Method", "tools/call", "Mcp-Name", "read_file");
        assertEquals(200, r.status, r.toString());
        JsonObject result = r.json().getAsJsonObject("result");
        assertFalse(result.get("isError").getAsBoolean(), r.toString());
        assertEquals("hello mcp\n", result.getAsJsonArray("content").get(0).getAsJsonObject().get("text").getAsString());
    }

    @Test
    public void modernHeaderMismatchIs400() throws IOException {
        String body = "{'jsonrpc':'2.0','id':3,'method':'tools/list','params':{'_meta':{'io.modelcontextprotocol/protocolVersion':'" + MODERN + "'}}}";
        Resp r = send("POST", "mcp-user", body, "MCP-Protocol-Version", MODERN, "Mcp-Method", "tools/call");
        assertEquals(400, r.status, r.toString());
        assertEquals(-32020, r.json().getAsJsonObject("error").get("code").getAsInt());
    }

    @Test
    public void noCredentialsIs401() throws IOException {
        assertEquals(401, send("POST", null, "{'jsonrpc':'2.0','id':4,'method':'ping'}").status);
    }

    @Test
    public void aUserWithoutTheMcpPermissionIsRefused() throws IOException {
        Resp r = send("POST", "other-user", "{'jsonrpc':'2.0','id':5,'method':'ping'}");
        assertEquals(401, r.status, r.toString());
    }

    @Test
    public void anUnknownOriginIs403AndATrustedOneIsServed() throws IOException {
        assertEquals(403, send("POST", "mcp-user", "{'jsonrpc':'2.0','id':6,'method':'ping'}", "Origin", "https://evil.example").status);
        assertEquals(200, send("POST", "mcp-user", "{'jsonrpc':'2.0','id':7,'method':'ping'}", "Origin", "https://trusted.example").status);
    }

    @Test
    public void getIs405() throws IOException {
        assertEquals(405, send("GET", "mcp-user", null).status);
    }
}
