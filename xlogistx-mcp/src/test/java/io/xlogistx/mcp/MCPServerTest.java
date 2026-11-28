package io.xlogistx.mcp;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;
import org.zoxweb.shared.util.NVGenericMap;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Protocol behaviour of {@link MCPServer}. Replies are checked with plain Gson so the test sees
 * the exact wire format GSONUtil produced.
 */
public class MCPServerTest {

    private static final String MODERN = "2026-07-28";

    private static MCPServer server() {
        MCPServer s = new MCPServer("test-server", "9.9", "use echo");
        s.register(new MCPTool() {
            public String getName() {
                return "echo";
            }

            public String getDescription() {
                return "Echo the text back";
            }

            public NVGenericMap inputSchema() {
                return SchemaBuilder.object().string("text", "Text to echo", true).build();
            }

            public boolean isReadOnly() {
                return true;
            }

            public String call(NVGenericMap arguments) {
                return "echo: " + ToolArgs.requiredString(arguments, "text");
            }
        });
        s.register(new MCPTool() {
            public String getName() {
                return "boom";
            }

            public String getDescription() {
                return "Always fails";
            }

            public NVGenericMap inputSchema() {
                return SchemaBuilder.object().build();
            }

            public boolean isReadOnly() {
                return false;
            }

            public String call(NVGenericMap arguments) {
                throw new IllegalArgumentException("bad input");
            }
        });
        return s;
    }

    /** Single quotes in the test JSON become double quotes. */
    private static byte[] b(String json) {
        return json.replace('\'', '"').getBytes(StandardCharsets.UTF_8);
    }

    private static MCPServer.Headers headers(String... kv) {
        final Map<String, String> m = new HashMap<>();
        for (int i = 0; i < kv.length; i += 2)
            m.put(kv[i].toLowerCase(Locale.ROOT), kv[i + 1]);
        return new MCPServer.Headers() {
            public String get(String name) {
                return m.get(name.toLowerCase(Locale.ROOT));
            }
        };
    }

    private static JsonObject json(MCPServer.Reply r) {
        assertNotNull(r.body, "expected a body: " + r);
        return JsonParser.parseString(r.body).getAsJsonObject();
    }

    private static String meta() {
        return "'_meta':{'io.modelcontextprotocol/protocolVersion':'" + MODERN + "','io.modelcontextprotocol/clientInfo':{'name':'t','version':'1'}}";
    }

    private static MCPServer.Headers modernHeaders(String method, String name) {
        return name == null
                ? headers("MCP-Protocol-Version", MODERN, "Mcp-Method", method)
                : headers("MCP-Protocol-Version", MODERN, "Mcp-Method", method, "Mcp-Name", name);
    }

    // ---- legacy ----

    @Test
    public void legacyInitializeNegotiatesARequestedLegacyVersion() {
        MCPServer.Reply r = server().handle(b("{'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-06-18','capabilities':{},'clientInfo':{'name':'c','version':'1'}}}"), headers());
        assertEquals(200, r.status);
        JsonObject o = json(r);
        assertEquals("2.0", o.get("jsonrpc").getAsString());
        assertEquals(1, o.get("id").getAsInt());
        JsonObject result = o.getAsJsonObject("result");
        assertEquals("2025-06-18", result.get("protocolVersion").getAsString());
        assertFalse(result.getAsJsonObject("capabilities").getAsJsonObject("tools").get("listChanged").getAsBoolean(),
                "false must be written, not dropped");
        assertEquals("test-server", result.getAsJsonObject("serverInfo").get("name").getAsString());
        assertEquals("use echo", result.get("instructions").getAsString());
    }

    @Test
    public void legacyInitializeFallsBackToTheNewestLegacyVersion() {
        JsonObject o = json(server().handle(b("{'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2024-11-05'}}"), headers()));
        assertEquals("2025-11-25", o.getAsJsonObject("result").get("protocolVersion").getAsString());
    }

    @Test
    public void aNotificationIsAcceptedWithNoBody() {
        MCPServer.Reply r = server().handle(b("{'jsonrpc':'2.0','method':'notifications/initialized'}"), headers());
        assertEquals(202, r.status);
        assertNull(r.body);
    }

    @Test
    public void legacyToolsListIsSortedAndCarriesSchemasAndAnnotations() {
        JsonObject result = json(server().handle(b("{'jsonrpc':'2.0','id':2,'method':'tools/list'}"), headers())).getAsJsonObject("result");
        JsonArray tools = result.getAsJsonArray("tools");
        assertEquals(2, tools.size());
        assertEquals("boom", tools.get(0).getAsJsonObject().get("name").getAsString());
        JsonObject echo = tools.get(1).getAsJsonObject();
        assertEquals("echo", echo.get("name").getAsString());
        JsonObject schema = echo.getAsJsonObject("inputSchema");
        assertEquals("object", schema.get("type").getAsString());
        assertEquals("string", schema.getAsJsonObject("properties").getAsJsonObject("text").get("type").getAsString());
        assertEquals("text", schema.getAsJsonArray("required").get(0).getAsString());
        assertTrue(echo.getAsJsonObject("annotations").get("readOnlyHint").getAsBoolean());
        assertTrue(tools.get(0).getAsJsonObject().getAsJsonObject("annotations").get("destructiveHint").getAsBoolean());
        assertFalse(result.has("ttlMs"), "cache hints are modern-only");
        assertTrue(tools.get(0).getAsJsonObject().getAsJsonObject("inputSchema").getAsJsonObject("properties").entrySet().isEmpty());
    }

    @Test
    public void legacyToolsCallEchoesAStringIdAndReturnsTextContent() {
        JsonObject o = json(server().handle(b("{'jsonrpc':'2.0','id':'abc','method':'tools/call','params':{'name':'echo','arguments':{'text':'hi'}}}"), headers()));
        assertEquals("abc", o.get("id").getAsString());
        JsonObject result = o.getAsJsonObject("result");
        JsonObject item = result.getAsJsonArray("content").get(0).getAsJsonObject();
        assertEquals("text", item.get("type").getAsString());
        assertEquals("echo: hi", item.get("text").getAsString());
        assertFalse(result.get("isError").getAsBoolean());
        assertFalse(result.has("resultType"));
    }

    @Test
    public void textSurvivesTheRoundTripExactly() {
        String text = "quote \\\" back\\\\slash new\\nline café 1.50 true 0042";
        JsonObject o = json(server().handle(b("{'jsonrpc':'2.0','id':3,'method':'tools/call','params':{'name':'echo','arguments':{'text':'" + text + "'}}}"), headers()));
        assertEquals("echo: quote \" back\\slash new\nline café 1.50 true 0042",
                o.getAsJsonObject("result").getAsJsonArray("content").get(0).getAsJsonObject().get("text").getAsString());
    }

    @Test
    public void aToolFailureIsAToolErrorNotAProtocolError() {
        MCPServer.Reply r = server().handle(b("{'jsonrpc':'2.0','id':4,'method':'tools/call','params':{'name':'boom','arguments':{}}}"), headers());
        assertEquals(200, r.status);
        JsonObject result = json(r).getAsJsonObject("result");
        assertTrue(result.get("isError").getAsBoolean());
        assertEquals("bad input", result.getAsJsonArray("content").get(0).getAsJsonObject().get("text").getAsString());
    }

    @Test
    public void anUnknownToolIsInvalidParams() {
        JsonObject o = json(server().handle(b("{'jsonrpc':'2.0','id':5,'method':'tools/call','params':{'name':'nope'}}"), headers()));
        assertEquals(MCPConst.ErrorCode.INVALID_PARAMS, o.getAsJsonObject("error").get("code").getAsInt());
    }

    @Test
    public void legacyPingAndUnknownMethod() {
        JsonObject ping = json(server().handle(b("{'jsonrpc':'2.0','id':6,'method':'ping'}"), headers()));
        assertTrue(ping.getAsJsonObject("result").entrySet().isEmpty());

        MCPServer.Reply r = server().handle(b("{'jsonrpc':'2.0','id':7,'method':'prompts/list'}"), headers());
        assertEquals(200, r.status);
        assertEquals(MCPConst.ErrorCode.METHOD_NOT_FOUND, json(r).getAsJsonObject("error").get("code").getAsInt());
    }

    // ---- modern ----

    @Test
    public void modernToolsCallWithMatchingHeaders() {
        MCPServer.Reply r = server().handle(
                b("{'jsonrpc':'2.0','id':10,'method':'tools/call','params':{'name':'echo','arguments':{'text':'yo'}," + meta() + "}}"),
                modernHeaders("tools/call", "echo"));
        assertEquals(200, r.status, r.toString());
        JsonObject result = json(r).getAsJsonObject("result");
        assertEquals("echo: yo", result.getAsJsonArray("content").get(0).getAsJsonObject().get("text").getAsString());
        assertEquals("complete", result.get("resultType").getAsString());
        assertEquals("test-server", result.getAsJsonObject("_meta")
                .getAsJsonObject("io.modelcontextprotocol/serverInfo").get("name").getAsString());
    }

    @Test
    public void modernNameHeaderMayUseTheBase64Sentinel() {
        String encoded = "=?base64?" + Base64.getEncoder().encodeToString("echo".getBytes(StandardCharsets.UTF_8)) + "?=";
        MCPServer.Reply r = server().handle(
                b("{'jsonrpc':'2.0','id':11,'method':'tools/call','params':{'name':'echo','arguments':{'text':'x'}," + meta() + "}}"),
                modernHeaders("tools/call", encoded));
        assertEquals(200, r.status, r.toString());
    }

    @Test
    public void modernHeaderMismatchIs400() {
        MCPServer.Reply wrongName = server().handle(
                b("{'jsonrpc':'2.0','id':12,'method':'tools/call','params':{'name':'echo','arguments':{'text':'x'}," + meta() + "}}"),
                modernHeaders("tools/call", "other"));
        assertEquals(400, wrongName.status);
        assertEquals(MCPConst.ErrorCode.HEADER_MISMATCH, json(wrongName).getAsJsonObject("error").get("code").getAsInt());

        MCPServer.Reply noMethod = server().handle(
                b("{'jsonrpc':'2.0','id':13,'method':'tools/list','params':{" + meta() + "}}"),
                headers("MCP-Protocol-Version", MODERN));
        assertEquals(400, noMethod.status);
        assertEquals(MCPConst.ErrorCode.HEADER_MISMATCH, json(noMethod).getAsJsonObject("error").get("code").getAsInt());
    }

    @Test
    public void aModernHeaderWithoutMetaIsAMismatch() {
        MCPServer.Reply r = server().handle(b("{'jsonrpc':'2.0','id':14,'method':'tools/list'}"),
                headers("MCP-Protocol-Version", MODERN, "Mcp-Method", "tools/list"));
        assertEquals(400, r.status);
        assertEquals(MCPConst.ErrorCode.HEADER_MISMATCH, json(r).getAsJsonObject("error").get("code").getAsInt());
    }

    @Test
    public void anUnsupportedVersionListsTheSupportedOnes() {
        String body = "{'jsonrpc':'2.0','id':15,'method':'tools/list','params':{'_meta':{'io.modelcontextprotocol/protocolVersion':'1900-01-01'}}}";
        MCPServer.Reply r = server().handle(b(body), headers("MCP-Protocol-Version", "1900-01-01", "Mcp-Method", "tools/list"));
        assertEquals(400, r.status);
        JsonObject error = json(r).getAsJsonObject("error");
        assertEquals(MCPConst.ErrorCode.UNSUPPORTED_PROTOCOL_VERSION, error.get("code").getAsInt());
        assertEquals("1900-01-01", error.getAsJsonObject("data").get("requested").getAsString());
        assertEquals(MODERN, error.getAsJsonObject("data").getAsJsonArray("supported").get(0).getAsString());
    }

    @Test
    public void aModernUnknownMethodIs404() {
        MCPServer.Reply r = server().handle(b("{'jsonrpc':'2.0','id':16,'method':'resources/list','params':{" + meta() + "}}"),
                modernHeaders("resources/list", null));
        assertEquals(404, r.status);
        assertEquals(MCPConst.ErrorCode.METHOD_NOT_FOUND, json(r).getAsJsonObject("error").get("code").getAsInt());
    }

    @Test
    public void modernDiscover() {
        MCPServer.Reply r = server().handle(b("{'jsonrpc':'2.0','id':'d1','method':'server/discover','params':{" + meta() + "}}"),
                modernHeaders("server/discover", null));
        assertEquals(200, r.status, r.toString());
        JsonObject result = json(r).getAsJsonObject("result");
        assertEquals(MODERN, result.getAsJsonArray("supportedVersions").get(0).getAsString());
        assertTrue(result.getAsJsonObject("capabilities").has("tools"));
        assertEquals("complete", result.get("resultType").getAsString());
        assertEquals("use echo", result.get("instructions").getAsString());
    }

    @Test
    public void modernToolsListIsCacheable() {
        JsonObject result = json(server().handle(b("{'jsonrpc':'2.0','id':17,'method':'tools/list','params':{" + meta() + "}}"),
                modernHeaders("tools/list", null))).getAsJsonObject("result");
        assertEquals(MCPConst.TOOLS_LIST_TTL_MS, result.get("ttlMs").getAsLong());
        assertEquals("private", result.get("cacheScope").getAsString());
    }

    @Test
    public void withoutHeadersTheModernValidationIsSkipped() {
        MCPServer.Reply r = server().handle(
                b("{'jsonrpc':'2.0','id':18,'method':'tools/call','params':{'name':'echo','arguments':{'text':'x'}," + meta() + "}}"),
                null);
        assertEquals(200, r.status, r.toString());
    }

    // ---- malformed input ----

    @Test
    public void malformedBodies() {
        MCPServer.Reply parse = server().handle(b("{not json"), headers());
        assertEquals(400, parse.status);
        JsonObject o = json(parse);
        assertEquals(MCPConst.ErrorCode.PARSE_ERROR, o.getAsJsonObject("error").get("code").getAsInt());
        assertFalse(o.has("id"));

        MCPServer.Reply batch = server().handle(b("[{'jsonrpc':'2.0','id':1,'method':'ping'}]"), headers());
        assertEquals(400, batch.status);
        assertEquals(MCPConst.ErrorCode.INVALID_REQUEST, json(batch).getAsJsonObject("error").get("code").getAsInt());

        MCPServer.Reply version = server().handle(b("{'jsonrpc':'1.0','id':1,'method':'ping'}"), headers());
        assertEquals(400, version.status);

        MCPServer.Reply empty = server().handle(new byte[0], headers());
        assertEquals(400, empty.status);
    }

    @Test
    public void decodeSentinel() {
        assertEquals("plain", MCPServer.decodeSentinel("plain"));
        assertEquals("café", MCPServer.decodeSentinel("=?base64?" + Base64.getEncoder().encodeToString("café".getBytes(StandardCharsets.UTF_8)) + "?="));
    }
}
