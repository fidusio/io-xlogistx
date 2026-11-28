package io.xlogistx.mcp;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Protocol constants for the Model Context Protocol (MCP) over JSON-RPC 2.0.
 * <p>
 * The server is dual-era:
 * <ul>
 *   <li><b>Modern</b> (2026-07-28 and later): stateless, every request carries its protocol
 *   version in {@code params._meta}, and on HTTP the {@code MCP-Protocol-Version},
 *   {@code Mcp-Method} and {@code Mcp-Name} headers mirror the body.</li>
 *   <li><b>Legacy</b> (2025-11-25 and earlier): the client opens with {@code initialize}.
 *   This server mints no session id, which the legacy revisions allow.</li>
 * </ul>
 */
public final class MCPConst {

    private MCPConst() {
    }

    public static final String JSONRPC_VERSION = "2.0";

    /** Modern, per-request-metadata protocol versions, newest first. */
    public static final List<String> MODERN_VERSIONS = Collections.unmodifiableList(Arrays.asList(
            "2026-07-28"));

    /** Legacy, initialize-handshake protocol versions, newest first. */
    public static final List<String> LEGACY_VERSIONS = Collections.unmodifiableList(Arrays.asList(
            "2025-11-25",
            "2025-06-18",
            "2025-03-26"));

    /** Everything this server speaks, newest first; reported by server/discover and version errors. */
    public static final List<String> SUPPORTED_VERSIONS;

    static {
        java.util.ArrayList<String> all = new java.util.ArrayList<>(MODERN_VERSIONS);
        all.addAll(LEGACY_VERSIONS);
        SUPPORTED_VERSIONS = Collections.unmodifiableList(all);
    }

    /** JSON-RPC methods. */
    public static final class Method {
        private Method() {
        }

        public static final String INITIALIZE = "initialize";
        public static final String PING = "ping";
        public static final String SERVER_DISCOVER = "server/discover";
        public static final String TOOLS_LIST = "tools/list";
        public static final String TOOLS_CALL = "tools/call";
        public static final String RESOURCES_READ = "resources/read";
        public static final String PROMPTS_GET = "prompts/get";
    }

    /** {@code _meta} keys. */
    public static final class Meta {
        private Meta() {
        }

        public static final String META = "_meta";
        public static final String PROTOCOL_VERSION = "io.modelcontextprotocol/protocolVersion";
        public static final String CLIENT_INFO = "io.modelcontextprotocol/clientInfo";
        public static final String SERVER_INFO = "io.modelcontextprotocol/serverInfo";
    }

    /** Streamable HTTP request headers (names are case-insensitive). */
    public static final class Header {
        private Header() {
        }

        public static final String PROTOCOL_VERSION = "MCP-Protocol-Version";
        public static final String METHOD = "Mcp-Method";
        public static final String NAME = "Mcp-Name";
        public static final String ORIGIN = "Origin";
    }

    /** JSON-RPC and MCP error codes. */
    public static final class ErrorCode {
        private ErrorCode() {
        }

        public static final int PARSE_ERROR = -32700;
        public static final int INVALID_REQUEST = -32600;
        public static final int METHOD_NOT_FOUND = -32601;
        public static final int INVALID_PARAMS = -32602;
        public static final int INTERNAL_ERROR = -32603;
        /** Headers missing or not matching the body (2026-07-28). */
        public static final int HEADER_MISMATCH = -32020;
        /** Requested protocol version not implemented (2026-07-28). */
        public static final int UNSUPPORTED_PROTOCOL_VERSION = -32022;
    }

    /** Prefix and suffix of the Base64 sentinel encoding for header values. */
    public static final String BASE64_SENTINEL_PREFIX = "=?base64?";
    public static final String BASE64_SENTINEL_SUFFIX = "?=";

    /** How long a client may cache tools/list (modern revision), in milliseconds. */
    public static final long TOOLS_LIST_TTL_MS = 5 * 60 * 1000L;
}
