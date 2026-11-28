package io.xlogistx.mcp;

import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.server.util.GSONUtil;
import org.zoxweb.shared.util.*;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AccessDeniedException;
import java.nio.file.DirectoryNotEmptyException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.NoSuchFileException;
import java.nio.file.NotDirectoryException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.TreeMap;

import static io.xlogistx.mcp.MCPConst.ErrorCode.*;

/**
 * Transport-agnostic MCP protocol core: one JSON-RPC message in, one {@link Reply} out.
 * <p>
 * Stateless: it holds the tool registry and nothing per client, so one instance serves every
 * connection, and the same instance can later sit behind a WebSocket relay. All JSON goes
 * through {@link GSONUtil} ({@code fromJSONGenericMap} / {@code toJSONGenericMap}); output is
 * written with {@code printNull=true} because without it GSONUtil drops {@code false} and
 * {@code 0}, and {@code "isError": false} must reach the client.
 */
public class MCPServer {

    public static final LogWrapper log = new LogWrapper(MCPServer.class).setEnabled(false);

    /** HTTP-style outcome: a status code and an optional JSON body. */
    public static final class Reply {
        public final int status;
        /** JSON text, or null when there is no body (202 Accepted). */
        public final String body;

        Reply(int status, String body) {
            this.status = status;
            this.body = body;
        }

        @Override
        public String toString() {
            return status + " " + body;
        }
    }

    /** Case-insensitive header lookup; returns null when the header is absent. */
    public interface Headers {
        String get(String name);
    }

    private final String name;
    private final String version;
    private final String instructions;
    // sorted: the modern revision asks for a deterministic tools/list order
    private final TreeMap<String, MCPTool> tools = new TreeMap<>();

    public MCPServer(String name, String version, String instructions) {
        this.name = name;
        this.version = version;
        this.instructions = instructions;
    }

    public synchronized MCPServer register(MCPTool tool) {
        if (tools.containsKey(tool.getName()))
            throw new IllegalArgumentException("Duplicate tool name: " + tool.getName());
        tools.put(tool.getName(), tool);
        return this;
    }

    public synchronized List<MCPTool> getTools() {
        return new ArrayList<>(tools.values());
    }

    private synchronized MCPTool lookupTool(String toolName) {
        return toolName == null ? null : tools.get(toolName);
    }

    public String getName() {
        return name;
    }

    public String getVersion() {
        return version;
    }

    /**
     * Process one message.
     *
     * @param body    the raw JSON-RPC message
     * @param headers the transport headers, or null for a transport without headers (the
     *                modern header-vs-body validation is then skipped)
     */
    public Reply handle(byte[] body, Headers headers) {
        NVGenericMap msg;
        try {
            msg = body == null || body.length == 0 ? null : GSONUtil.fromJSONGenericMap(body);
        } catch (Exception e) {
            return error(400, null, PARSE_ERROR, "Parse error: " + e.getMessage(), null, false);
        }
        if (msg == null)
            return error(400, null, INVALID_REQUEST, "The body must be a single JSON-RPC object", null, false);

        GetNameValue<?> id = msg.get("id");
        String method = str(msg.getValue("method"));

        if (method == null) {
            // a JSON-RPC response from the client: nothing to do with it
            if (msg.get("result") != null || msg.get("error") != null)
                return new Reply(202, null);
            return error(400, id, INVALID_REQUEST, "Missing method", null, false);
        }
        if (!MCPConst.JSONRPC_VERSION.equals(str(msg.getValue("jsonrpc"))))
            return error(400, id, INVALID_REQUEST, "jsonrpc must be \"2.0\"", null, false);

        NVGenericMap params = map(msg.get("params"));
        if (params == null)
            params = new NVGenericMap("params");

        // notification: accept and move on
        if (id == null)
            return new Reply(202, null);

        NVGenericMap meta = map(params.get(MCPConst.Meta.META));
        String requested = meta != null ? str(meta.getValue(MCPConst.Meta.PROTOCOL_VERSION)) : null;
        String headerVersion = header(headers, MCPConst.Header.PROTOCOL_VERSION);

        try {
            if (requested != null)
                return handleModern(id, method, params, requested, headers);

            // a modern header with no _meta version: the body and the header disagree
            if (headerVersion != null && MCPConst.MODERN_VERSIONS.contains(headerVersion))
                return error(400, id, HEADER_MISMATCH, "Header mismatch: " + MCPConst.Header.PROTOCOL_VERSION
                        + " is " + headerVersion + " but the body has no _meta protocol version", null, true);

            return handleLegacy(id, method, params);
        } catch (Exception e) {
            if (log.isEnabled()) log.getLogger().info("internal error " + e);
            return error(500, id, INTERNAL_ERROR, "Internal error: " + e, null, requested != null);
        }
    }

    // ---- modern (2026-07-28): stateless, version in _meta, headers mirrored ----

    private Reply handleModern(GetNameValue<?> id, String method, NVGenericMap params, String requested, Headers headers)
            throws IOException {
        if (!MCPConst.MODERN_VERSIONS.contains(requested)) {
            NVGenericMap data = new NVGenericMap("data");
            data.add(new NVStringList("supported", new ArrayList<>(MCPConst.SUPPORTED_VERSIONS)));
            data.add("requested", requested);
            return error(400, id, UNSUPPORTED_PROTOCOL_VERSION, "Unsupported protocol version", data, true);
        }

        String mismatch = validateHeaders(method, params, requested, headers);
        if (mismatch != null)
            return error(400, id, HEADER_MISMATCH, "Header mismatch: " + mismatch, null, true);

        switch (method) {
            case MCPConst.Method.SERVER_DISCOVER:
                return result(id, discoverResult(), true);
            case MCPConst.Method.TOOLS_LIST:
                return result(id, toolsListResult(true), true);
            case MCPConst.Method.TOOLS_CALL:
                return toolsCall(id, params, true);
            default:
                return error(404, id, METHOD_NOT_FOUND, "Method not found: " + method, null, true);
        }
    }

    /** @return null when the headers are valid, else the reason */
    private static String validateHeaders(String method, NVGenericMap params, String requested, Headers headers) {
        if (headers == null)
            return null;

        String hv = headers.get(MCPConst.Header.PROTOCOL_VERSION);
        if (hv == null)
            return MCPConst.Header.PROTOCOL_VERSION + " header is missing";
        if (!hv.equals(requested))
            return MCPConst.Header.PROTOCOL_VERSION + " header value '" + hv + "' does not match body value '" + requested + "'";

        String hm = headers.get(MCPConst.Header.METHOD);
        if (hm == null)
            return MCPConst.Header.METHOD + " header is missing";
        if (!hm.equals(method))
            return MCPConst.Header.METHOD + " header value '" + hm + "' does not match body value '" + method + "'";

        String bodyName = null;
        if (MCPConst.Method.TOOLS_CALL.equals(method) || MCPConst.Method.PROMPTS_GET.equals(method))
            bodyName = str(params.getValue("name"));
        else if (MCPConst.Method.RESOURCES_READ.equals(method))
            bodyName = str(params.getValue("uri"));

        if (bodyName != null) {
            String raw = headers.get(MCPConst.Header.NAME);
            if (raw == null)
                return MCPConst.Header.NAME + " header is missing";
            String hn;
            try {
                hn = decodeSentinel(raw);
            } catch (IllegalArgumentException e) {
                return MCPConst.Header.NAME + " header has an invalid Base64 value";
            }
            if (!hn.equals(bodyName))
                return MCPConst.Header.NAME + " header value '" + hn + "' does not match body value '" + bodyName + "'";
        }
        return null;
    }

    /** Decode the {@code =?base64?...?=} sentinel form; plain values pass through. */
    static String decodeSentinel(String value) {
        if (value.startsWith(MCPConst.BASE64_SENTINEL_PREFIX) && value.endsWith(MCPConst.BASE64_SENTINEL_SUFFIX)
                && value.length() >= MCPConst.BASE64_SENTINEL_PREFIX.length() + MCPConst.BASE64_SENTINEL_SUFFIX.length()) {
            String b64 = value.substring(MCPConst.BASE64_SENTINEL_PREFIX.length(),
                    value.length() - MCPConst.BASE64_SENTINEL_SUFFIX.length());
            return new String(Base64.getDecoder().decode(b64), StandardCharsets.UTF_8);
        }
        return value;
    }

    private NVGenericMap discoverResult() {
        NVGenericMap result = new NVGenericMap("result");
        result.add(new NVStringList("supportedVersions", new ArrayList<>(MCPConst.SUPPORTED_VERSIONS)));
        result.add(capabilities(false));
        if (instructions != null)
            result.add("instructions", instructions);
        return result;
    }

    // ---- legacy (2025-11-25 and earlier): initialize handshake, no session id minted ----

    private Reply handleLegacy(GetNameValue<?> id, String method, NVGenericMap params) throws IOException {
        switch (method) {
            case MCPConst.Method.INITIALIZE: {
                String requested = str(params.getValue("protocolVersion"));
                String negotiated = MCPConst.LEGACY_VERSIONS.contains(requested)
                        ? requested
                        : MCPConst.LEGACY_VERSIONS.get(0);
                NVGenericMap result = new NVGenericMap("result");
                result.add("protocolVersion", negotiated);
                result.add(capabilities(true));
                result.add(serverInfo("serverInfo"));
                if (instructions != null)
                    result.add("instructions", instructions);
                return result(id, result, false);
            }
            case MCPConst.Method.PING:
                return result(id, new NVGenericMap("result"), false);
            case MCPConst.Method.SERVER_DISCOVER:
                return result(id, discoverResult(), false);
            case MCPConst.Method.TOOLS_LIST:
                return result(id, toolsListResult(false), false);
            case MCPConst.Method.TOOLS_CALL:
                return toolsCall(id, params, false);
            default:
                return error(200, id, METHOD_NOT_FOUND, "Method not found: " + method, null, false);
        }
    }

    // ---- shared ----

    private NVGenericMap capabilities(boolean legacy) {
        NVGenericMap capabilities = new NVGenericMap("capabilities");
        NVGenericMap toolsCap = new NVGenericMap("tools");
        if (legacy)
            toolsCap.add(new NVBoolean("listChanged", false));
        capabilities.add(toolsCap);
        return capabilities;
    }

    private NVGenericMap serverInfo(String mapName) {
        NVGenericMap info = new NVGenericMap(mapName);
        info.add("name", name);
        info.add("version", version);
        return info;
    }

    private NVGenericMap toolsListResult(boolean modern) {
        NVGenericMap result = new NVGenericMap("result");
        NVGenericMapList list = new NVGenericMapList("tools");
        for (MCPTool tool : getTools()) {
            NVGenericMap t = new NVGenericMap();
            t.add("name", tool.getName());
            t.add("description", tool.getDescription());
            NVGenericMap schema = tool.inputSchema();
            schema.setName("inputSchema");
            t.add(schema);
            NVGenericMap annotations = new NVGenericMap("annotations");
            annotations.add(new NVBoolean("readOnlyHint", tool.isReadOnly()));
            if (!tool.isReadOnly())
                annotations.add(new NVBoolean("destructiveHint", true));
            t.add(annotations);
            list.add(t);
        }
        result.add(list);
        if (modern) {
            result.add(new NVLong("ttlMs", MCPConst.TOOLS_LIST_TTL_MS));
            // the list depends on this server's configuration and its caller's access
            result.add("cacheScope", "private");
        }
        return result;
    }

    private Reply toolsCall(GetNameValue<?> id, NVGenericMap params, boolean modern) throws IOException {
        String toolName = str(params.getValue("name"));
        MCPTool tool = lookupTool(toolName);
        if (tool == null)
            return error(200, id, INVALID_PARAMS, "Unknown tool: " + toolName, null, modern);

        NVGenericMap arguments = map(params.get("arguments"));
        if (arguments == null)
            arguments = new NVGenericMap("arguments");

        String text;
        boolean isError;
        try {
            text = tool.call(arguments);
            isError = false;
        } catch (Exception e) {
            text = describe(e);
            isError = true;
            if (log.isEnabled()) log.getLogger().info(toolName + " failed: " + e);
        }
        if (text == null)
            text = "";

        NVGenericMap result = new NVGenericMap("result");
        NVGenericMapList content = new NVGenericMapList("content");
        NVGenericMap item = new NVGenericMap();
        item.add("type", "text");
        item.add("text", text);
        content.add(item);
        result.add(content);
        result.add(new NVBoolean("isError", isError));
        return result(id, result, modern);
    }

    /** A message the model can act on, without stack traces. */
    static String describe(Throwable e) {
        if (e instanceof NoSuchFileException)
            return "No such file or directory: " + e.getMessage();
        if (e instanceof AccessDeniedException) {
            String reason = ((AccessDeniedException) e).getReason();
            return "Access denied: " + ((AccessDeniedException) e).getFile() + (reason != null ? " (" + reason + ")" : "");
        }
        if (e instanceof FileAlreadyExistsException)
            return "Already exists: " + e.getMessage();
        if (e instanceof DirectoryNotEmptyException)
            return "Directory not empty: " + e.getMessage();
        if (e instanceof NotDirectoryException)
            return "Not a directory: " + e.getMessage();
        if (e instanceof IllegalArgumentException && e.getMessage() != null)
            return e.getMessage();
        return e.getMessage() != null ? e.getClass().getSimpleName() + ": " + e.getMessage() : e.toString();
    }

    private Reply result(GetNameValue<?> id, NVGenericMap result, boolean modern) throws IOException {
        if (modern) {
            result.add("resultType", "complete");
            NVGenericMap meta = new NVGenericMap(MCPConst.Meta.META);
            meta.add(serverInfo(MCPConst.Meta.SERVER_INFO));
            result.add(meta);
        }
        NVGenericMap response = envelope(id);
        result.setName("result");
        response.add(result);
        return new Reply(200, toJSON(response));
    }

    /** A JSON-RPC error with no id, for failures before a message is parsed (403, 503). */
    public static Reply errorReply(int status, int code, String message) {
        return error(status, null, code, message, null, false);
    }

    private static Reply error(int status, GetNameValue<?> id, int code, String message, NVGenericMap data, boolean modern) {
        NVGenericMap response = envelope(id);
        NVGenericMap err = new NVGenericMap("error");
        err.add(new NVInt("code", code));
        err.add("message", message);
        if (data != null) {
            data.setName("data");
            err.add(data);
        }
        response.add(err);
        try {
            return new Reply(status, toJSON(response));
        } catch (IOException e) {
            // cannot happen with a StringWriter; keep the contract of always replying
            return new Reply(status, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":" + INTERNAL_ERROR
                    + ",\"message\":\"Internal error\"}}");
        }
    }

    /** {@code jsonrpc} plus the request id; an unknown id is omitted, which the MCP transport allows. */
    private static NVGenericMap envelope(GetNameValue<?> id) {
        NVGenericMap response = new NVGenericMap();
        response.add("jsonrpc", MCPConst.JSONRPC_VERSION);
        if (id != null && id.getValue() != null)
            response.add(id);
        return response;
    }

    static String toJSON(NVGenericMap map) throws IOException {
        return GSONUtil.toJSONGenericMap(map, false, true, false);
    }

    static NVGenericMap map(GetNameValue<?> gnv) {
        return gnv instanceof NVGenericMap ? (NVGenericMap) gnv : null;
    }

    static String str(Object v) {
        return v == null ? null : v.toString();
    }

    private static String header(Headers headers, String name) {
        return headers == null ? null : headers.get(name);
    }
}
