package io.xlogistx.mcp.services;

import io.xlogistx.common.data.PropertyContainer;
import io.xlogistx.common.http.HTTPProtocolHandler;
import io.xlogistx.http.EndpointsUtil;
import io.xlogistx.mcp.MCPConst;
import io.xlogistx.mcp.MCPServer;
import io.xlogistx.mcp.MCPTool;
import io.xlogistx.mcp.fs.FileAccessPolicy;
import io.xlogistx.mcp.fs.FileSystemTools;
import org.zoxweb.server.http.HTTPUtil;
import org.zoxweb.server.logging.LogWrapper;
import org.zoxweb.shared.annotation.EndPointProp;
import org.zoxweb.shared.annotation.SecurityProp;
import org.zoxweb.shared.http.*;
import org.zoxweb.shared.security.SecConst;
import org.zoxweb.shared.util.*;

import java.util.*;

/**
 * The MCP Streamable HTTP endpoint: {@code POST /mcp}.
 * <p>
 * Only POST is mapped, so the server itself answers GET and DELETE with 405, which is what the
 * 2026-07-28 revision asks of a server that keeps no sessions. Every response is a single JSON
 * object; the endpoint never opens an SSE stream.
 * <p>
 * Configuration ({@code properties} of the endpoint entry):
 * <pre>{@code
 * {
 *   "bean": "io.xlogistx.mcp.services.MCPEndpoint",
 *   "properties": {
 *     "roots": ["D:/data/mcp"],           // required, folders the tools may access
 *     "read-only": false,                  // true leaves out write_file, edit_file, create_directory
 *     "allowed-origins": [],               // browser Origins to accept; any other Origin gets 403
 *     "server-name": "xlogistx-mcp",
 *     "max-read-chars": 1048576,
 *     "max-results": 500,
 *     "max-search-file-bytes": 4194304,
 *     "max-write-bytes": 4194304
 *   }
 * }
 * }</pre>
 * Access needs the {@code mcp:access} permission through the server's Shiro configuration.
 */
public class MCPEndpoint
        extends PropertyContainer<NVGenericMap> {

    public static final LogWrapper log = new LogWrapper(MCPEndpoint.class).setEnabled(true);

    public static final String SERVER_VERSION = "1.0.0";

    private volatile MCPServer server;
    private volatile String configError = "no properties configured";
    private volatile Set<String> allowedOrigins = Collections.emptySet();

    @Override
    protected void refreshProperties() {
        NVGenericMap props = getProperties();
        if (props == null)
            return;
        try {
            List<String> roots = stringList(props, "roots");
            boolean readOnly = bool(props, "read-only", false);
            FileAccessPolicy policy = new FileAccessPolicy(roots, readOnly);

            FileSystemTools.Limits limits = new FileSystemTools.Limits();
            limits.maxReadChars = (int) number(props, "max-read-chars", limits.maxReadChars);
            limits.maxResults = (int) number(props, "max-results", limits.maxResults);
            limits.maxSearchFileBytes = number(props, "max-search-file-bytes", limits.maxSearchFileBytes);
            limits.maxWriteBytes = (int) number(props, "max-write-bytes", limits.maxWriteBytes);

            String name = props.getValue("server-name") != null ? props.getValue("server-name").toString() : "xlogistx-mcp";
            MCPServer s = new MCPServer(name, SERVER_VERSION,
                    "File system access confined to the configured root folders"
                            + (readOnly ? " (read-only)" : "")
                            + ". Call list_allowed_roots first; paths outside the roots are refused.");
            for (MCPTool tool : FileSystemTools.create(policy, limits))
                s.register(tool);

            allowedOrigins = Collections.unmodifiableSet(new HashSet<>(stringListOptional(props, "allowed-origins")));
            server = s;
            configError = null;
            log.getLogger().info("MCP endpoint ready: roots=" + policy.getRoots() + " read-only=" + readOnly
                    + " tools=" + s.getTools().size());
        } catch (Exception e) {
            server = null;
            configError = e.getMessage() != null ? e.getMessage() : e.toString();
            log.getLogger().severe("MCP endpoint configuration failed: " + configError);
        }
    }

    @EndPointProp(methods = {HTTPMethod.POST}, name = "mcp", uris = "/mcp")
    @SecurityProp(authentications = {SecConst.AuthenticationType.ALL}, permissions = "mcp:access")
    public HTTPMessageConfigInterface mcp() {
        HTTPProtocolHandler hph = EndpointsUtil.SINGLETON.getProtocolHandler();
        HTTPMessageConfigInterface request = hph.getRequest();
        final NVGenericMap requestHeaders = request.getHeaders();
        MCPServer.Headers headers = new MCPServer.Headers() {
            @Override
            public String get(String name) {
                return header(requestHeaders, name);
            }
        };

        // DNS-rebinding protection: a browser Origin must be explicitly allowed
        String origin = headers.get(MCPConst.Header.ORIGIN);
        if (origin != null && !allowedOrigins.contains(origin))
            return toHTTP(MCPServer.errorReply(403, MCPConst.ErrorCode.INVALID_REQUEST, "Origin not allowed: " + origin));

        MCPServer s = server;
        if (s == null)
            return toHTTP(MCPServer.errorReply(500, MCPConst.ErrorCode.INTERNAL_ERROR,
                    "MCP endpoint is not configured: " + configError));

        MCPServer.Reply reply = s.handle(request.getContent(), headers);
        if (log.isEnabled() && reply.status >= 400)
            log.getLogger().info("MCP reply " + reply);
        return toHTTP(reply);
    }

    public MCPServer getServer() {
        return server;
    }

    // ---- helpers ----

    static HTTPMessageConfigInterface toHTTP(MCPServer.Reply reply) {
        HTTPMessageConfigInterface hmci = new HTTPMessageConfig();
        HTTPStatusCode status = HTTPStatusCode.statusByCode(reply.status, HTTPStatusCode.INTERNAL_SERVER_ERROR);//toStatus(reply.status);
        if (reply.body == null) {
            HTTPUtil.buildResponse(hmci, status,
                    HTTPConst.CommonHeader.NO_CACHE_CONTROL,
                    HTTPConst.CommonHeader.EXPIRES_ZERO);
            hmci.setContentLength(0);
            hmci.getHeaders().remove(HTTPHeader.CONTENT_TYPE);
        } else {
            hmci.setContent(reply.body);
            HTTPUtil.buildResponse(hmci, status,
                    HTTPConst.CommonHeader.CONTENT_TYPE_JSON_UTF8,
                    HTTPConst.CommonHeader.NO_CACHE_CONTROL,
                    HTTPConst.CommonHeader.EXPIRES_ZERO);
        }
        return hmci;
    }

//    static HTTPStatusCode toStatus(int code) {
//        switch (code) {
//            case 200:
//                return HTTPStatusCode.OK;
//            case 202:
//                return HTTPStatusCode.ACCEPTED;
//            case 400:
//                return HTTPStatusCode.BAD_REQUEST;
//            case 403:
//                return HTTPStatusCode.FORBIDDEN;
//            case 404:
//                return HTTPStatusCode.NOT_FOUND;
//            default:
//                return HTTPStatusCode.INTERNAL_SERVER_ERROR;
//        }
//    }

    /** Header names are case-insensitive. */
    static String header(NVGenericMap headers, String name) {
        if (headers == null)
            return null;
        for (GetNameValue<?> h : headers.values()) {
            if (h != null && name.equalsIgnoreCase(h.getName()))
                return h.getValue() != null ? h.getValue().toString().trim() : null;
        }
        return null;
    }

    static List<String> stringList(NVGenericMap props, String name) {
        List<String> list = stringListOptional(props, name);
        if (list.isEmpty())
            throw new IllegalArgumentException("Property '" + name + "' is required");
        return list;
    }

    /** Accepts a JSON array of strings or one comma-separated string. */
    static List<String> stringListOptional(NVGenericMap props, String name) {
        GetNameValue<?> gnv = props.get(name);
        List<String> ret = new ArrayList<>();
        if (gnv instanceof NVStringList) {
            for (String s : ((NVStringList) gnv).getValue()) {
                if (s != null && !s.trim().isEmpty())
                    ret.add(s.trim());
            }
        } else if (gnv != null && gnv.getValue() != null) {
            for (String s : gnv.getValue().toString().split(",")) {
                if (!s.trim().isEmpty())
                    ret.add(s.trim());
            }
        }
        return ret;
    }

    static boolean bool(NVGenericMap props, String name, boolean def) {
        Object v = props.getValue(name);
        if (v == null)
            return def;
        if (v instanceof Boolean)
            return (Boolean) v;
        return Boolean.parseBoolean(v.toString().trim());
    }

    static long number(NVGenericMap props, String name, long def) {
        Object v = props.getValue(name);
        if (v == null)
            return def;
        long n = v instanceof Number ? ((Number) v).longValue() : Long.parseLong(v.toString().trim());
        if (n <= 0)
            throw new IllegalArgumentException("Property '" + name + "' must be positive");
        return n;
    }
}
