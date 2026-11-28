package io.xlogistx.mcp;

import org.zoxweb.shared.util.NVGenericMap;

/**
 * A tool exposed through {@code tools/list} and invoked through {@code tools/call}.
 * <p>
 * Implementations must be thread-safe: the HTTP server calls them from its worker threads.
 */
public interface MCPTool {

    /** Unique tool name, e.g. {@code read_file}. */
    String getName();

    /** What the tool does, written for the model that will choose it. */
    String getDescription();

    /**
     * The JSON Schema of the arguments. Build a new map on every call; the server names it
     * {@code inputSchema} and places it in the response.
     */
    NVGenericMap inputSchema();

    /** True when the tool never changes anything; reported as the {@code readOnlyHint}. */
    boolean isReadOnly();

    /**
     * Run the tool.
     *
     * @param arguments the {@code arguments} object of the call, never null
     * @return the text result
     * @throws Exception any failure; the server reports it as a tool error ({@code isError: true}),
     *                   not as a protocol error, so the model can see it and recover
     */
    String call(NVGenericMap arguments) throws Exception;
}
