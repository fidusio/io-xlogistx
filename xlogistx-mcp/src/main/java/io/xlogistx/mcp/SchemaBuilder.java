package io.xlogistx.mcp;

import org.zoxweb.shared.util.NVGenericMap;
import org.zoxweb.shared.util.NVInt;
import org.zoxweb.shared.util.NVStringList;

import java.util.ArrayList;
import java.util.List;

/**
 * Builds the JSON Schema object of a tool's {@code inputSchema} as an {@link NVGenericMap}.
 * <pre>{@code
 * SchemaBuilder.object()
 *     .string("path", "File to read", true)
 *     .integer("limit", "Lines to return", false, 1, 100000)
 *     .build();
 * }</pre>
 */
public final class SchemaBuilder {

    private final NVGenericMap properties = new NVGenericMap("properties");
    private final List<String> required = new ArrayList<>();

    private SchemaBuilder() {
    }

    public static SchemaBuilder object() {
        return new SchemaBuilder();
    }

    public SchemaBuilder string(String name, String description, boolean isRequired) {
        return property(name, "string", description, isRequired);
    }

    public SchemaBuilder bool(String name, String description) {
        return property(name, "boolean", description, false);
    }

    public SchemaBuilder integer(String name, String description, boolean isRequired, int min, int max) {
        NVGenericMap p = new NVGenericMap(name);
        p.add("type", "integer");
        p.add("description", description);
        p.add(new NVInt("minimum", min));
        p.add(new NVInt("maximum", max));
        properties.add(p);
        if (isRequired)
            required.add(name);
        return this;
    }

    private SchemaBuilder property(String name, String type, String description, boolean isRequired) {
        NVGenericMap p = new NVGenericMap(name);
        p.add("type", type);
        p.add("description", description);
        properties.add(p);
        if (isRequired)
            required.add(name);
        return this;
    }

    /** The schema, named {@code inputSchema}. */
    public NVGenericMap build() {
        NVGenericMap schema = new NVGenericMap("inputSchema");
        schema.add("type", "object");
        schema.add(properties);
        if (!required.isEmpty())
            schema.add(new NVStringList("required", new ArrayList<>(required)));
        return schema;
    }
}
