package io.xlogistx.mcp;

import org.zoxweb.shared.util.NVGenericMap;

/**
 * Typed access to tool-call arguments parsed by {@code GSONUtil.fromJSONGenericMap}: JSON
 * strings arrive as strings, numbers as NVInt/NVLong/NVDouble, booleans as NVBoolean.
 */
public final class ToolArgs {

    private ToolArgs() {
    }

    /** A required string; an empty string is allowed (file content may be empty). */
    public static String requiredString(NVGenericMap args, String name) {
        Object v = args.getValue(name);
        if (v == null)
            throw new IllegalArgumentException("Missing required argument: " + name);
        return v.toString();
    }

    /** A required, non-blank string, such as a path. */
    public static String requiredNonBlank(NVGenericMap args, String name) {
        String v = requiredString(args, name);
        if (v.trim().isEmpty())
            throw new IllegalArgumentException("Argument must not be empty: " + name);
        return v;
    }

    public static String optionalString(NVGenericMap args, String name, String def) {
        Object v = args.getValue(name);
        return v == null ? def : v.toString();
    }

    public static int optionalInt(NVGenericMap args, String name, int def, int min, int max) {
        Object v = args.getValue(name);
        if (v == null)
            return def;
        long n;
        if (v instanceof Number) {
            double d = ((Number) v).doubleValue();
            if (d != Math.rint(d))
                throw new IllegalArgumentException("Argument " + name + " must be an integer");
            n = (long) d;
        } else {
            try {
                n = Long.parseLong(v.toString().trim());
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Argument " + name + " must be an integer");
            }
        }
        if (n < min || n > max)
            throw new IllegalArgumentException("Argument " + name + " must be between " + min + " and " + max);
        return (int) n;
    }

    public static boolean optionalBoolean(NVGenericMap args, String name, boolean def) {
        Object v = args.getValue(name);
        if (v == null)
            return def;
        if (v instanceof Boolean)
            return (Boolean) v;
        String s = v.toString().trim();
        if ("true".equalsIgnoreCase(s))
            return true;
        if ("false".equalsIgnoreCase(s))
            return false;
        throw new IllegalArgumentException("Argument " + name + " must be true or false");
    }
}
