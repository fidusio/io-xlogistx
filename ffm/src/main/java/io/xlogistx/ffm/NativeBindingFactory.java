package io.xlogistx.ffm;

import org.zoxweb.shared.util.ParamUtil;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.nio.file.Path;
import java.util.*;

/**
 * NativeBindingFactory — Unified entry point for creating FFM MethodHandles
 * from native shared libraries using any of three discovery strategies:
 *
 *   1. DWARF   — Parse debug info from .so via libdw (requires -dbgsym or -g)
 *   2. HEADER  — Parse .h files with pure Java preprocessor + parser (no gcc needed)
 *   3. GCC     — Parse .h files using gcc -E preprocessing + Java parser
 *
 * All three produce the same CType → NativeFunction → FunctionDescriptor → MethodHandle
 * pipeline. The output is fully interchangeable regardless of which strategy was used.
 *
 * Usage:
 *   // Pure Java — header file only, no external dependencies
 *   var bindings = NativeBindingFactory.fromHeader("/usr/include/pcap/pcap.h")
 *       .library("/usr/lib/x86_64-linux-gnu/libpcap.so")
 *       .includePath("/usr/include")
 *       .bind();
 *
 *   // DWARF — requires libdw and debug symbols
 *   var bindings = NativeBindingFactory.fromDwarf("/usr/lib/x86_64-linux-gnu/libpcap.so.1")
 *       .bind();
 *
 *   // Use a binding
 *   MethodHandle pcap_open = bindings.getHandle("pcap_open_live");
 *   MemorySegment handle = (MemorySegment) pcap_open.invoke(device, snaplen, promisc, timeout, errbuf);
 *
 * Thread-safety: NativeBindings instances are thread-safe after construction.
 *                Builder instances are NOT thread-safe.
 */
public class NativeBindingFactory {

    // =========================================================================
    // SHARED DATA MODEL — Identical to DwarfFFMLoader and CHeaderParser
    // =========================================================================

    /**
     * Represents a resolved C type. Sealed hierarchy shared across all strategies.
     */
    public sealed interface CType {
        record Primitive(String name, int byteSize, Encoding encoding) implements CType {}
        record Pointer(CType pointee) implements CType {}
        record Struct(String name, long byteSize, List<StructField> fields) implements CType {}
        record Union(String name, long byteSize, List<StructField> fields) implements CType {}
        record Enum(String name, int byteSize, List<EnumConstant> constants) implements CType {}
        record Typedef(String name, CType underlying) implements CType {}
        record Qualified(Qualifier qual, CType underlying) implements CType {}
        record Array(CType elementType, long count) implements CType {}
        record FunctionPointer(CType returnType, List<CType> paramTypes) implements CType {}
        record Void() implements CType {}
        record Unresolved(String name) implements CType {}

        enum Encoding { SIGNED, UNSIGNED, FLOAT, BOOLEAN, SIGNED_CHAR, UNSIGNED_CHAR, UNKNOWN }
        enum Qualifier { CONST, VOLATILE, RESTRICT }
    }

    public record StructField(String name, CType type, long offset) {}
    public record EnumConstant(String name, long value) {}
    public record Parameter(String name, CType type) {}

    public record NativeFunction(String name, CType returnType,
                                 List<Parameter> params, boolean variadic) {
        @Override
        public String toString() {
            StringJoiner pj = new StringJoiner(", ");
            for (Parameter p : params) pj.add(typeToString(p.type()) + " " + p.name());
            if (variadic) pj.add("...");
            return typeToString(returnType) + " " + name + "(" + pj + ")";
        }
    }

    public record BoundFunction(NativeFunction function, FunctionDescriptor descriptor,
                                MethodHandle handle) {}


    // =========================================================================
    // NATIVE BINDINGS — The result of binding: map of name → BoundFunction
    // =========================================================================

    /**
     * Holds all bound functions for a native library.
     * Thread-safe after construction — all fields are immutable.
     */
    public static class NativeBindings implements AutoCloseable {
        private final String libraryPath;
        private final Strategy strategy;
        private final Map<String, BoundFunction> boundFunctions;
        private final Map<String, CType.Struct> structs;
        private final Map<String, CType> typedefs;
        private final List<NativeFunction> allFunctions;
        private final Arena arena;
        private final SymbolLookup lookup;

        NativeBindings(String libraryPath, Strategy strategy,
                       List<NativeFunction> functions,
                       Map<String, CType.Struct> structs,
                       Map<String, CType> typedefs) {
            this.libraryPath = libraryPath;
            this.strategy = strategy;
            this.allFunctions = List.copyOf(functions);
            this.structs = Map.copyOf(structs);
            this.typedefs = Map.copyOf(typedefs);
            this.arena = Arena.ofShared(); // shared arena for thread safety
            this.lookup = SymbolLookup.libraryLookup(Path.of(libraryPath), arena);

            // Bind all non-variadic functions
            Map<String, BoundFunction> bound = new LinkedHashMap<>();
            Linker linker = Linker.nativeLinker();

            for (NativeFunction func : functions) {
                try {
                    FunctionDescriptor desc = buildDescriptor(func);
                    if (desc == null) continue; // variadic

                    var symbol = lookup.find(func.name());
                    if (symbol.isEmpty()) continue; // not exported

                    MethodHandle handle = linker.downcallHandle(symbol.get(), desc);
                    bound.put(func.name(), new BoundFunction(func, desc, handle));
                } catch (Exception e) {
                    // Skip functions that fail to bind
                }
            }

            this.boundFunctions = Map.copyOf(bound);
        }

        /** Gets a MethodHandle by function name. Throws if not found. */
        public MethodHandle getHandle(String name) {
            BoundFunction bf = boundFunctions.get(name);
            if (bf == null) throw new NoSuchElementException("No binding for: " + name
                    + ". Available: " + boundFunctions.keySet());
            return bf.handle();
        }

        /** Gets a BoundFunction (with metadata) by name. Returns null if not found. */
        public BoundFunction getFunction(String name) { return boundFunctions.get(name); }

        /** Gets a struct layout by name (without "struct " prefix). */
        public CType.Struct getStruct(String name) { return structs.get(name); }

        /** Gets a MemoryLayout for a named struct, ready for allocation. */
        public MemoryLayout getStructLayout(String name) {
            CType.Struct s = structs.get(name);
            if (s == null) throw new NoSuchElementException("No struct: " + name);
            return buildStructLayout(s);
        }

        /** Allocates a struct instance in the shared arena. */
        public MemorySegment allocateStruct(String name) {
            return arena.allocate(getStructLayout(name));
        }

        /** Returns the shared arena (for allocating strings, buffers, etc.) */
        public Arena getArena() { return arena; }

        /** Returns the symbol lookup for manual resolution. */
        public SymbolLookup getLookup() { return lookup; }

        /** Returns all bound function names. */
        public Set<String> getBoundFunctionNames() { return boundFunctions.keySet(); }

        /** Returns all discovered functions (including unbound/variadic). */
        public List<NativeFunction> getAllFunctions() { return allFunctions; }

        /** Returns all discovered structs. */
        public Map<String, CType.Struct> getStructs() { return structs; }

        /** Returns all discovered typedefs. */
        public Map<String, CType> getTypedefs() { return typedefs; }

        /** Returns the strategy used to discover bindings. */
        public Strategy getStrategy() { return strategy; }

        /** Summary stats. */
        public String summary() {
            long variadic = allFunctions.stream().filter(NativeFunction::variadic).count();
            return String.format("Library: %s | Strategy: %s | Functions: %d bound, %d variadic, " +
                            "%d total | Structs: %d | Typedefs: %d",
                    libraryPath, strategy, boundFunctions.size(), variadic,
                    allFunctions.size(), structs.size(), typedefs.size());
        }

        @Override
        public void close() { arena.close(); }
    }

    public enum Strategy { HEADER_PURE_JAVA, HEADER_GCC, DWARF }


    // =========================================================================
    // BUILDER — Fluent API for configuring and executing binding discovery
    // =========================================================================

    /**
     * Builder for header-based binding discovery.
     */
    public static class HeaderBuilder {
        private final String headerPath;
        private String libraryPath;
        private final List<String> includePaths = new ArrayList<>();
        private final Map<String, String> defines = new LinkedHashMap<>();
        private CPreprocessor.Platform platform = CPreprocessor.Platform.LINUX_X86_64;
        private boolean useGcc = false;

        HeaderBuilder(String headerPath) {
            this.headerPath = headerPath;
        }

        /** Sets the shared library to bind against. */
        public HeaderBuilder library(String path) { this.libraryPath = path; return this; }

        /** Adds an include search path (-I). */
        public HeaderBuilder includePath(String path) { includePaths.add(path); return this; }

        /** Adds multiple include paths. */
        public HeaderBuilder includePaths(String... paths) {
            includePaths.addAll(Arrays.asList(paths));
            return this;
        }

        /** Defines a macro (-D). */
        public HeaderBuilder define(String name, String value) {
            defines.put(name, value); return this;
        }

        /** Defines a flag macro (-D with value 1). */
        public HeaderBuilder define(String name) { return define(name, "1"); }

        /** Sets the target platform for type sizes and predefined macros. */
        public HeaderBuilder platform(CPreprocessor.Platform p) { this.platform = p; return this; }

        /** Forces gcc -E preprocessing instead of pure Java. */
        public HeaderBuilder useGcc() { this.useGcc = true; return this; }

        /**
         * Executes the full pipeline: preprocess → tokenize → parse → bind.
         */
        public NativeBindings bind() throws Exception {
            if (libraryPath == null) {
                throw new IllegalStateException("Library path not set. Call .library(path) first.");
            }

            String preprocessed;
            Strategy strategy;

            if (useGcc) {
                // Use gcc -E
                preprocessed = CHeaderParser.preprocess(headerPath,
                        includePaths.toArray(new String[0]));
                strategy = Strategy.HEADER_GCC;
            } else {
                // Pure Java preprocessing
                CPreprocessor pp = new CPreprocessor(platform);
                for (String dir : includePaths) pp.addUserIncludePath(dir);
                for (var entry : defines.entrySet()) pp.define(entry.getKey(), entry.getValue());
                preprocessed = pp.preprocess(headerPath);
                strategy = Strategy.HEADER_PURE_JAVA;
            }

            // Tokenize
            List<CHeaderParser.Token> tokens = CHeaderParser.tokenize(preprocessed);

            // Parse
            CHeaderParser.Parser parser = new CHeaderParser.Parser(tokens);
            parser.parseAll();

            // Convert to unified model
            List<NativeFunction> functions = convertFunctions(parser.functions);
            Map<String, CType.Struct> structs = convertStructs(parser.structs);
            Map<String, CType> typedefs = convertTypedefs(parser.typedefs);

            return new NativeBindings(libraryPath, strategy, functions, structs, typedefs);
        }

        /**
         * Parse only — returns discovered metadata without binding to a library.
         * Useful for code generation or inspection.
         */
        public ParseResult parseOnly() throws Exception {
            String preprocessed;
            if (useGcc) {
                preprocessed = CHeaderParser.preprocess(headerPath,
                        includePaths.toArray(new String[0]));
            } else {
                CPreprocessor pp = new CPreprocessor(platform);
                for (String dir : includePaths) pp.addUserIncludePath(dir);
                for (var entry : defines.entrySet()) pp.define(entry.getKey(), entry.getValue());
                preprocessed = pp.preprocess(headerPath);
            }

            List<CHeaderParser.Token> tokens = CHeaderParser.tokenize(preprocessed);
            CHeaderParser.Parser parser = new CHeaderParser.Parser(tokens);
            parser.parseAll();

            return new ParseResult(
                    convertFunctions(parser.functions),
                    convertStructs(parser.structs),
                    convertTypedefs(parser.typedefs)
            );
        }
    }

    public record ParseResult(List<NativeFunction> functions,
                              Map<String, CType.Struct> structs,
                              Map<String, CType> typedefs) {}

    /**
     * Builder for DWARF-based binding discovery.
     */
    public static class DwarfBuilder {
        private final String libraryPath;

        DwarfBuilder(String libraryPath) { this.libraryPath = libraryPath; }

        /**
         * Parses DWARF from the library and creates bindings.
         * The library must have debug info (.debug_info section).
         */
        public NativeBindings bind() throws Throwable {
            try (DwarfFFMLoader loader = new DwarfFFMLoader()) {
                loader.parseDwarf(libraryPath);

                List<NativeFunction> functions = convertDwarfFunctions(loader.getFunctions());
                Map<String, CType.Struct> structs = convertDwarfStructs(loader.getStructs());

                return new NativeBindings(libraryPath, Strategy.DWARF,
                        functions, structs, Map.of());
            }
        }

        // Convert DwarfFFMLoader types → NativeBindingFactory types
        // (They share the same structure but are different classes)
        private List<NativeFunction> convertDwarfFunctions(
                List<DwarfFFMLoader.NativeFunction> dwarfFunctions) {
            List<NativeFunction> result = new ArrayList<>();
            for (var df : dwarfFunctions) {
                List<Parameter> params = new ArrayList<>();
                boolean variadic = false;
                for (var dp : df.params()) {
                    if (dp.type() instanceof DwarfFFMLoader.CType.Unresolved u
                            && u.reason().equals("variadic")) {
                        variadic = true;
                    } else {
                        params.add(new Parameter(dp.name(), convertDwarfType(dp.type())));
                    }
                }
                result.add(new NativeFunction(df.name(),
                        convertDwarfType(df.returnType()), params, variadic));
            }
            return result;
        }

        private Map<String, CType.Struct> convertDwarfStructs(
                Map<String, DwarfFFMLoader.CType.Struct> dwarfStructs) {
            Map<String, CType.Struct> result = new LinkedHashMap<>();
            for (var entry : dwarfStructs.entrySet()) {
                result.put(entry.getKey(), (CType.Struct) convertDwarfType(entry.getValue()));
            }
            return result;
        }

        private CType convertDwarfType(DwarfFFMLoader.CType dwarfType) {
            return switch (dwarfType) {
                case DwarfFFMLoader.CType.Primitive p ->
                    new CType.Primitive(p.name(), p.byteSize(), convertEncoding(p.encoding()));
                case DwarfFFMLoader.CType.Pointer p ->
                    new CType.Pointer(convertDwarfType(p.pointee()));
                case DwarfFFMLoader.CType.Struct s -> {
                    List<StructField> fields = new ArrayList<>();
                    for (var f : s.fields())
                        fields.add(new StructField(f.name(), convertDwarfType(f.type()), f.offset()));
                    yield new CType.Struct(s.name(), s.byteSize(), fields);
                }
                case DwarfFFMLoader.CType.Union u ->
                    new CType.Union(u.name(), u.byteSize(), List.of());
                case DwarfFFMLoader.CType.Enum e ->
                    new CType.Enum(e.name(), e.byteSize(), List.of());
                case DwarfFFMLoader.CType.Typedef t ->
                    new CType.Typedef(t.name(), convertDwarfType(t.underlying()));
                case DwarfFFMLoader.CType.Qualified q ->
                    new CType.Qualified(CType.Qualifier.CONST, convertDwarfType(q.underlying()));
                case DwarfFFMLoader.CType.Array a ->
                    new CType.Array(convertDwarfType(a.elementType()), a.count());
                case DwarfFFMLoader.CType.Void v -> new CType.Void();
                case DwarfFFMLoader.CType.Unresolved u -> new CType.Unresolved(u.reason());
            };
        }

        private CType.Encoding convertEncoding(DwarfFFMLoader.CType.Encoding e) {
            return switch (e) {
                case SIGNED -> CType.Encoding.SIGNED;
                case UNSIGNED -> CType.Encoding.UNSIGNED;
                case FLOAT -> CType.Encoding.FLOAT;
                case BOOLEAN -> CType.Encoding.BOOLEAN;
                case SIGNED_CHAR -> CType.Encoding.SIGNED_CHAR;
                case UNSIGNED_CHAR -> CType.Encoding.UNSIGNED_CHAR;
                case UNKNOWN -> CType.Encoding.UNKNOWN;
            };
        }
    }


    // =========================================================================
    // FACTORY METHODS — Entry points
    // =========================================================================

    /** Creates bindings from a C header file using pure Java preprocessing. */
    public static HeaderBuilder fromHeader(String headerPath) {
        return new HeaderBuilder(headerPath);
    }

    /** Creates bindings from DWARF debug info in a shared library. */
    public static DwarfBuilder fromDwarf(String libraryPath) {
        return new DwarfBuilder(libraryPath);
    }


    // =========================================================================
    // TYPE CONVERSION — CHeaderParser types → NativeBindingFactory types
    // =========================================================================

    private static List<NativeFunction> convertFunctions(
            List<CHeaderParser.NativeFunction> parserFunctions) {
        List<NativeFunction> result = new ArrayList<>();
        for (var pf : parserFunctions) {
            List<Parameter> params = pf.params().stream()
                    .map(p -> new Parameter(p.name(), convertParserType(p.type())))
                    .toList();
            result.add(new NativeFunction(pf.name(),
                    convertParserType(pf.returnType()), params, pf.variadic()));
        }
        return result;
    }

    private static Map<String, CType.Struct> convertStructs(
            Map<String, CHeaderParser.CType.Struct> parserStructs) {
        Map<String, CType.Struct> result = new LinkedHashMap<>();
        for (var entry : parserStructs.entrySet()) {
            result.put(entry.getKey(), (CType.Struct) convertParserType(entry.getValue()));
        }
        return result;
    }

    private static Map<String, CType> convertTypedefs(
            Map<String, CHeaderParser.CType> parserTypedefs) {
        Map<String, CType> result = new LinkedHashMap<>();
        for (var entry : parserTypedefs.entrySet()) {
            result.put(entry.getKey(), convertParserType(entry.getValue()));
        }
        return result;
    }

    private static CType convertParserType(CHeaderParser.CType pt) {
        return switch (pt) {
            case CHeaderParser.CType.Primitive p ->
                new CType.Primitive(p.name(), p.byteSize(), convertEncoding(p.encoding()));
            case CHeaderParser.CType.Pointer p ->
                new CType.Pointer(convertParserType(p.pointee()));
            case CHeaderParser.CType.Struct s -> {
                List<StructField> fields = s.fields().stream()
                        .map(f -> new StructField(f.name(), convertParserType(f.type()), f.offset()))
                        .toList();
                yield new CType.Struct(s.name(), s.byteSize(), fields);
            }
            case CHeaderParser.CType.Union u -> {
                List<StructField> fields = u.fields().stream()
                        .map(f -> new StructField(f.name(), convertParserType(f.type()), f.offset()))
                        .toList();
                yield new CType.Union(u.name(), u.byteSize(), fields);
            }
            case CHeaderParser.CType.Enum e -> {
                List<EnumConstant> constants = e.constants().stream()
                        .map(c -> new EnumConstant(c.name(), c.value()))
                        .toList();
                yield new CType.Enum(e.name(), e.byteSize(), constants);
            }
            case CHeaderParser.CType.Typedef t ->
                new CType.Typedef(t.name(), convertParserType(t.underlying()));
            case CHeaderParser.CType.Qualified q ->
                new CType.Qualified(convertQualifier(q.qual()), convertParserType(q.underlying()));
            case CHeaderParser.CType.Array a ->
                new CType.Array(convertParserType(a.elementType()), a.count());
            case CHeaderParser.CType.FunctionPointer fp ->
                new CType.FunctionPointer(convertParserType(fp.returnType()),
                    fp.paramTypes().stream().map(NativeBindingFactory::convertParserType).toList());
            case CHeaderParser.CType.Void v -> new CType.Void();
            case CHeaderParser.CType.Unresolved u -> new CType.Unresolved(u.name());
        };
    }

    private static CType.Encoding convertEncoding(CHeaderParser.CType.Encoding e) {
        return CType.Encoding.valueOf(e.name());
    }

    private static CType.Qualifier convertQualifier(CHeaderParser.CType.Qualifier q) {
        return CType.Qualifier.valueOf(q.name());
    }


    // =========================================================================
    // FFM TYPE MAPPING — CType → MemoryLayout / FunctionDescriptor
    // =========================================================================

    public static MemoryLayout cTypeToLayout(CType type) {
        return switch (type) {
            case CType.Primitive p -> primitiveToLayout(p);
            case CType.Pointer ignored -> ValueLayout.ADDRESS;
            case CType.Struct s -> buildStructLayout(s);
            case CType.Union u -> MemoryLayout.paddingLayout(u.byteSize() > 0 ? u.byteSize() : 8);
            case CType.Enum ignored -> ValueLayout.JAVA_INT;
            case CType.Typedef t -> cTypeToLayout(t.underlying());
            case CType.Qualified q -> cTypeToLayout(q.underlying());
            case CType.Array a -> MemoryLayout.sequenceLayout(a.count(),
                    cTypeToLayout(a.elementType()));
            case CType.FunctionPointer ignored -> ValueLayout.ADDRESS;
            case CType.Void ignored -> null;
            case CType.Unresolved ignored -> ValueLayout.ADDRESS;
        };
    }

    private static MemoryLayout primitiveToLayout(CType.Primitive p) {
        return switch (p.encoding()) {
            case FLOAT -> p.byteSize() == 4 ? ValueLayout.JAVA_FLOAT : ValueLayout.JAVA_DOUBLE;
            case BOOLEAN -> ValueLayout.JAVA_BOOLEAN;
            case SIGNED_CHAR, UNSIGNED_CHAR -> ValueLayout.JAVA_BYTE;
            default -> switch (p.byteSize()) {
                case 1 -> ValueLayout.JAVA_BYTE;
                case 2 -> ValueLayout.JAVA_SHORT;
                case 4 -> ValueLayout.JAVA_INT;
                case 8 -> ValueLayout.JAVA_LONG;
                default -> ValueLayout.JAVA_INT;
            };
        };
    }

    static MemoryLayout buildStructLayout(CType.Struct s) {
        if (s.fields().isEmpty()) {
            return MemoryLayout.paddingLayout(s.byteSize() > 0 ? s.byteSize() : 1);
        }
        List<MemoryLayout> members = new ArrayList<>();
        long currentOffset = 0;
        for (StructField field : s.fields()) {
            if (field.offset() > currentOffset) {
                members.add(MemoryLayout.paddingLayout(field.offset() - currentOffset));
            }
            MemoryLayout fl = cTypeToLayout(field.type());
            if (fl != null) {
                members.add(fl.withName(field.name()));
                currentOffset = field.offset() + fl.byteSize();
            }
        }
        if (currentOffset < s.byteSize()) {
            members.add(MemoryLayout.paddingLayout(s.byteSize() - currentOffset));
        }
        return MemoryLayout.structLayout(members.toArray(new MemoryLayout[0]));
    }

    public static FunctionDescriptor buildDescriptor(NativeFunction func) {
        if (func.variadic()) return null;

        MemoryLayout returnLayout = cTypeToLayout(func.returnType());
        MemoryLayout[] paramLayouts = func.params().stream()
                .map(p -> cTypeToLayout(p.type()))
                .filter(Objects::nonNull)
                .toArray(MemoryLayout[]::new);

        return returnLayout != null
                ? FunctionDescriptor.of(returnLayout, paramLayouts)
                : FunctionDescriptor.ofVoid(paramLayouts);
    }


    // =========================================================================
    // TYPE DISPLAY
    // =========================================================================

    public static String typeToString(CType type) {
        return switch (type) {
            case CType.Primitive p -> p.name();
            case CType.Pointer p -> typeToString(p.pointee()) + "*";
            case CType.Struct s -> "struct " + s.name();
            case CType.Union u -> "union " + u.name();
            case CType.Enum e -> "enum " + e.name();
            case CType.Typedef t -> t.name();
            case CType.Qualified q -> q.qual().name().toLowerCase() + " " + typeToString(q.underlying());
            case CType.Array a -> typeToString(a.elementType()) + "[" + a.count() + "]";
            case CType.FunctionPointer fp -> typeToString(fp.returnType()) + "(*)(...)";
            case CType.Void ignored -> "void";
            case CType.Unresolved u -> u.name() + "?";
        };
    }


    // =========================================================================
    // MAIN — Demo showing all three approaches
    // =========================================================================

    public static void main(String[] args) throws Throwable {
        ParamUtil.ParamMap params = ParamUtil.parse("=", args);
        String header = params.stringValue("include", false);
        String libPath = params.stringValue("lib", false);
        System.out.println("╔══════════════════════════════════════════════════════════════════╗");
        System.out.println("║     NativeBindingFactory — Unified Native Binding Pipeline       ║");
        System.out.println("╚══════════════════════════════════════════════════════════════════╝");
        System.out.println();

        // --- Demo 1: Pure Java header parsing (no external dependencies) ---
        System.out.println("▶ APPROACH 1: Pure Java (header → preprocessor → parser → FFM)");
        System.out.println("─".repeat(70));

        try (NativeBindings mathBindings = NativeBindingFactory
//                .fromHeader("/usr/include/math.h")
//                .library("/usr/lib/x86_64-linux-gnu/libm.so.6")
                .fromHeader(header)
                .library(libPath)
                .bind()) {

            System.out.println("  " + mathBindings.summary());
            System.out.println();

            // Invoke functions
            System.out.println("  Invocations:");
            invoke(mathBindings, "sin", Math.PI / 2);
            invoke(mathBindings, "cos", 0.0);
            invoke(mathBindings, "sqrt", 144.0);
            invoke(mathBindings, "log", Math.E);
            invoke(mathBindings, "exp", 1.0);
            System.out.println();
        } catch (Exception e) {
            System.out.println("  Skipped: " + e.getMessage());
            System.out.println();
        }

        // --- Demo 2: gcc -E preprocessing ---
        System.out.println("▶ APPROACH 2: gcc preprocessing (header → gcc -E → parser → FFM)");
        System.out.println("─".repeat(70));

        try (NativeBindings mathBindings2 = NativeBindingFactory
//                .fromHeader("/usr/include/math.h")
//                .library("/usr/lib/x86_64-linux-gnu/libm.so.6")
                .fromHeader(header)
                .library(libPath)
                .useGcc()
                .bind()) {

            System.out.println("  " + mathBindings2.summary());
            System.out.println();

            invoke(mathBindings2, "sin", Math.PI / 2);
            invoke(mathBindings2, "sqrt", 2.0);
            System.out.println();
        } catch (Exception e) {
            System.out.println("  Skipped: " + e.getMessage());
            System.out.println();
        }

        // --- Demo 3: DWARF (if debug symbols available) ---
        System.out.println("▶ APPROACH 3: DWARF (libdw → parse debug info → FFM)");
        System.out.println("─".repeat(70));

        try (NativeBindings dwarfBindings = NativeBindingFactory
//                .fromDwarf("/usr/lib/x86_64-linux-gnu/libm.so.6")
                .fromDwarf(libPath)
                .bind()) {

            System.out.println("  " + dwarfBindings.summary());
            System.out.println();

            invoke(dwarfBindings, "sin", Math.PI / 2);
            invoke(dwarfBindings, "sqrt", 144.0);
            System.out.println();
        } catch (Throwable e) {
            System.out.println("  Skipped (no debug symbols?): " + e.getMessage());
            System.out.println();
        }

        // --- Demo 4: Parse-only mode (no library binding) ---
        System.out.println("▶ BONUS: Parse-only mode (inspect without binding)");
        System.out.println("─".repeat(70));

        try {
            ParseResult result = NativeBindingFactory
//                    .fromHeader("/usr/include/math.h")
                    .fromHeader(header)
                    .parseOnly();

            System.out.printf("  Parsed %d functions, %d structs, %d typedefs%n",
                    result.functions().size(), result.structs().size(), result.typedefs().size());

            System.out.println("  First 10 function signatures:");
            result.functions().stream().limit(10)
                    .forEach(f -> System.out.println("    " + f));

        } catch (Exception e) {
            System.out.println("  Skipped: " + e.getMessage());
        }

        System.out.println();
        System.out.println("Done.");
    }

    private static void invoke(NativeBindings bindings, String name, double arg) {
        try {
            BoundFunction bf = bindings.getFunction(name);
            if (bf != null) {
                double result = (double) bf.handle().invoke(arg);
                System.out.printf("    %s(%.4f) = %.15f%n", name, arg, result);
            }
        } catch (Throwable t) {
            System.out.printf("    %s(%.4f) → error: %s%n", name, arg, t.getMessage());
        }
    }
}
