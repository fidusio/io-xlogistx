package io.xlogistx.ffm;

import io.xlogistx.ffm.NativeBindingFactory.BoundFunction;
import io.xlogistx.ffm.NativeBindingFactory.CType;
import io.xlogistx.ffm.NativeBindingFactory.NativeBindings;
import io.xlogistx.ffm.NativeBindingFactory.NativeFunction;
import io.xlogistx.ffm.NativeBindingFactory.Parameter;
import io.xlogistx.ffm.NativeBindingFactory.Strategy;
import org.zoxweb.shared.util.ParamUtil;

import java.lang.foreign.Arena;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;

/**
 * FFMUtil — High-level facade over {@link NativeBindingFactory} for loading
 * native shared libraries and introspecting their capabilities.
 *
 * <p>Two complementary APIs are provided:</p>
 *
 * <ol>
 *   <li><b>Fluent loader + {@link Library} wrapper</b> — Object-oriented entry point.
 *       Configure load strategy via {@link #library(String)}, then use the returned
 *       {@link Library} to list, inspect, invoke, and allocate native entities.
 *       <pre>{@code
 *       try (FFMUtil.Library libm = FFMUtil.library("/usr/lib/x86_64-linux-gnu/libm.so.6")
 *               .header("/usr/include/math.h")
 *               .includePath("/usr/include")
 *               .load()) {
 *           System.out.println(libm.capabilitiesReport());
 *           double r = (double) libm.handle("sin").invoke(Math.PI / 2);
 *       }
 *       }</pre>
 *   </li>
 *   <li><b>Static loaders + {@link LibraryCapabilities} record</b> — Functional entry
 *       point. One-line loaders, then pass the raw {@link NativeBindings} or a
 *       plain-data {@link LibraryCapabilities} snapshot around.
 *       <pre>{@code
 *       NativeBindings nb = FFMUtil.loadHeader("/usr/include/math.h",
 *                                              "/usr/lib/x86_64-linux-gnu/libm.so.6");
 *       LibraryCapabilities caps = FFMUtil.describe(nb);
 *       caps.functions().forEach(f -> System.out.println(f.signature()));
 *       }</pre>
 *   </li>
 * </ol>
 *
 * <p>Both styles sit on top of {@link NativeBindingFactory} and work with all
 * three discovery strategies ({@link Strategy#HEADER_PURE_JAVA},
 * {@link Strategy#HEADER_GCC}, {@link Strategy#DWARF}).</p>
 *
 * <p>Thread-safety: static methods are safe. {@link Library} is safe to read
 * after {@code load()}. {@link Loader} is not thread-safe.</p>
 */
public final class FFMUtil {

    private FFMUtil() {}


    // =========================================================================
    // FLUENT LOADER (approach 1)
    // =========================================================================

    /**
     * Starts a fluent load configuration for the given shared library.
     *
     * @param libraryPath Absolute path to the .so / .dylib / .dll file.
     * @return A {@link Loader} to configure discovery strategy and call {@link Loader#load()}.
     */
    public static Loader library(String libraryPath) {
        return new Loader(libraryPath);
    }

    /** Platform configuration */
    public enum Platform {
        LINUX_X86_64, LINUX_AARCH64, MACOS_X86_64, MACOS_AARCH64;

        /** Detects the current platform from JVM system properties. */
        public static Platform detect() {
            String os = System.getProperty("os.name", "").toLowerCase();
            String arch = System.getProperty("os.arch", "").toLowerCase();
            boolean mac = os.contains("mac") || os.contains("darwin");
            boolean aarch64 = arch.contains("aarch64") || arch.contains("arm64");
            if (mac) return aarch64 ? MACOS_AARCH64 : MACOS_X86_64;
            return aarch64 ? LINUX_AARCH64 : LINUX_X86_64;
        }
    }

    /**
     * Fluent loader. Pick exactly one discovery strategy:
     * <ul>
     *   <li>{@link #header(String)} — pure-Java header parsing (default if a header is set).</li>
     *   <li>{@link #useGcc()} — add to {@code header(...)} to use {@code gcc -E} instead.</li>
     *   <li>{@link #dwarf()} — use DWARF debug info embedded in the library.</li>
     * </ul>
     * Call {@link #load()} to execute. Not thread-safe.
     */
    public static final class Loader {
        private final String libraryPath;
        private String headerPath;
        private final List<String> includePaths = new ArrayList<>();
        private final Map<String, String> defines = new LinkedHashMap<>();
        private Platform platform = Platform.detect();
        private boolean useGcc = false;
        private boolean useDwarf = false;

        Loader(String libraryPath) {
            this.libraryPath = Optional.ofNullable(libraryPath)
                    .orElseThrow(() -> new IllegalArgumentException("libraryPath is required"));
        }

        /** Sets the C header file to parse (pure-Java or gcc strategy). */
        public Loader header(String path) { this.headerPath = path; return this; }

        /** Adds an include search path (like {@code -I}). */
        public Loader includePath(String path) { this.includePaths.add(path); return this; }

        /** Adds multiple include search paths. */
        public Loader includePaths(String... paths) {
            Collections.addAll(this.includePaths, paths); return this;
        }

        /** Defines a preprocessor macro (like {@code -D}). */
        public Loader define(String name, String value) {
            this.defines.put(name, value); return this;
        }

        /** Defines a flag macro (equivalent to {@code -Dname=1}). */
        public Loader define(String name) { return define(name, "1"); }

        /** Sets the target platform for type sizes and predefined macros. */
        public Loader platform(Platform p) { this.platform = p; return this; }

        /** Switches the header strategy to {@code gcc -E} preprocessing. */
        public Loader useGcc() { this.useGcc = true; return this; }

        /**
         * Switches to DWARF discovery. No header file is used — the library
         * must have been built with {@code -g} or have a matching {@code -dbgsym}.
         */
        public Loader dwarf() { this.useDwarf = true; return this; }

        /**
         * Executes the configured discovery pipeline and binds all exported functions.
         *
         * @return A ready-to-use {@link Library}. Close it to release the native arena.
         * @throws IllegalStateException if no strategy has been configured.
         * @throws Throwable any error raised by the underlying discovery pipeline.
         */
        public Library load() throws Throwable {
            if (useDwarf) {
                NativeBindings nb = NativeBindingFactory.fromDwarf(libraryPath).bind();
                return new Library(libraryPath, nb);
            }
            if (headerPath == null) {
                throw new IllegalStateException(
                        "No strategy configured: call .header(path) or .dwarf()");
            }
            var hb = NativeBindingFactory.fromHeader(headerPath)
                    .library(libraryPath)
                    .platform(platform);
            for (String ip : includePaths) hb.includePath(ip);
            for (var e : defines.entrySet()) hb.define(e.getKey(), e.getValue());
            if (useGcc) hb.useGcc();
            return new Library(libraryPath, hb.bind());
        }
    }


    // =========================================================================
    // LIBRARY WRAPPER (approach 1 result)
    // =========================================================================

    /**
     * Object-oriented wrapper around a loaded {@link NativeBindings}. Provides
     * listing, invocation, and allocation shortcuts on top of the raw bindings.
     *
     * <p>Backed by a shared {@link Arena} — closing this {@code Library} releases
     * the library mapping and invalidates every {@link MethodHandle} obtained from it.</p>
     */
    public static final class Library implements AutoCloseable {
        private final String libraryPath;
        private final NativeBindings bindings;

        Library(String libraryPath, NativeBindings bindings) {
            this.libraryPath = libraryPath;
            this.bindings = bindings;
        }

        /** Returns the path passed to the loader. */
        public String libraryPath() { return libraryPath; }

        /** Returns the strategy that produced these bindings. */
        public Strategy strategy() { return bindings.getStrategy(); }

        /** Returns the underlying raw bindings for advanced use. */
        public NativeBindings raw() { return bindings; }

        /** Returns the shared arena — use it to allocate strings, buffers, etc. */
        public Arena arena() { return bindings.getArena(); }

        // --- function access ---------------------------------------------------

        /** True if a function of this name was discovered and successfully bound. */
        public boolean hasFunction(String name) {
            return bindings.getBoundFunctionNames().contains(name);
        }

        /**
         * Returns the {@link MethodHandle} for {@code name}.
         * @throws NoSuchElementException if the function was not bound (missing,
         *         variadic, or failed to bind).
         */
        public MethodHandle handle(String name) { return bindings.getHandle(name); }

        /** Returns the full {@link BoundFunction} (signature + descriptor + handle) or null. */
        public BoundFunction function(String name) { return bindings.getFunction(name); }

        /**
         * Convenience: look up {@code name} and invoke with the given arguments.
         * Uses {@link MethodHandle#invokeWithArguments(Object...)}, which performs
         * basic boxing conversions but cannot auto-convert Java strings to
         * {@link MemorySegment} — allocate those explicitly via {@link #allocateString(String)}.
         */
        public Object invoke(String name, Object... args) throws Throwable {
            return handle(name).invokeWithArguments(args);
        }

        // --- struct access -----------------------------------------------------

        /** True if a struct of this name was discovered. */
        public boolean hasStruct(String name) { return bindings.getStructs().containsKey(name); }

        /** Returns the discovered struct or null. */
        public CType.Struct struct(String name) { return bindings.getStruct(name); }

        /** Returns a ready-to-use {@link MemoryLayout} for {@code name}. */
        public MemoryLayout structLayout(String name) { return bindings.getStructLayout(name); }

        /** Allocates a zeroed instance of {@code name} in the shared arena. */
        public MemorySegment allocateStruct(String name) { return bindings.allocateStruct(name); }

        // --- string helper -----------------------------------------------------

        /** Allocates a null-terminated C string in the shared arena. */
        public MemorySegment allocateString(String s) {
            return bindings.getArena().allocateFrom(s);
        }

        /** Allocates a raw byte buffer of {@code size} bytes in the shared arena. */
        public MemorySegment allocate(long size) {
            return bindings.getArena().allocate(size);
        }

        /** Allocates a single value slot in the shared arena. */
        public MemorySegment allocate(ValueLayout layout) {
            return bindings.getArena().allocate(layout);
        }

        // --- listings (structured) --------------------------------------------

        /** All bound (invocable) function names, in discovery order. */
        public List<String> listBoundFunctionNames() {
            return new ArrayList<>(bindings.getBoundFunctionNames());
        }

        /** All discovered struct names. */
        public List<String> listStructNames() {
            return new ArrayList<>(bindings.getStructs().keySet());
        }

        /** All discovered typedef names. */
        public List<String> listTypedefNames() {
            return new ArrayList<>(bindings.getTypedefs().keySet());
        }

        /** Functions discovered but NOT bound (variadic or missing symbol). */
        public List<String> listUnboundFunctionNames() {
            List<String> out = new ArrayList<>();
            for (NativeFunction f : bindings.getAllFunctions()) {
                if (!bindings.getBoundFunctionNames().contains(f.name())) out.add(f.name());
            }
            return out;
        }

        /** Rich, structured snapshot of everything the library exposes. */
        public LibraryCapabilities capabilities() {
            return describe(libraryPath, bindings);
        }

        // --- listings (pretty) -------------------------------------------------

        /** One-line summary from the underlying bindings. */
        public String summary() { return bindings.summary(); }

        /** Multi-line, human-readable report of the library's capabilities. */
        public String capabilitiesReport() { return capabilities().prettyReport(); }

        /** Concise one-line-per-function signature list. */
        public String functionsReport() {
            StringBuilder sb = new StringBuilder();
            for (NativeFunction f : bindings.getAllFunctions()) {
                boolean bound = bindings.getBoundFunctionNames().contains(f.name());
                sb.append(bound ? "  [BOUND]   " : "  [UNBOUND] ")
                        .append(f).append('\n');
            }
            return sb.toString();
        }

        /** Concise one-line-per-struct listing with sizes. */
        public String structsReport() {
            StringBuilder sb = new StringBuilder();
            for (var e : bindings.getStructs().entrySet()) {
                CType.Struct s = e.getValue();
                sb.append("  struct ").append(e.getKey())
                        .append(" (").append(s.byteSize()).append(" bytes, ")
                        .append(s.fields().size()).append(" fields)\n");
            }
            return sb.toString();
        }

        @Override
        public void close() { bindings.close(); }
    }


    // =========================================================================
    // STATIC LOADERS (approach 2)
    // =========================================================================

    /**
     * Loads a library using pure-Java header parsing.
     *
     * @param headerPath  Path to the .h file.
     * @param libraryPath Path to the .so / .dylib / .dll file.
     * @return Raw {@link NativeBindings}. Caller must {@code close()} it.
     */
    public static NativeBindings loadHeader(String headerPath, String libraryPath) throws Exception {
        return NativeBindingFactory.fromHeader(headerPath).library(libraryPath).bind();
    }

    /**
     * Loads a library using {@code gcc -E} for preprocessing, then parses
     * declarations in Java.
     */
    public static NativeBindings loadHeaderGcc(String headerPath, String libraryPath) throws Exception {
        return NativeBindingFactory.fromHeader(headerPath).library(libraryPath).useGcc().bind();
    }

    /**
     * Loads a library using DWARF debug info (requires libdw and debug symbols).
     */
    public static NativeBindings loadDwarf(String libraryPath) throws Throwable {
        return NativeBindingFactory.fromDwarf(libraryPath).bind();
    }


    // =========================================================================
    // CAPABILITIES RECORD (approach 2 result)
    // =========================================================================

    /** Name and type of a single function parameter. */
    public record ParamInfo(String name, String type) {}

    /**
     * Metadata for a discovered function.
     *
     * @param bound {@code true} when a {@link MethodHandle} was successfully created
     *              (symbol exported and descriptor buildable). Variadic functions are
     *              always {@code false} — FFM requires a separate specialized handle
     *              per call site for those.
     */
    public record FunctionInfo(String name, String returnType, List<ParamInfo> parameters,
                               boolean variadic, boolean bound, String signature) {}

    /** One field inside a struct. */
    public record FieldInfo(String name, String type, long offset) {}

    /** A struct and its fields. */
    public record StructInfo(String name, long byteSize, List<FieldInfo> fields) {}

    /** A typedef alias to another type. */
    public record TypedefInfo(String name, String underlying) {}

    /** One enum constant. */
    public record EnumConstantInfo(String name, long value) {}

    /**
     * An enum discovered through a typedef (for example {@code typedef enum {...} Foo_e}).
     * Untyped / anonymous enums are not currently exposed by the binder.
     */
    public record EnumInfo(String name, int byteSize, List<EnumConstantInfo> constants) {}

    /**
     * Plain-data snapshot of everything a loaded library exposes. Safe to serialize,
     * log, or pass across module boundaries without holding a reference to the live
     * arena.
     */
    public record LibraryCapabilities(
            String libraryPath,
            Strategy strategy,
            List<FunctionInfo> functions,
            List<StructInfo> structs,
            List<TypedefInfo> typedefs,
            List<EnumInfo> enums,
            int boundFunctionCount,
            int totalFunctionCount
    ) {
        /** Human-readable multi-section report. */
        public String prettyReport() {
            StringBuilder sb = new StringBuilder();
            sb.append("═══════════════════════════════════════════════════════════════\n");
            sb.append("Library: ").append(libraryPath).append('\n');
            sb.append("Strategy: ").append(strategy).append('\n');
            sb.append("Functions: ").append(boundFunctionCount)
                    .append(" bound / ").append(totalFunctionCount).append(" total\n");
            sb.append("Structs: ").append(structs.size())
                    .append(" | Typedefs: ").append(typedefs.size())
                    .append(" | Enums: ").append(enums.size()).append('\n');
            sb.append("═══════════════════════════════════════════════════════════════\n");

            if (!functions.isEmpty()) {
                sb.append("\n── Functions ──────────────────────────────────────────────────\n");
                for (FunctionInfo f : functions) {
                    sb.append(f.bound() ? "  [BOUND]   " : "  [UNBOUND] ")
                            .append(f.signature()).append('\n');
                }
            }
            if (!structs.isEmpty()) {
                sb.append("\n── Structs ────────────────────────────────────────────────────\n");
                for (StructInfo s : structs) {
                    sb.append("  struct ").append(s.name())
                            .append(" (").append(s.byteSize()).append(" bytes)\n");
                    for (FieldInfo field : s.fields()) {
                        sb.append("      +").append(field.offset()).append("  ")
                                .append(field.type()).append(' ').append(field.name()).append('\n');
                    }
                }
            }
            if (!enums.isEmpty()) {
                sb.append("\n── Enums ──────────────────────────────────────────────────────\n");
                for (EnumInfo e : enums) {
                    sb.append("  enum ").append(e.name())
                            .append(" (").append(e.byteSize()).append(" bytes)\n");
                    for (EnumConstantInfo c : e.constants()) {
                        sb.append("      ").append(c.name()).append(" = ").append(c.value()).append('\n');
                    }
                }
            }
            if (!typedefs.isEmpty()) {
                sb.append("\n── Typedefs ───────────────────────────────────────────────────\n");
                for (TypedefInfo t : typedefs) {
                    sb.append("  typedef ").append(t.underlying())
                            .append(" ").append(t.name()).append('\n');
                }
            }
            return sb.toString();
        }
    }


    // =========================================================================
    // DESCRIBE — converts raw bindings into the plain-data capabilities snapshot
    // =========================================================================

    /** Builds a capabilities snapshot from the bindings (library path unknown). */
    public static LibraryCapabilities describe(NativeBindings bindings) {
        return describe("<unknown>", bindings);
    }

    /** Builds a capabilities snapshot from the bindings using the supplied library path. */
    public static LibraryCapabilities describe(String libraryPath, NativeBindings bindings) {
        List<FunctionInfo> functions = new ArrayList<>();
        var boundNames = bindings.getBoundFunctionNames();
        for (NativeFunction f : bindings.getAllFunctions()) {
            List<ParamInfo> params = new ArrayList<>();
            for (Parameter p : f.params()) {
                params.add(new ParamInfo(p.name(), NativeBindingFactory.typeToString(p.type())));
            }
            functions.add(new FunctionInfo(
                    f.name(),
                    NativeBindingFactory.typeToString(f.returnType()),
                    params,
                    f.variadic(),
                    boundNames.contains(f.name()),
                    f.toString()));
        }

        List<StructInfo> structs = new ArrayList<>();
        for (var e : bindings.getStructs().entrySet()) {
            CType.Struct s = e.getValue();
            List<FieldInfo> fields = new ArrayList<>();
            for (var field : s.fields()) {
                fields.add(new FieldInfo(field.name(),
                        NativeBindingFactory.typeToString(field.type()),
                        field.offset()));
            }
            structs.add(new StructInfo(e.getKey(), s.byteSize(), fields));
        }

        List<TypedefInfo> typedefs = new ArrayList<>();
        List<EnumInfo> enums = new ArrayList<>();
        for (var e : bindings.getTypedefs().entrySet()) {
            CType underlying = unwrap(e.getValue());
            if (underlying instanceof CType.Enum en) {
                List<EnumConstantInfo> consts = new ArrayList<>();
                for (var c : en.constants()) consts.add(new EnumConstantInfo(c.name(), c.value()));
                enums.add(new EnumInfo(e.getKey(), en.byteSize(), consts));
            }
            typedefs.add(new TypedefInfo(e.getKey(),
                    NativeBindingFactory.typeToString(e.getValue())));
        }

        return new LibraryCapabilities(
                libraryPath,
                bindings.getStrategy(),
                Collections.unmodifiableList(functions),
                Collections.unmodifiableList(structs),
                Collections.unmodifiableList(typedefs),
                Collections.unmodifiableList(enums),
                boundNames.size(),
                bindings.getAllFunctions().size());
    }

    private static CType unwrap(CType t) {
        return switch (t) {
            case CType.Typedef td -> unwrap(td.underlying());
            case CType.Qualified q -> unwrap(q.underlying());
            default -> t;
        };
    }


    // =========================================================================
    // MAIN — CLI driver that prints the capabilities of a shared library
    // =========================================================================

    private static final String USAGE = """
            FFMUtil — list the capabilities of a native shared library.

            Usage:
              FFMUtil lib=<path> [strategy=pure|gcc|dwarf] [header=<path>] \\
                      [include=<path1,path2,...>] [define=NAME=VAL,NAME2=VAL2,...] \\
                      [platform=linux-x86_64|linux-aarch64|macos-x86_64|macos-aarch64] \\
                      [show=all|summary|functions|structs|typedefs|enums]

            Required:
              lib=<path>                   Path to .so / .dylib / .dll to bind against.

            Strategy:
              strategy=pure   (default when header= is supplied)
                              Pure-Java preprocessor + parser. Needs header=<path>.
              strategy=gcc    Use gcc -E preprocessing instead of the Java one.
                              Needs header=<path>. Requires gcc on PATH.
              strategy=dwarf  (default when no header= is supplied)
                              Parse DWARF debug info from the library via libdw.
                              Library must be built with -g or have a -dbgsym package.
                              Linux-only.

            Optional (header strategies only):
              header=<path>                Path to the .h file to parse.
              include=<p1,p2,...>          Comma-separated -I include paths.
              define=N=V,N2=V2             Comma-separated -D macros (use just "N" for flag).
              platform=<id>                Target platform (default: linux-x86_64).

            Output:
              show=all       (default)     Full capabilities report.
              show=summary                 One-line summary only.
              show=functions|structs|typedefs|enums
                                           Print just that section.

            Debug (header strategies only):
              debug=true                   Print preprocessed length, token count,
                                           and first 400 chars of preprocessed output.
              dump=<path>                  Write full preprocessed output to <path>.

            Examples:
              FFMUtil lib=/usr/lib/x86_64-linux-gnu/libm.so.6 header=/usr/include/math.h
              FFMUtil lib=/usr/lib/x86_64-linux-gnu/libm.so.6 strategy=dwarf show=summary
              FFMUtil lib=libpcap.so header=/usr/include/pcap/pcap.h \\
                      include=/usr/include define=_GNU_SOURCE show=functions
            """;

    public static void main(String[] args) throws Throwable {
        if (args.length == 0 || hasHelpFlag(args)) {
            System.out.println(USAGE);
            return;
        }

        ParamUtil.ParamMap params = ParamUtil.parse("=", args);
        String lib = params.stringValue("lib", true);
        if (lib == null) {
            System.err.println("ERROR: lib=<path> is required.\n");
            System.out.println(USAGE);
            System.exit(2);
            return;
        }

        String header = params.stringValue("header", true);
        String strategyStr = params.stringValue("strategy", true);
        String includeStr = params.stringValue("include", true);
        String defineStr = params.stringValue("define", true);
        String platformStr = params.stringValue("platform", true);
        String dumpPath = params.stringValue("dump", true);
        boolean debug = "true".equalsIgnoreCase(params.stringValue("debug", true));
        String show = Optional.ofNullable(params.stringValue("show", true))
                .orElse("all")
                .toLowerCase(Locale.ROOT);

        // Resolve strategy with sensible defaults
        if (strategyStr == null) {
            strategyStr = (header != null) ? "pure" : "dwarf";
        }
        strategyStr = strategyStr.toLowerCase(Locale.ROOT);

        Loader loader = library(lib);

        switch (strategyStr) {
            case "pure" -> {
                requireHeader(header, "pure");
                loader.header(header);
            }
            case "gcc" -> {
                requireHeader(header, "gcc");
                loader.header(header).useGcc();
            }
            case "dwarf" -> loader.dwarf();
            default -> {
                System.err.println("ERROR: unknown strategy: " + strategyStr);
                System.exit(2);
                return;
            }
        }

        if (platformStr != null) loader.platform(parsePlatform(platformStr));

        if (includeStr != null && !includeStr.isBlank()) {
            for (String p : includeStr.split(",")) {
                String trimmed = p.trim();
                if (!trimmed.isEmpty()) loader.includePath(trimmed);
            }
        }

        if (defineStr != null && !defineStr.isBlank()) {
            for (String d : defineStr.split(",")) {
                String entry = d.trim();
                if (entry.isEmpty()) continue;
                int eq = entry.indexOf('=');
                if (eq < 0) loader.define(entry);
                else loader.define(entry.substring(0, eq), entry.substring(eq + 1));
            }
        }

        if ((debug || dumpPath != null) && header != null && !"dwarf".equals(strategyStr)) {
            String preprocessed = runPreprocessor(header, strategyStr, platformStr,
                    includeStr, defineStr);
            if (dumpPath != null) {
                java.nio.file.Files.writeString(java.nio.file.Path.of(dumpPath), preprocessed);
                System.out.println("Dumped " + preprocessed.length() + " chars of preprocessed "
                        + "output to: " + dumpPath);
            }
            if (debug) {
                List<CHeaderParser.Token> tokens = CHeaderParser.tokenize(preprocessed);
                int openCount = countOccurrences(preprocessed, "/*");
                int closeCount = countOccurrences(preprocessed, "*/");
                System.out.println("[debug] preprocessed length : " + preprocessed.length() + " chars");
                System.out.println("[debug] tokens              : " + tokens.size());
                System.out.println("[debug] /* count            : " + openCount);
                System.out.println("[debug] */ count            : " + closeCount
                        + (openCount != closeCount ? "  ← MISMATCH (unbalanced comments)" : ""));
                int len = preprocessed.length();
                System.out.println("[debug] first 400 chars of preprocessed output:");
                System.out.println("──────────────────────────────────────────────────────");
                System.out.println(preprocessed.substring(0, Math.min(400, len)));
                System.out.println("──────────────────────────────────────────────────────");
                System.out.println("[debug] last 400 chars of preprocessed output:");
                System.out.println("──────────────────────────────────────────────────────");
                System.out.println(preprocessed.substring(Math.max(0, len - 400), len));
                System.out.println("──────────────────────────────────────────────────────");
            }
        }

        try (Library library = loader.load()) {
            switch (show) {
                case "summary" -> System.out.println(library.summary());
                case "functions" -> {
                    System.out.println(library.summary());
                    System.out.println();
                    System.out.print(library.functionsReport());
                }
                case "structs" -> {
                    System.out.println(library.summary());
                    System.out.println();
                    System.out.print(library.structsReport());
                }
                case "typedefs" -> {
                    System.out.println(library.summary());
                    System.out.println();
                    for (TypedefInfo t : library.capabilities().typedefs()) {
                        System.out.println("  typedef " + t.underlying() + " " + t.name());
                    }
                }
                case "enums" -> {
                    System.out.println(library.summary());
                    System.out.println();
                    for (EnumInfo e : library.capabilities().enums()) {
                        System.out.println("  enum " + e.name() + " (" + e.byteSize() + " bytes)");
                        for (EnumConstantInfo c : e.constants()) {
                            System.out.println("      " + c.name() + " = " + c.value());
                        }
                    }
                }
                case "all" -> System.out.println(library.capabilitiesReport());
                default -> {
                    System.err.println("ERROR: unknown show=" + show);
                    System.exit(2);
                }
            }
        }
    }

    private static String runPreprocessor(String header, String strategy, String platformStr,
                                           String includeStr, String defineStr) throws Exception {
        if ("gcc".equals(strategy)) {
            String[] includes = includeStr == null ? new String[0] : includeStr.split(",");
            return CHeaderParser.preprocess(header, includes);
        }
        CPreprocessor pp = platformStr != null
                ? new CPreprocessor(parsePlatform(platformStr))
                : new CPreprocessor();
        if (includeStr != null && !includeStr.isBlank()) {
            for (String p : includeStr.split(",")) {
                String t = p.trim();
                if (!t.isEmpty()) pp.addUserIncludePath(t);
            }
        }
        if (defineStr != null && !defineStr.isBlank()) {
            for (String d : defineStr.split(",")) {
                String entry = d.trim();
                if (entry.isEmpty()) continue;
                int eq = entry.indexOf('=');
                if (eq < 0) pp.define(entry);
                else pp.define(entry.substring(0, eq), entry.substring(eq + 1));
            }
        }
        return pp.preprocess(header);
    }

    private static int countOccurrences(String text, String needle) {
        int count = 0, idx = 0;
        while ((idx = text.indexOf(needle, idx)) != -1) { count++; idx += needle.length(); }
        return count;
    }

    private static boolean hasHelpFlag(String[] args) {
        for (String a : args) {
            if (a.equals("-h") || a.equals("--help") || a.equals("help") || a.equals("?")) {
                return true;
            }
        }
        return false;
    }

    private static void requireHeader(String header, String strategy) {
        if (header == null) {
            System.err.println("ERROR: strategy=" + strategy + " requires header=<path>\n");
            System.out.println(USAGE);
            System.exit(2);
        }
    }

    private static Platform parsePlatform(String s) {
        return switch (s.toLowerCase(Locale.ROOT)) {
            case "linux-x86_64", "linux_x86_64", "linux-x64" -> Platform.LINUX_X86_64;
            case "linux-aarch64", "linux_aarch64", "linux-arm64" -> Platform.LINUX_AARCH64;
            case "macos-x86_64", "macos_x86_64", "macos-x64" -> Platform.MACOS_X86_64;
            case "macos-aarch64", "macos_aarch64", "macos-arm64" -> Platform.MACOS_AARCH64;
            default -> throw new IllegalArgumentException("Unknown platform: " + s);
        };
    }
}
