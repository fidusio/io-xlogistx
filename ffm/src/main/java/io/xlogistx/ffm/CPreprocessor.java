package io.xlogistx.ffm;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;

/**
 * CPreprocessor — A pure Java implementation of the C preprocessor.
 *
 * Handles:
 *   - #include "file" and #include &lt;file&gt; with configurable search paths
 *   - #define NAME value (object-like macros)
 *   - #define NAME(args) body (function-like macros)
 *   - #undef NAME
 *   - #if / #ifdef / #ifndef / #elif / #else / #endif with expression evaluation
 *   - ## token pasting
 *   - # stringification
 *   - #pragma once
 *   - Include guards (standard #ifndef pattern)
 *   - Predefined platform macros (__linux__, __x86_64__, __SIZEOF_LONG__, etc.)
 *   - Line continuation (backslash-newline)
 *   - Variadic macros (__VA_ARGS__)
 *   - GCC __attribute__, __extension__, __builtin_* (passed through)
 *
 * This replaces gcc -E so the entire header-to-FFM pipeline is pure Java.
 * The output format matches gcc -E -P (flat C declarations, no line markers).
 *
 * Thread-safety: NOT thread-safe. Create one instance per preprocessing task.
 */


public class CPreprocessor {

    // =========================================================================
    // CONFIGURATION
    // =========================================================================

    /** Include search paths for #include &lt;...&gt; (system headers) */
    private final List<Path> systemIncludePaths = new ArrayList<>();

    /** Include search paths for #include "..." (user headers), searched first */
    private final List<Path> userIncludePaths = new ArrayList<>();

    /** Predefined macros: name → Macro */
    private final Map<String, Macro> macros = new LinkedHashMap<>();

    /** Files already included via #pragma once or include guards */
    private final Set<String> onceGuards = new HashSet<>();

    /** Include guard detection: tracks #ifndef at top of file */
    private final Map<String, String> includeGuardCandidates = new HashMap<>();

    /** Current include depth (prevents infinite recursion) */
    private int includeDepth = 0;
    private static final int MAX_INCLUDE_DEPTH = 64;

    /** Macro expansion depth (prevents infinite recursion) */
    private int expansionDepth = 0;
    private static final int MAX_EXPANSION_DEPTH = 256;

    /** Output buffer */
    private final StringBuilder output = new StringBuilder();

    /** Conditional compilation stack */
    private final Deque<CondState> condStack = new ArrayDeque<>();


    // =========================================================================
    // MACRO REPRESENTATION
    // =========================================================================

    record Macro(String name, List<String> params, boolean variadic, String body, boolean predefined) {
        /** Object-like macro (no parameters) */
        static Macro objectLike(String name, String body) {
            return new Macro(name, null, false, body, false);
        }

        /** Function-like macro with parameters */
        static Macro functionLike(String name, List<String> params, boolean variadic, String body) {
            return new Macro(name, params, variadic, body, false);
        }

        /** Predefined macro (cannot be #undef'd) */
        static Macro predefined(String name, String body) {
            return new Macro(name, null, false, body, true);
        }

        boolean isFunctionLike() { return params != null; }
    }

    /** State for conditional compilation (#if/#ifdef/#else/#endif) */
    enum CondState {
        ACTIVE,         // Currently outputting code
        INACTIVE,       // Skipping code (condition was false)
        DONE            // Already found true branch, skip remaining #elif/#else
    }


    // =========================================================================
    // CONSTRUCTOR + CONFIGURATION
    // =========================================================================

    public CPreprocessor() {
        this(FFMUtil.Platform.detect());
    }

    public CPreprocessor(FFMUtil.Platform platform) {
        registerPlatformMacros(platform);
        registerStandardPaths(platform);
    }

    /**
     * Adds a system include path (#include &lt;...&gt; search).
     */
    public CPreprocessor addSystemIncludePath(String path) {
        systemIncludePaths.add(Path.of(path));
        return this;
    }

    /**
     * Adds a user include path (#include "..." search).
     */
    public CPreprocessor addUserIncludePath(String path) {
        userIncludePaths.add(Path.of(path));
        return this;
    }

    /**
     * Defines an object-like macro.
     */
    public CPreprocessor define(String name, String value) {
        macros.put(name, Macro.objectLike(name, value));
        return this;
    }

    /**
     * Defines a macro with no value (flag macro, like -DFOO).
     */
    public CPreprocessor define(String name) {
        return define(name, "1");
    }

    /**
     * Undefines a macro.
     */
    public CPreprocessor undefine(String name) {
        Macro m = macros.get(name);
        if (m != null && !m.predefined()) macros.remove(name);
        return this;
    }


    // =========================================================================
    // PLATFORM MACROS — Predefined macros for target platform
    // =========================================================================

    private void registerPlatformMacros(FFMUtil.Platform platform) {
        // Standard C predefined
        predef("__STDC__", "1");
        predef("__STDC_VERSION__", "201710L");   // C17
        predef("__STDC_HOSTED__", "1");

        // Common compiler identification (pretend to be GCC for compatibility)
        predef("__GNUC__", "13");
        predef("__GNUC_MINOR__", "0");
        predef("__GNUC_PATCHLEVEL__", "0");

        // NULL
        predef("NULL", "((void*)0)");

        // Standard type limits that headers often check
        predef("__CHAR_BIT__", "8");
        predef("__SCHAR_MAX__", "127");
        predef("__SHRT_MAX__", "32767");
        predef("__INT_MAX__", "2147483647");
        predef("__LONG_MAX__", "9223372036854775807L");
        predef("__LONG_LONG_MAX__", "9223372036854775807LL");

        // Size macros — critical for correct type resolution
        predef("__SIZEOF_SHORT__", "2");
        predef("__SIZEOF_INT__", "4");
        predef("__SIZEOF_LONG__", "8");
        predef("__SIZEOF_LONG_LONG__", "8");
        predef("__SIZEOF_FLOAT__", "4");
        predef("__SIZEOF_DOUBLE__", "8");
        predef("__SIZEOF_LONG_DOUBLE__", "16");
        predef("__SIZEOF_POINTER__", "8");
        predef("__SIZEOF_SIZE_T__", "8");
        predef("__SIZEOF_WCHAR_T__", "4");

        // Integer width macros
        predef("__INT8_TYPE__", "signed char");
        predef("__INT16_TYPE__", "short");
        predef("__INT32_TYPE__", "int");
        predef("__INT64_TYPE__", "long");
        predef("__UINT8_TYPE__", "unsigned char");
        predef("__UINT16_TYPE__", "unsigned short");
        predef("__UINT32_TYPE__", "unsigned int");
        predef("__UINT64_TYPE__", "unsigned long");
        predef("__INTPTR_TYPE__", "long");
        predef("__UINTPTR_TYPE__", "unsigned long");
        predef("__SIZE_TYPE__", "unsigned long");
        predef("__PTRDIFF_TYPE__", "long");

        // Common feature-test macros
        predef("_GNU_SOURCE", "1");
        predef("__GLIBC__", "2");
        predef("__GLIBC_MINOR__", "38");

        // Byte order
        predef("__BYTE_ORDER__", "1234");
        predef("__ORDER_LITTLE_ENDIAN__", "1234");
        predef("__ORDER_BIG_ENDIAN__", "4321");

        // GCC builtins and attributes — define as empty to pass through
        predef("__attribute__(...)", "");
        predef("__extension__", "");
        predef("__restrict", "restrict");
        predef("__restrict__", "restrict");
        predef("__inline", "inline");
        predef("__inline__", "inline");
        predef("__volatile__", "volatile");
        predef("__const", "const");
        predef("__const__", "const");
        predef("__signed__", "signed");
        predef("__typeof__", "typeof");
        predef("__asm__(...)", "");
        predef("__asm(...)", "");
        predef("__builtin_va_list", "void*");
        predef("__builtin_va_start(...)", "");
        predef("__builtin_va_end(...)", "");
        predef("__builtin_va_arg(...)", "");
        predef("__builtin_offsetof(...)", "0");
        predef("__builtin_types_compatible_p(...)", "0");
        predef("__builtin_expect(...)", "0");
        predef("__THROW", "");
        predef("__nonnull(...)", "");
        predef("__wur", "");
        predef("__fortify_function", "");
        predef("__artificial__", "");
        predef("__always_inline__", "");
        predef("__noinline__", "");

        // Platform-specific
        switch (platform) {
            case LINUX_X86_64 -> {
                predef("__linux__", "1");
                predef("__linux", "1");
                predef("linux", "1");
                predef("__unix__", "1");
                predef("__unix", "1");
                predef("unix", "1");
                predef("__gnu_linux__", "1");
                predef("__x86_64__", "1");
                predef("__x86_64", "1");
                predef("__amd64__", "1");
                predef("__amd64", "1");
                predef("__LP64__", "1");
                predef("_LP64", "1");
            }
            case LINUX_AARCH64 -> {
                predef("__linux__", "1");
                predef("__linux", "1");
                predef("linux", "1");
                predef("__unix__", "1");
                predef("__unix", "1");
                predef("unix", "1");
                predef("__gnu_linux__", "1");
                predef("__aarch64__", "1");
                predef("__ARM_64BIT_STATE", "1");
                predef("__LP64__", "1");
                predef("_LP64", "1");
            }
            case MACOS_X86_64 -> {
                predef("__APPLE__", "1");
                predef("__MACH__", "1");
                predef("__x86_64__", "1");
                predef("__LP64__", "1");
                predef("__SIZEOF_LONG__", "8");
            }
            case MACOS_AARCH64 -> {
                predef("__APPLE__", "1");
                predef("__MACH__", "1");
                predef("__aarch64__", "1");
                predef("__arm64__", "1");
                predef("__LP64__", "1");
                predef("__SIZEOF_LONG__", "8");
            }
        }
    }

    private void predef(String nameOrSig, String body) {
        // Handle function-like predefined macros: __attribute__(...)
        int parenIdx = nameOrSig.indexOf('(');
        if (parenIdx > 0) {
            String name = nameOrSig.substring(0, parenIdx);
            String paramStr = nameOrSig.substring(parenIdx + 1, nameOrSig.length() - 1);
            boolean variadic = paramStr.contains("...");
            List<String> params = new ArrayList<>();
            if (!paramStr.isEmpty() && !paramStr.equals("...")) {
                for (String p : paramStr.split(",")) {
                    p = p.trim();
                    if (!p.equals("...")) params.add(p);
                }
            }
            macros.put(name, new Macro(name, params, variadic, body, true));
        } else {
            macros.put(nameOrSig, new Macro(nameOrSig, null, false, body, true));
        }
    }

    private void registerStandardPaths(FFMUtil.Platform platform) {
        switch (platform) {
            case LINUX_X86_64 -> {
                addSystemIncludePath("/usr/include");
                addSystemIncludePath("/usr/include/x86_64-linux-gnu");
                addLinuxGccIncludes("x86_64-linux-gnu");
                addSystemIncludePath("/usr/local/include");
            }
            case LINUX_AARCH64 -> {
                addSystemIncludePath("/usr/include");
                addSystemIncludePath("/usr/include/aarch64-linux-gnu");
                addLinuxGccIncludes("aarch64-linux-gnu");
                addSystemIncludePath("/usr/local/include");
            }
            case MACOS_X86_64, MACOS_AARCH64 -> {
                addSystemIncludePath("/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include");
                addSystemIncludePath("/usr/local/include");
                addSystemIncludePath("/opt/homebrew/include");
            }
        }
    }

    /** Scans for installed GCC include directories (stdint.h, stddef.h live here). */
    private void addLinuxGccIncludes(String triple) {
        Path gccBase = Path.of("/usr/lib/gcc/" + triple);
        if (Files.isDirectory(gccBase)) {
            try (var dirs = Files.list(gccBase)) {
                dirs.filter(Files::isDirectory)
                    .sorted(Comparator.reverseOrder()) // prefer newest version
                    .forEach(ver -> {
                        Path inc = ver.resolve("include");
                        if (Files.isDirectory(inc)) addSystemIncludePath(inc.toString());
                    });
            } catch (IOException ignored) {}
        }
    }


    // =========================================================================
    // MAIN ENTRY POINT
    // =========================================================================

    /**
     * Preprocesses a C header file and returns the flat output.
     *
     * @param headerPath Path to the .h file
     * @return Preprocessed C source (equivalent to gcc -E -P output)
     */
    public String preprocess(String headerPath) throws IOException {
        output.setLength(0);
        condStack.clear();
        includeDepth = 0;

        Path path = Path.of(headerPath).toAbsolutePath();
        processFile(path);

        return output.toString();
    }

    /**
     * Preprocesses a C header from a string (for testing or inline headers).
     */
    public String preprocessString(String source, String virtualPath) throws IOException {
        output.setLength(0);
        condStack.clear();
        includeDepth = 0;

        processSource(source, Path.of(virtualPath));

        return output.toString();
    }


    // =========================================================================
    // FILE PROCESSING
    // =========================================================================

    private void processFile(Path filePath) throws IOException {
        // Normalize for #pragma once / include guard tracking
        String canonical = filePath.toAbsolutePath().normalize().toString();

        // Check #pragma once
        if (onceGuards.contains(canonical)) return;

        // Check include depth
        if (includeDepth >= MAX_INCLUDE_DEPTH) {
            // Silently skip — deeply nested includes are usually transitive system headers
            return;
        }

        if (!Files.exists(filePath)) {
            // Silently skip missing headers — many system headers include optional ones
            return;
        }

        String source = Files.readString(filePath);
        processSource(source, filePath);
    }

    private void processSource(String source, Path filePath) throws IOException {
        String canonical = filePath.toAbsolutePath().normalize().toString();

        // Join line continuations
        source = joinLineContinuations(source);

        // Strip C/C++ comments BEFORE line-by-line directive scanning, so that
        // directive-like text inside a comment (e.g. "#define X" embedded in
        // glibc's cdefs.h explanatory comment) isn't treated as a real directive.
        source = stripComments(source);

        // Split into lines
        String[] lines = source.split("\n", -1);

        // Track include guard: first non-empty line is #ifndef GUARD
        String guardCandidate = null;
        boolean firstDirective = true;

        includeDepth++;

        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            String trimmed = line.trim();

            if (trimmed.isEmpty()) {
                if (isActive()) output.append("\n");
                continue;
            }

            if (trimmed.startsWith("#")) {
                String directive = trimmed.substring(1).trim();

                // Include guard detection
                if (firstDirective && directive.startsWith("ifndef ")) {
                    guardCandidate = directive.substring(7).trim();
                    // Check if next meaningful line is #define GUARD
                    for (int j = i + 1; j < lines.length; j++) {
                        String next = lines[j].trim();
                        if (next.isEmpty()) continue;
                        if (next.equals("#define " + guardCandidate) ||
                                next.equals("# define " + guardCandidate)) {
                            // This is an include guard
                            if (onceGuards.contains(canonical)) {
                                includeDepth--;
                                return; // already included
                            }
                            includeGuardCandidates.put(canonical, guardCandidate);
                        }
                        break;
                    }
                }
                firstDirective = false;

                processDirective(directive, filePath);
            } else {
                firstDirective = false;
                if (isActive()) {
                    String expanded = expandMacros(trimmed);
                    output.append(expanded).append("\n");
                }
            }
        }

        // If we tracked an include guard, mark this file
        if (includeGuardCandidates.containsKey(canonical)) {
            onceGuards.add(canonical);
        }

        includeDepth--;
    }

    /**
     * Strips C-style {@code /* ... *}{@code /} block comments and {@code //} line
     * comments, preserving line numbering by keeping the newlines inside them.
     * Must run BEFORE line-by-line directive processing, otherwise a directive-like
     * token inside a comment (e.g. {@code #define} inside glibc's explanatory
     * comment in {@code cdefs.h}) would be misinterpreted as a real directive.
     * String and character literals are respected so that {@code "//"} inside a
     * string is not treated as a line-comment start.
     */
    private String stripComments(String source) {
        StringBuilder sb = new StringBuilder(source.length());
        int i = 0, n = source.length();
        while (i < n) {
            char c = source.charAt(i);

            // Block comment
            if (c == '/' && i + 1 < n && source.charAt(i + 1) == '*') {
                i += 2;
                while (i + 1 < n && !(source.charAt(i) == '*' && source.charAt(i + 1) == '/')) {
                    if (source.charAt(i) == '\n') sb.append('\n');
                    i++;
                }
                i = Math.min(i + 2, n);
                sb.append(' ');
                continue;
            }

            // Line comment
            if (c == '/' && i + 1 < n && source.charAt(i + 1) == '/') {
                while (i < n && source.charAt(i) != '\n') i++;
                continue;
            }

            // String literal — pass through untouched
            if (c == '"') {
                sb.append(c); i++;
                while (i < n) {
                    char cc = source.charAt(i);
                    sb.append(cc);
                    if (cc == '\\' && i + 1 < n) { sb.append(source.charAt(i + 1)); i += 2; continue; }
                    i++;
                    if (cc == '"') break;
                }
                continue;
            }

            // Character literal — pass through untouched
            if (c == '\'') {
                sb.append(c); i++;
                while (i < n) {
                    char cc = source.charAt(i);
                    sb.append(cc);
                    if (cc == '\\' && i + 1 < n) { sb.append(source.charAt(i + 1)); i += 2; continue; }
                    i++;
                    if (cc == '\'') break;
                }
                continue;
            }

            sb.append(c);
            i++;
        }
        return sb.toString();
    }

    /**
     * Joins backslash-newline continuations into single logical lines.
     */
    private String joinLineContinuations(String source) {
        StringBuilder sb = new StringBuilder(source.length());
        int i = 0;
        while (i < source.length()) {
            if (source.charAt(i) == '\\' && i + 1 < source.length() && source.charAt(i + 1) == '\n') {
                i += 2; // skip backslash and newline
            } else {
                sb.append(source.charAt(i));
                i++;
            }
        }
        return sb.toString();
    }


    // =========================================================================
    // DIRECTIVE PROCESSING
    // =========================================================================

    private void processDirective(String directive, Path currentFile) throws IOException {
        // Strip leading/trailing whitespace and normalize tabs to spaces.
        // System headers (e.g. glibc cdefs.h) use tabs between directive keywords
        // and arguments (#ifdef\t__cplusplus).  The startsWith() checks below
        // match a space, so tabs must be normalized first.
        directive = directive.trim().replace('\t', ' ');

        if (directive.startsWith("include")) {
            if (isActive()) processInclude(directive, currentFile);
        } else if (directive.startsWith("define")) {
            if (isActive()) processDefine(directive);
        } else if (directive.startsWith("undef ")) {
            if (isActive()) processUndef(directive);
        } else if (directive.startsWith("ifdef ")) {
            processIfdef(directive, false);
        } else if (directive.startsWith("ifndef ")) {
            processIfdef(directive, true);
        } else if (directive.startsWith("if ")) {
            processIf(directive);
        } else if (directive.startsWith("elif ")) {
            processElif(directive);
        } else if (directive.equals("else")) {
            processElse();
        } else if (directive.equals("endif")) {
            processEndif();
        } else if (directive.startsWith("pragma")) {
            if (isActive()) processPragma(directive, currentFile);
        } else if (directive.startsWith("error")) {
            if (isActive()) {
                // #error — we'll just skip rather than throwing
            }
        } else if (directive.startsWith("warning")) {
            // Skip
        }
        // Ignore unknown directives (#line, #ident, etc.)
    }


    // =========================================================================
    // #include
    // =========================================================================

    private void processInclude(String directive, Path currentFile) throws IOException {
        // #include <file> or #include "file"
        String rest = directive.substring("include".length()).trim();

        // Expand macros in the include path (handles cases like #include MACRO_HEADER)
        rest = expandMacros(rest).trim();

        boolean isSystem;
        String filename;

        if (rest.startsWith("<") && rest.contains(">")) {
            isSystem = true;
            filename = rest.substring(1, rest.indexOf('>'));
        } else if (rest.startsWith("\"") && rest.lastIndexOf('"') > 0) {
            isSystem = false;
            filename = rest.substring(1, rest.lastIndexOf('"'));
        } else {
            return; // unrecognized format
        }

        Path resolved = resolveInclude(filename, isSystem, currentFile);
        if (resolved != null) {
            processFile(resolved);
        }
    }

    /**
     * Resolves an include path using the search path rules:
     *   #include "file" — search: current dir → user paths → system paths
     *   #include &lt;file&gt; — search: system paths only
     */
    private Path resolveInclude(String filename, boolean isSystem, Path currentFile) {
        if (!isSystem) {
            // First search relative to current file's directory
            Path relative = currentFile.getParent().resolve(filename);
            if (Files.exists(relative)) return relative;

            // Then user include paths
            for (Path dir : userIncludePaths) {
                Path candidate = dir.resolve(filename);
                if (Files.exists(candidate)) return candidate;
            }
        }

        // System include paths
        for (Path dir : systemIncludePaths) {
            Path candidate = dir.resolve(filename);
            if (Files.exists(candidate)) return candidate;
        }

        return null; // header not found — silently skip
    }


    // =========================================================================
    // #define / #undef
    // =========================================================================

    private void processDefine(String directive) {
        String rest = directive.substring("define".length()).trim();
        if (rest.isEmpty()) return;

        // Extract macro name
        int nameEnd = 0;
        while (nameEnd < rest.length() && (Character.isLetterOrDigit(rest.charAt(nameEnd))
                || rest.charAt(nameEnd) == '_')) nameEnd++;

        String name = rest.substring(0, nameEnd);
        if (name.isEmpty()) return;

        String afterName = rest.substring(nameEnd);

        // Function-like macro: NAME(params) body
        if (afterName.startsWith("(")) {
            int closeParen = findMatchingParen(afterName, 0);
            if (closeParen < 0) return;

            String paramStr = afterName.substring(1, closeParen);
            String body = afterName.substring(closeParen + 1).trim();

            List<String> params = new ArrayList<>();
            boolean variadic = false;

            if (!paramStr.trim().isEmpty()) {
                for (String p : paramStr.split(",")) {
                    p = p.trim();
                    if (p.equals("...")) {
                        variadic = true;
                    } else if (p.endsWith("...")) {
                        // Named variadic: args...
                        params.add(p.substring(0, p.length() - 3).trim());
                        variadic = true;
                    } else {
                        params.add(p);
                    }
                }
            }

            macros.put(name, Macro.functionLike(name, params, variadic, body));
        } else {
            // Object-like macro: NAME body
            String body = afterName.trim();
            macros.put(name, Macro.objectLike(name, body));
        }
    }

    private void processUndef(String directive) {
        String name = directive.substring("undef".length()).trim();
        Macro m = macros.get(name);
        if (m != null && !m.predefined()) {
            macros.remove(name);
        }
    }


    // =========================================================================
    // CONDITIONAL COMPILATION
    // =========================================================================

    /** Returns true if we should emit code (all conditions in stack are active) */
    private boolean isActive() {
        return condStack.stream().allMatch(s -> s == CondState.ACTIVE);
    }

    private void processIfdef(String directive, boolean isNot) {
        String name;
        if (isNot) {
            name = directive.substring("ifndef".length()).trim();
        } else {
            name = directive.substring("ifdef".length()).trim();
        }

        boolean defined = macros.containsKey(name);
        boolean condition = isNot ? !defined : defined;

        if (!isActive()) {
            // Parent condition is false — push DONE so all children are skipped
            condStack.push(CondState.DONE);
        } else {
            condStack.push(condition ? CondState.ACTIVE : CondState.INACTIVE);
        }
    }

    private void processIf(String directive) {
        String expr = directive.substring("if".length()).trim();

        if (!isActive()) {
            condStack.push(CondState.DONE);
        } else {
            boolean result = evaluateCondition(expr);
            condStack.push(result ? CondState.ACTIVE : CondState.INACTIVE);
        }
    }

    private void processElif(String directive) {
        if (condStack.isEmpty()) return;

        CondState current = condStack.pop();

        if (current == CondState.DONE) {
            // Already found a true branch
            condStack.push(CondState.DONE);
        } else if (current == CondState.ACTIVE) {
            // Previous branch was true — skip remaining
            condStack.push(CondState.DONE);
        } else {
            // INACTIVE — evaluate this branch
            // But only if parent is active
            if (!isActive()) {
                condStack.push(CondState.DONE);
            } else {
                String expr = directive.substring("elif".length()).trim();
                boolean result = evaluateCondition(expr);
                condStack.push(result ? CondState.ACTIVE : CondState.INACTIVE);
            }
        }
    }

    private void processElse() {
        if (condStack.isEmpty()) return;

        CondState current = condStack.pop();

        if (current == CondState.DONE) {
            condStack.push(CondState.DONE);
        } else if (current == CondState.ACTIVE) {
            condStack.push(CondState.DONE);
        } else {
            // Was INACTIVE — check if parent is active
            condStack.push(CondState.ACTIVE);
        }
    }

    private void processEndif() {
        if (!condStack.isEmpty()) {
            condStack.pop();
        }
    }


    // =========================================================================
    // CONDITION EXPRESSION EVALUATION
    // =========================================================================

    /**
     * Evaluates a preprocessor condition expression.
     * Handles: defined(X), defined X, integer literals, &&, ||, !, ==, !=,
     *          &lt;, &gt;, &lt;=, &gt;=, +, -, *, /, %, &, |, ^, ~, &lt;&lt;, &gt;&gt;, parentheses
     */
    private boolean evaluateCondition(String expr) {
        // First expand macros (except 'defined' operator)
        expr = expandConditionMacros(expr);
        // Parse and evaluate
        try {
            return evalExpr(new ExprTokenizer(expr)) != 0;
        } catch (Exception e) {
            return false; // on parse error, treat as false
        }
    }

    /**
     * Expands macros in a condition expression, handling 'defined' specially.
     * The 'defined(X)' operator checks if X is defined WITHOUT expanding it.
     */
    private String expandConditionMacros(String expr) {
        // First handle defined(NAME) and defined NAME
        Pattern definedParen = Pattern.compile("defined\\s*\\(\\s*(\\w+)\\s*\\)");
        Pattern definedBare = Pattern.compile("defined\\s+(\\w+)");

        // Replace defined(...) with 0 or 1
        Matcher m = definedParen.matcher(expr);
        StringBuilder sb = new StringBuilder();
        while (m.find()) {
            m.appendReplacement(sb, macros.containsKey(m.group(1)) ? "1" : "0");
        }
        m.appendTail(sb);
        expr = sb.toString();

        m = definedBare.matcher(expr);
        sb = new StringBuilder();
        while (m.find()) {
            m.appendReplacement(sb, macros.containsKey(m.group(1)) ? "1" : "0");
        }
        m.appendTail(sb);
        expr = sb.toString();

        // Now expand remaining macros
        expr = expandMacros(expr);

        // Any remaining identifiers that weren't macros → 0
        // (per C standard, undefined identifiers in #if evaluate to 0)
        expr = expr.replaceAll("\\b[a-zA-Z_]\\w*\\b", "0");

        return expr;
    }

    /** Simple tokenizer for condition expressions */
    static class ExprTokenizer {
        final String src;
        int pos;

        ExprTokenizer(String src) { this.src = src.trim(); this.pos = 0; }

        void skipWhitespace() { while (pos < src.length() && src.charAt(pos) == ' ') pos++; }

        long readNumber() {
            skipWhitespace();
            int start = pos;
            boolean hex = false;
            if (pos + 1 < src.length() && src.charAt(pos) == '0'
                    && (src.charAt(pos + 1) == 'x' || src.charAt(pos + 1) == 'X')) {
                pos += 2;
                hex = true;
                while (pos < src.length() && isHex(src.charAt(pos))) pos++;
            } else {
                while (pos < src.length() && Character.isDigit(src.charAt(pos))) pos++;
            }
            // Skip suffixes
            while (pos < src.length() && "uUlLfF".indexOf(src.charAt(pos)) >= 0) pos++;
            String num = src.substring(start, pos);
            num = num.replaceAll("[uUlLfF]+$", "");
            try {
                if (hex) return Long.parseUnsignedLong(num.substring(2), 16);
                return Long.parseLong(num);
            } catch (NumberFormatException e) { return 0; }
        }

        char peekChar() {
            skipWhitespace();
            return pos < src.length() ? src.charAt(pos) : 0;
        }

        boolean match(char c) {
            skipWhitespace();
            if (pos < src.length() && src.charAt(pos) == c) { pos++; return true; }
            return false;
        }

        boolean match(String s) {
            skipWhitespace();
            if (src.startsWith(s, pos)) { pos += s.length(); return true; }
            return false;
        }

        private static boolean isHex(char c) {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        }
    }

    // Recursive descent expression evaluator with proper precedence
    private long evalExpr(ExprTokenizer t) { return evalTernary(t); }

    private long evalTernary(ExprTokenizer t) {
        long val = evalOr(t);
        if (t.match('?')) {
            long thenVal = evalExpr(t);
            t.match(':');
            long elseVal = evalExpr(t);
            return val != 0 ? thenVal : elseVal;
        }
        return val;
    }

    private long evalOr(ExprTokenizer t) {
        long val = evalAnd(t);
        while (t.match("||")) val = (val != 0 || evalAnd(t) != 0) ? 1 : 0;
        return val;
    }

    private long evalAnd(ExprTokenizer t) {
        long val = evalBitOr(t);
        while (t.match("&&")) val = (val != 0 && evalBitOr(t) != 0) ? 1 : 0;
        return val;
    }

    private long evalBitOr(ExprTokenizer t) {
        long val = evalBitXor(t);
        while (t.peekChar() == '|' && !peekAhead(t, "||")) { t.pos++; val |= evalBitXor(t); }
        return val;
    }

    private long evalBitXor(ExprTokenizer t) {
        long val = evalBitAnd(t);
        while (t.match('^')) val ^= evalBitAnd(t);
        return val;
    }

    private long evalBitAnd(ExprTokenizer t) {
        long val = evalEquality(t);
        while (t.peekChar() == '&' && !peekAhead(t, "&&")) { t.pos++; val &= evalEquality(t); }
        return val;
    }

    private long evalEquality(ExprTokenizer t) {
        long val = evalRelational(t);
        while (true) {
            if (t.match("==")) val = val == evalRelational(t) ? 1 : 0;
            else if (t.match("!=")) val = val != evalRelational(t) ? 1 : 0;
            else break;
        }
        return val;
    }

    private long evalRelational(ExprTokenizer t) {
        long val = evalShift(t);
        while (true) {
            if (t.match("<=")) val = val <= evalShift(t) ? 1 : 0;
            else if (t.match(">=")) val = val >= evalShift(t) ? 1 : 0;
            else if (t.match("<")) val = val < evalShift(t) ? 1 : 0;
            else if (t.match(">")) val = val > evalShift(t) ? 1 : 0;
            else break;
        }
        return val;
    }

    private long evalShift(ExprTokenizer t) {
        long val = evalAdditive(t);
        while (true) {
            if (t.match("<<")) val <<= evalAdditive(t);
            else if (t.match(">>")) val >>= evalAdditive(t);
            else break;
        }
        return val;
    }

    private long evalAdditive(ExprTokenizer t) {
        long val = evalMultiplicative(t);
        while (true) {
            if (t.match('+')) val += evalMultiplicative(t);
            else if (t.match('-')) val -= evalMultiplicative(t);
            else break;
        }
        return val;
    }

    private long evalMultiplicative(ExprTokenizer t) {
        long val = evalUnary(t);
        while (true) {
            if (t.match('*')) val *= evalUnary(t);
            else if (t.match('/')) { long d = evalUnary(t); val = d != 0 ? val / d : 0; }
            else if (t.match('%')) { long d = evalUnary(t); val = d != 0 ? val % d : 0; }
            else break;
        }
        return val;
    }

    private long evalUnary(ExprTokenizer t) {
        t.skipWhitespace();
        if (t.match('!')) return evalUnary(t) == 0 ? 1 : 0;
        if (t.match('~')) return ~evalUnary(t);
        if (t.match('-')) return -evalUnary(t);
        if (t.match('+')) return evalUnary(t);
        return evalPrimary(t);
    }

    private long evalPrimary(ExprTokenizer t) {
        t.skipWhitespace();
        if (t.pos >= t.src.length()) return 0;

        char c = t.src.charAt(t.pos);

        if (c == '(') {
            t.pos++;
            long val = evalExpr(t);
            t.match(')');
            return val;
        }

        if (Character.isDigit(c)) {
            return t.readNumber();
        }

        // Character literal
        if (c == '\'') {
            t.pos++;
            char ch = t.src.charAt(t.pos);
            if (ch == '\\') { t.pos++; ch = t.src.charAt(t.pos); }
            t.pos++;
            t.match('\'');
            return ch;
        }

        // Remaining identifier — shouldn't happen after macro expansion, treat as 0
        while (t.pos < t.src.length() &&
                (Character.isLetterOrDigit(t.src.charAt(t.pos)) || t.src.charAt(t.pos) == '_'))
            t.pos++;
        return 0;
    }

    private boolean peekAhead(ExprTokenizer t, String s) {
        t.skipWhitespace();
        return t.src.startsWith(s, t.pos);
    }


    // =========================================================================
    // #pragma
    // =========================================================================

    private void processPragma(String directive, Path currentFile) {
        String rest = directive.substring("pragma".length()).trim();
        if (rest.equals("once")) {
            String canonical = currentFile.toAbsolutePath().normalize().toString();
            onceGuards.add(canonical);
        }
        // Ignore other pragmas
    }


    // =========================================================================
    // MACRO EXPANSION
    // =========================================================================

    /**
     * Expands all macros in a line of text.
     * Handles nested expansion with recursion protection.
     */
    String expandMacros(String text) {
        if (text.isEmpty()) return text;
        if (expansionDepth >= MAX_EXPANSION_DEPTH) return text;

        expansionDepth++;
        try {
            return expandMacrosImpl(text, new HashSet<>());
        } finally {
            expansionDepth--;
        }
    }

    private String expandMacrosImpl(String text, Set<String> expanding) {
        StringBuilder result = new StringBuilder();
        int i = 0;

        while (i < text.length()) {
            char c = text.charAt(i);

            // Skip string literals
            if (c == '"') {
                int end = findClosingQuote(text, i, '"');
                result.append(text, i, end);
                i = end;
                continue;
            }
            if (c == '\'') {
                int end = findClosingQuote(text, i, '\'');
                result.append(text, i, end);
                i = end;
                continue;
            }

            // Identifier — potential macro
            if (Character.isLetter(c) || c == '_') {
                int start = i;
                while (i < text.length() && (Character.isLetterOrDigit(text.charAt(i))
                        || text.charAt(i) == '_')) i++;
                String name = text.substring(start, i);

                Macro macro = macros.get(name);

                if (macro == null || expanding.contains(name)) {
                    // Not a macro, or already expanding (recursion guard)
                    result.append(name);
                    continue;
                }

                if (macro.isFunctionLike()) {
                    // Must be followed by (
                    int parenStart = skipWhitespaceIdx(text, i);
                    if (parenStart < text.length() && text.charAt(parenStart) == '(') {
                        // Parse arguments
                        int[] endIdx = new int[]{parenStart};
                        List<String> args = parseMacroArgs(text, endIdx);
                        i = endIdx[0];

                        String expanded = expandFunctionMacro(macro, args, expanding);
                        result.append(expanded);
                    } else {
                        // Function-like macro without () — not an invocation
                        result.append(name);
                    }
                } else {
                    // Object-like macro
                    Set<String> newExpanding = new HashSet<>(expanding);
                    newExpanding.add(name);
                    String expanded = expandMacrosImpl(macro.body(), newExpanding);
                    result.append(expanded);
                }
            } else {
                result.append(c);
                i++;
            }
        }

        return result.toString();
    }

    /**
     * Parses comma-separated macro arguments, respecting nested parentheses.
     */
    private List<String> parseMacroArgs(String text, int[] idx) {
        List<String> args = new ArrayList<>();
        int i = idx[0] + 1; // skip opening (
        int depth = 1;
        int argStart = i;

        while (i < text.length() && depth > 0) {
            char c = text.charAt(i);
            if (c == '(') depth++;
            else if (c == ')') {
                depth--;
                if (depth == 0) {
                    String arg = text.substring(argStart, i).trim();
                    if (!arg.isEmpty() || !args.isEmpty()) args.add(arg);
                    i++; // skip closing )
                    break;
                }
            } else if (c == ',' && depth == 1) {
                args.add(text.substring(argStart, i).trim());
                argStart = i + 1;
            } else if (c == '"') {
                i = findClosingQuote(text, i, '"');
                continue;
            } else if (c == '\'') {
                i = findClosingQuote(text, i, '\'');
                continue;
            }
            i++;
        }

        idx[0] = i;
        return args;
    }

    /**
     * Scans a macro body to find parameters that appear immediately before or
     * after the ## token-paste operator. These must use raw (unexpanded) arguments.
     */
    private Set<String> identifyPasteParams(String body, Set<String> paramNames) {
        Set<String> result = new HashSet<>();
        // Find all ## positions and check adjacent identifiers
        int idx = 0;
        while ((idx = body.indexOf("##", idx)) >= 0) {
            // Check identifier before ##
            int before = idx - 1;
            while (before >= 0 && body.charAt(before) == ' ') before--;
            if (before >= 0) {
                int end = before + 1;
                while (before >= 0 && (Character.isLetterOrDigit(body.charAt(before))
                        || body.charAt(before) == '_')) before--;
                String token = body.substring(before + 1, end);
                if (paramNames.contains(token)) result.add(token);
            }
            // Check identifier after ##
            int after = idx + 2;
            while (after < body.length() && body.charAt(after) == ' ') after++;
            if (after < body.length()) {
                int start = after;
                while (after < body.length() && (Character.isLetterOrDigit(body.charAt(after))
                        || body.charAt(after) == '_')) after++;
                String token = body.substring(start, after);
                if (paramNames.contains(token)) result.add(token);
            }
            idx += 2;
        }
        return result;
    }

    /**
     * Expands a function-like macro with the given arguments.
     * Handles # (stringification), ## (token pasting), and __VA_ARGS__.
     *
     * Per the C standard, macro arguments are fully expanded before substitution
     * EXCEPT when the parameter appears with # (stringification) or ## (token pasting).
     */
    private String expandFunctionMacro(Macro macro, List<String> args, Set<String> expanding) {
        String body = macro.body();
        if (body.isEmpty()) return "";

        // Build parameter → raw argument mapping
        Map<String, String> rawParamMap = new LinkedHashMap<>();
        for (int i = 0; i < macro.params().size() && i < args.size(); i++) {
            rawParamMap.put(macro.params().get(i), args.get(i));
        }

        // Build parameter → expanded argument mapping (C standard: args are
        // pre-expanded before substitution, unless used with # or ##)
        Map<String, String> expandedParamMap = new LinkedHashMap<>();
        for (var entry : rawParamMap.entrySet()) {
            expandedParamMap.put(entry.getKey(), expandMacrosImpl(entry.getValue().trim(), expanding));
        }

        // Handle __VA_ARGS__
        if (macro.variadic()) {
            int fixedCount = macro.params().size();
            StringJoiner vaArgs = new StringJoiner(", ");
            for (int i = fixedCount; i < args.size(); i++) {
                vaArgs.add(args.get(i));
            }
            String raw = vaArgs.toString();
            rawParamMap.put("__VA_ARGS__", raw);
            expandedParamMap.put("__VA_ARGS__", expandMacrosImpl(raw.trim(), expanding));
        }

        // Identify parameters that appear adjacent to ## (these must use raw args).
        // Scan the body for patterns: "param ##" or "## param"
        Set<String> pasteParams = identifyPasteParams(body, rawParamMap.keySet());

        // Process body: substitute parameters, handle # and ##
        StringBuilder result = new StringBuilder();
        int i = 0;
        char[] bodyChars = body.toCharArray();
        boolean afterPaste = false; // true if we just processed ##

        while (i < bodyChars.length) {
            // Stringification: #param — uses RAW argument
            if (bodyChars[i] == '#' && i + 1 < bodyChars.length && bodyChars[i + 1] != '#') {
                i++;
                while (i < bodyChars.length && bodyChars[i] == ' ') i++;
                int start = i;
                while (i < bodyChars.length && (Character.isLetterOrDigit(bodyChars[i])
                        || bodyChars[i] == '_')) i++;
                String paramName = new String(bodyChars, start, i - start);
                String argValue = rawParamMap.getOrDefault(paramName, "");
                result.append('"').append(argValue.replace("\\", "\\\\")
                        .replace("\"", "\\\"")).append('"');
                afterPaste = false;
                continue;
            }

            // Token pasting: ##
            if (bodyChars[i] == '#' && i + 1 < bodyChars.length && bodyChars[i + 1] == '#') {
                // Remove trailing whitespace from result
                while (!result.isEmpty() && result.charAt(result.length() - 1) == ' ')
                    result.deleteCharAt(result.length() - 1);
                i += 2;
                while (i < bodyChars.length && bodyChars[i] == ' ') i++;
                afterPaste = true;
                // Next token gets pasted directly (using raw arg)
                continue;
            }

            // Identifier — check if it's a parameter
            if (Character.isLetter(bodyChars[i]) || bodyChars[i] == '_') {
                int start = i;
                while (i < bodyChars.length && (Character.isLetterOrDigit(bodyChars[i])
                        || bodyChars[i] == '_')) i++;
                String token = new String(bodyChars, start, i - start);

                // Use raw for # / ## contexts, expanded otherwise
                boolean usePaste = afterPaste || pasteParams.contains(token);
                Map<String, String> map = usePaste ? rawParamMap : expandedParamMap;
                String replacement = map.get(token);
                if (replacement != null) {
                    result.append(replacement);
                } else {
                    result.append(token);
                }
                afterPaste = false;
                continue;
            }

            result.append(bodyChars[i]);
            afterPaste = false;
            i++;
        }

        // Recursively expand the result
        Set<String> newExpanding = new HashSet<>(expanding);
        newExpanding.add(macro.name());
        return expandMacrosImpl(result.toString(), newExpanding);
    }


    // =========================================================================
    // STRING HELPERS
    // =========================================================================

    private int findClosingQuote(String text, int start, char quoteChar) {
        int i = start + 1;
        while (i < text.length()) {
            if (text.charAt(i) == '\\') { i += 2; continue; }
            if (text.charAt(i) == quoteChar) return i + 1;
            i++;
        }
        return text.length();
    }

    private int findMatchingParen(String text, int openIdx) {
        int depth = 1;
        for (int i = openIdx + 1; i < text.length(); i++) {
            if (text.charAt(i) == '(') depth++;
            else if (text.charAt(i) == ')') { depth--; if (depth == 0) return i; }
        }
        return -1;
    }

    private int skipWhitespaceIdx(String text, int from) {
        while (from < text.length() && text.charAt(from) == ' ') from++;
        return from;
    }


    // =========================================================================
    // PUBLIC API — Query macro state
    // =========================================================================

    /** Checks if a macro is defined */
    public boolean isDefined(String name) { return macros.containsKey(name); }

    /** Gets a macro's expansion value (for object-like macros) */
    public String getMacroValue(String name) {
        Macro m = macros.get(name);
        return m != null ? m.body() : null;
    }

    /** Returns all defined macro names */
    public Set<String> getDefinedMacros() { return Collections.unmodifiableSet(macros.keySet()); }

    /** Returns count of files processed (for diagnostics) */
    public int getFilesProcessed() { return onceGuards.size(); }


    // =========================================================================
    // MAIN — Standalone preprocessor for testing
    // =========================================================================

    public static void main(String[] args) throws IOException {
        if (args.length < 1) {
            System.out.println("Usage: java CPreprocessor [options] <header.h>");
            System.out.println();
            System.out.println("Options:");
            System.out.println("  -I <dir>          Add include search path");
            System.out.println("  -D <name>=<value> Define a macro");
            System.out.println("  -D <name>         Define a macro with value 1");
            System.out.println("  --platform <p>    Set platform (LINUX_X86_64, LINUX_AARCH64,");
            System.out.println("                    MACOS_X86_64, MACOS_AARCH64)");
            System.out.println("  --stats           Print processing statistics instead of output");
            return;
        }

        FFMUtil.Platform platform = FFMUtil.Platform.LINUX_X86_64;
        List<String> includeDirs = new ArrayList<>();
        Map<String, String> defines = new LinkedHashMap<>();
        boolean showStats = false;
        String headerPath = null;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "-I" -> { if (i + 1 < args.length) includeDirs.add(args[++i]); }
                case "--platform" -> {
                    if (i + 1 < args.length) platform = FFMUtil.Platform.valueOf(args[++i]);
                }
                case "--stats" -> showStats = true;
                default -> {
                    if (args[i].startsWith("-D")) {
                        String def = args[i].substring(2);
                        if (def.isEmpty() && i + 1 < args.length) def = args[++i];
                        int eq = def.indexOf('=');
                        if (eq > 0) defines.put(def.substring(0, eq), def.substring(eq + 1));
                        else defines.put(def, "1");
                    } else if (!args[i].startsWith("-")) {
                        headerPath = args[i];
                    }
                }
            }
        }

        if (headerPath == null) {
            System.err.println("Error: no header file specified");
            return;
        }

        CPreprocessor pp = new CPreprocessor(platform);
        for (String dir : includeDirs) pp.addUserIncludePath(dir);
        for (var entry : defines.entrySet()) pp.define(entry.getKey(), entry.getValue());

        long startTime = System.nanoTime();
        String result = pp.preprocess(headerPath);
        long elapsed = System.nanoTime() - startTime;

        if (showStats) {
            System.out.printf("Header:          %s%n", headerPath);
            System.out.printf("Platform:        %s%n", platform);
            System.out.printf("Files processed: %d%n", pp.getFilesProcessed());
            System.out.printf("Output lines:    %d%n", result.lines().count());
            System.out.printf("Output chars:    %d%n", result.length());
            System.out.printf("Macros defined:  %d%n", pp.getDefinedMacros().size());
            System.out.printf("Time:            %.2f ms%n", elapsed / 1_000_000.0);
        } else {
            System.out.print(result);
        }
    }
}
