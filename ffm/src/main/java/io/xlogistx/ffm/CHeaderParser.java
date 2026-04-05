package io.xlogistx.ffm;
import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;

/**
 * CHeaderParser — Reads C header files (.h), parses function declarations,
 * struct/union definitions, typedefs, and enums, then creates FFM MethodHandles.
 *
 * Strategy:
 *   1. Run gcc -E (preprocessor) to expand all #include, #ifdef, #define
 *   2. Tokenize the preprocessed output
 *   3. Parse declarations using recursive descent
 *   4. Produce CType/NativeFunction metadata (same model as DwarfFFMLoader)
 *   5. Map to FunctionDescriptor → MethodHandle
 *
 * This gives you the same end result as jextract but staying entirely in Java,
 * and produces the same data structures as the DWARF approach.
 *
 * Usage:
 *   javac CHeaderParser.java
 *   java --enable-native-access=ALL-UNNAMED CHeaderParser /usr/include/pcap/pcap.h libpcap.so
 *
 * Requirements:
 *   - gcc (for preprocessing only — no compilation needed)
 *   - JDK 22+ (FFM API)
 */


public class CHeaderParser {

    // =========================================================================
    // SHARED DATA MODEL — Same sealed CType hierarchy as DwarfFFMLoader
    // =========================================================================

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
    public record NativeFunction(String name, CType returnType, List<Parameter> params, boolean variadic) {
        @Override
        public String toString() {
            StringJoiner pj = new StringJoiner(", ");
            for (Parameter p : params) pj.add(typeToString(p.type) + " " + p.name);
            if (variadic) pj.add("...");
            return typeToString(returnType) + " " + name + "(" + pj + ")";
        }
    }

    public record BoundFunction(NativeFunction function, FunctionDescriptor descriptor,
                                MethodHandle handle) {}


    // =========================================================================
    // TOKENIZER — Breaks preprocessed C source into tokens
    // =========================================================================

    enum TokenType {
        IDENTIFIER, NUMBER, STRING, CHAR_LITERAL,
        STAR, LPAREN, RPAREN, LBRACE, RBRACE, LBRACKET, RBRACKET,
        SEMICOLON, COMMA, COLON, ELLIPSIS, EQUALS, DOT,
        // Operators we skip over but need to recognize
        PLUS, MINUS, SLASH, PIPE, AMPERSAND, TILDE, CARET,
        LSHIFT, RSHIFT, QUESTION, EXCL,
        EOF
    }

    record Token(TokenType type, String value, int line) {
        @Override
        public String toString() { return type + "(" + value + ")"; }
    }

    /**
     * Tokenizes preprocessed C source. Skips # line directives.
     */
    static List<Token> tokenize(String source) {
        List<Token> tokens = new ArrayList<>();
        int i = 0;
        int line = 1;
        char[] chars = source.toCharArray();
        int len = chars.length;

        while (i < len) {
            char c = chars[i];

            // Whitespace
            if (c == ' ' || c == '\t' || c == '\r' || c == '\f') { i++; continue; }

            // Newline
            if (c == '\n') { line++; i++; continue; }

            // Preprocessor line directives: # <linenum> "filename" ...
            if (c == '#' && (i == 0 || chars[i - 1] == '\n')) {
                while (i < len && chars[i] != '\n') i++;
                continue;
            }

            // Line comments (shouldn't appear after -E but just in case)
            if (c == '/' && i + 1 < len && chars[i + 1] == '/') {
                while (i < len && chars[i] != '\n') i++;
                continue;
            }

            // Block comments
            if (c == '/' && i + 1 < len && chars[i + 1] == '*') {
                i += 2;
                while (i + 1 < len && !(chars[i] == '*' && chars[i + 1] == '/')) {
                    if (chars[i] == '\n') line++;
                    i++;
                }
                i += 2;
                continue;
            }

            // String literals
            if (c == '"') {
                int start = i++;
                while (i < len && chars[i] != '"') {
                    if (chars[i] == '\\') i++; // skip escaped char
                    i++;
                }
                i++; // closing quote
                tokens.add(new Token(TokenType.STRING, new String(chars, start, i - start), line));
                continue;
            }

            // Char literals
            if (c == '\'') {
                int start = i++;
                while (i < len && chars[i] != '\'') {
                    if (chars[i] == '\\') i++;
                    i++;
                }
                i++;
                tokens.add(new Token(TokenType.CHAR_LITERAL, new String(chars, start, i - start), line));
                continue;
            }

            // Ellipsis
            if (c == '.' && i + 2 < len && chars[i + 1] == '.' && chars[i + 2] == '.') {
                tokens.add(new Token(TokenType.ELLIPSIS, "...", line));
                i += 3;
                continue;
            }

            // Shift operators
            if (c == '<' && i + 1 < len && chars[i + 1] == '<') {
                tokens.add(new Token(TokenType.LSHIFT, "<<", line));
                i += 2;
                continue;
            }
            if (c == '>' && i + 1 < len && chars[i + 1] == '>') {
                tokens.add(new Token(TokenType.RSHIFT, ">>", line));
                i += 2;
                continue;
            }

            // Numbers (decimal, hex, octal, float)
            if (Character.isDigit(c) || (c == '.' && i + 1 < len && Character.isDigit(chars[i + 1]))) {
                int start = i;
                if (c == '0' && i + 1 < len && (chars[i + 1] == 'x' || chars[i + 1] == 'X')) {
                    i += 2;
                    while (i < len && isHexDigit(chars[i])) i++;
                } else {
                    while (i < len && (Character.isDigit(chars[i]) || chars[i] == '.'
                            || chars[i] == 'e' || chars[i] == 'E'
                            || chars[i] == '+' || chars[i] == '-')) i++;
                }
                // Consume type suffixes: U, L, UL, ULL, LL, F, etc.
                while (i < len && (chars[i] == 'u' || chars[i] == 'U' ||
                        chars[i] == 'l' || chars[i] == 'L' ||
                        chars[i] == 'f' || chars[i] == 'F')) i++;
                tokens.add(new Token(TokenType.NUMBER, new String(chars, start, i - start), line));
                continue;
            }

            // Identifiers and keywords
            if (Character.isLetter(c) || c == '_') {
                int start = i;
                while (i < len && (Character.isLetterOrDigit(chars[i]) || chars[i] == '_')) i++;
                tokens.add(new Token(TokenType.IDENTIFIER, new String(chars, start, i - start), line));
                continue;
            }

            // Single character tokens
            TokenType tt = switch (c) {
                case '*' -> TokenType.STAR;
                case '(' -> TokenType.LPAREN;
                case ')' -> TokenType.RPAREN;
                case '{' -> TokenType.LBRACE;
                case '}' -> TokenType.RBRACE;
                case '[' -> TokenType.LBRACKET;
                case ']' -> TokenType.RBRACKET;
                case ';' -> TokenType.SEMICOLON;
                case ',' -> TokenType.COMMA;
                case ':' -> TokenType.COLON;
                case '=' -> TokenType.EQUALS;
                case '.' -> TokenType.DOT;
                case '+' -> TokenType.PLUS;
                case '-' -> TokenType.MINUS;
                case '/' -> TokenType.SLASH;
                case '|' -> TokenType.PIPE;
                case '&' -> TokenType.AMPERSAND;
                case '~' -> TokenType.TILDE;
                case '^' -> TokenType.CARET;
                case '?' -> TokenType.QUESTION;
                case '!' -> TokenType.EXCL;
                default -> null;
            };

            if (tt != null) {
                tokens.add(new Token(tt, String.valueOf(c), line));
                i++;
            } else {
                i++; // skip unrecognized
            }
        }

        tokens.add(new Token(TokenType.EOF, "", line));
        return tokens;
    }

    private static boolean isHexDigit(char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }


    // =========================================================================
    // PARSER — Recursive descent parser for C declarations
    // =========================================================================

    /**
     * Parses preprocessed C source into functions, structs, typedefs, and enums.
     */
    static class Parser {
        private final List<Token> tokens;
        private int pos;

        // Parsed results
        final List<NativeFunction> functions = new ArrayList<>();
        final Map<String, CType> typedefs = new LinkedHashMap<>();
        final Map<String, CType.Struct> structs = new LinkedHashMap<>();
        final Map<String, CType.Union> unions = new LinkedHashMap<>();
        final Map<String, CType.Enum> enums = new LinkedHashMap<>();

        // Built-in type registry — maps C type names to primitives
        // Populated with standard C types + any discovered typedefs
        final Map<String, CType> typeRegistry = new LinkedHashMap<>();

        Parser(List<Token> tokens) {
            this.tokens = tokens;
            registerBuiltinTypes();
        }

        private void registerBuiltinTypes() {
            // Standard C primitive types with sizes for x86-64 Linux
            reg("void",               new CType.Void());
            reg("char",               new CType.Primitive("char", 1, CType.Encoding.SIGNED_CHAR));
            reg("signed char",        new CType.Primitive("signed char", 1, CType.Encoding.SIGNED_CHAR));
            reg("unsigned char",      new CType.Primitive("unsigned char", 1, CType.Encoding.UNSIGNED_CHAR));
            reg("short",              new CType.Primitive("short", 2, CType.Encoding.SIGNED));
            reg("unsigned short",     new CType.Primitive("unsigned short", 2, CType.Encoding.UNSIGNED));
            reg("int",                new CType.Primitive("int", 4, CType.Encoding.SIGNED));
            reg("unsigned int",       new CType.Primitive("unsigned int", 4, CType.Encoding.UNSIGNED));
            reg("unsigned",           new CType.Primitive("unsigned", 4, CType.Encoding.UNSIGNED));
            reg("long",               new CType.Primitive("long", 8, CType.Encoding.SIGNED));
            reg("unsigned long",      new CType.Primitive("unsigned long", 8, CType.Encoding.UNSIGNED));
            reg("long long",          new CType.Primitive("long long", 8, CType.Encoding.SIGNED));
            reg("unsigned long long", new CType.Primitive("unsigned long long", 8, CType.Encoding.UNSIGNED));
            reg("float",              new CType.Primitive("float", 4, CType.Encoding.FLOAT));
            reg("double",             new CType.Primitive("double", 8, CType.Encoding.FLOAT));
            reg("long double",        new CType.Primitive("long double", 16, CType.Encoding.FLOAT));
            reg("_Bool",              new CType.Primitive("_Bool", 1, CType.Encoding.BOOLEAN));
            reg("bool",               new CType.Primitive("bool", 1, CType.Encoding.BOOLEAN));

            // Common fixed-width types (stdint.h)
            reg("int8_t",    new CType.Primitive("int8_t", 1, CType.Encoding.SIGNED));
            reg("uint8_t",   new CType.Primitive("uint8_t", 1, CType.Encoding.UNSIGNED));
            reg("int16_t",   new CType.Primitive("int16_t", 2, CType.Encoding.SIGNED));
            reg("uint16_t",  new CType.Primitive("uint16_t", 2, CType.Encoding.UNSIGNED));
            reg("int32_t",   new CType.Primitive("int32_t", 4, CType.Encoding.SIGNED));
            reg("uint32_t",  new CType.Primitive("uint32_t", 4, CType.Encoding.UNSIGNED));
            reg("int64_t",   new CType.Primitive("int64_t", 8, CType.Encoding.SIGNED));
            reg("uint64_t",  new CType.Primitive("uint64_t", 8, CType.Encoding.UNSIGNED));

            // Common POSIX types
            reg("size_t",    new CType.Primitive("size_t", 8, CType.Encoding.UNSIGNED));
            reg("ssize_t",   new CType.Primitive("ssize_t", 8, CType.Encoding.SIGNED));
            reg("off_t",     new CType.Primitive("off_t", 8, CType.Encoding.SIGNED));
            reg("pid_t",     new CType.Primitive("pid_t", 4, CType.Encoding.SIGNED));
            reg("uid_t",     new CType.Primitive("uid_t", 4, CType.Encoding.UNSIGNED));
            reg("gid_t",     new CType.Primitive("gid_t", 4, CType.Encoding.UNSIGNED));
            reg("time_t",    new CType.Primitive("time_t", 8, CType.Encoding.SIGNED));
            reg("intptr_t",  new CType.Primitive("intptr_t", 8, CType.Encoding.SIGNED));
            reg("uintptr_t", new CType.Primitive("uintptr_t", 8, CType.Encoding.UNSIGNED));
            reg("ptrdiff_t", new CType.Primitive("ptrdiff_t", 8, CType.Encoding.SIGNED));
        }

        private void reg(String name, CType type) { typeRegistry.put(name, type); }

        // --- Token access ---

        private Token peek() { return tokens.get(pos); }
        private Token peek(int ahead) {
            int idx = pos + ahead;
            return idx < tokens.size() ? tokens.get(idx) : tokens.getLast();
        }
        private Token advance() { return tokens.get(pos++); }
        private boolean check(TokenType type) { return peek().type == type; }
        private boolean checkId(String value) { return check(TokenType.IDENTIFIER) && peek().value.equals(value); }

        private boolean match(TokenType type) {
            if (check(type)) { advance(); return true; }
            return false;
        }

        private void expect(TokenType type) {
            if (!check(type)) {
                throw new ParseException("Expected " + type + " but got " + peek()
                        + " at line " + peek().line);
            }
            advance();
        }

        // --- Skip helpers ---

        /** Skips a balanced group of braces/parens/brackets */
        private void skipBalanced(TokenType open, TokenType close) {
            int depth = 1;
            advance(); // consume opening
            while (depth > 0 && !check(TokenType.EOF)) {
                if (check(open)) depth++;
                else if (check(close)) depth--;
                if (depth > 0) advance();
            }
            if (check(close)) advance();
        }

        /** Skips to the next semicolon at the current brace depth */
        private void skipToSemicolon() {
            int depth = 0;
            while (!check(TokenType.EOF)) {
                if (check(TokenType.LBRACE)) depth++;
                else if (check(TokenType.RBRACE)) depth--;
                else if (check(TokenType.SEMICOLON) && depth <= 0) { advance(); return; }
                advance();
            }
        }


        // =====================================================================
        // TOP-LEVEL PARSING
        // =====================================================================

        void parseAll() {
            while (!check(TokenType.EOF)) {
                try {
                    parseTopLevel();
                } catch (ParseException e) {
                    // Recovery: skip to next semicolon or closing brace
                    skipToSemicolon();
                }
            }
        }

        private void parseTopLevel() {
            // Skip storage class specifiers and qualifiers that don't affect the type
            skipStorageClass();

            if (checkId("typedef")) {
                parseTypedef();
            } else if (checkId("struct") && isStructDefinition()) {
                parseStructDefinition();
            } else if (checkId("union") && isStructDefinition()) {
                parseUnionDefinition();
            } else if (checkId("enum") && isEnumDefinition()) {
                parseEnumDefinition();
            } else if (isLikelyFunctionDecl()) {
                parseFunctionDeclaration();
            } else {
                // Skip unrecognized declaration
                skipToSemicolon();
            }
        }

        private void skipStorageClass() {
            while (checkId("extern") || checkId("static") || checkId("inline")
                    || checkId("__inline") || checkId("__inline__")
                    || checkId("__extension__") || checkId("__attribute__")
                    || checkId("__restrict") || checkId("__restrict__")) {
                if (checkId("__attribute__")) {
                    advance();
                    if (check(TokenType.LPAREN)) skipBalanced(TokenType.LPAREN, TokenType.RPAREN);
                } else {
                    advance();
                }
            }
        }

        /** Heuristic: is this a struct/union/enum definition (not just usage)? */
        private boolean isStructDefinition() {
            // struct NAME { ... } or struct { ... }
            int save = pos;
            advance(); // skip struct/union
            if (check(TokenType.IDENTIFIER)) advance(); // optional name
            boolean isDef = check(TokenType.LBRACE);
            pos = save;
            return isDef;
        }

        private boolean isEnumDefinition() {
            int save = pos;
            advance(); // skip enum
            if (check(TokenType.IDENTIFIER)) advance();
            boolean isDef = check(TokenType.LBRACE);
            pos = save;
            return isDef;
        }

        /**
         * Heuristic to determine if current position starts a function declaration.
         * Looks for: type_specifiers name ( ... ) ;
         */
        private boolean isLikelyFunctionDecl() {
            if (check(TokenType.EOF) || check(TokenType.RBRACE)) return false;

            int save = pos;
            try {
                // Try parsing a type + name
                parseTypeSpecifier();
                // Skip pointer qualifiers
                while (check(TokenType.STAR)) advance();
                // Should be an identifier (function name)
                if (!check(TokenType.IDENTIFIER)) return false;
                advance();
                // Followed by (
                return check(TokenType.LPAREN);
            } catch (Exception e) {
                return false;
            } finally {
                pos = save;
            }
        }


        // =====================================================================
        // TYPE SPECIFIER PARSING
        // =====================================================================

        /**
         * Parses a C type specifier, handling:
         *   - Simple types: int, char, float, double, void
         *   - Compound: unsigned int, long long, unsigned long long
         *   - struct/union/enum references: struct pcap_pkthdr
         *   - Typedef names: pcap_t, size_t, uint32_t
         *   - Qualifiers: const, volatile, restrict
         */
        CType parseTypeSpecifier() {
            CType.Qualifier qualifier = null;

            // Leading qualifiers
            while (checkId("const") || checkId("volatile") || checkId("restrict")
                    || checkId("__const") || checkId("__volatile") || checkId("__restrict")) {
                String q = advance().value;
                if (q.contains("const")) qualifier = CType.Qualifier.CONST;
                else if (q.contains("volatile")) qualifier = CType.Qualifier.VOLATILE;
                else if (q.contains("restrict")) qualifier = CType.Qualifier.RESTRICT;
            }

            // Skip __extension__, __attribute__
            skipStorageClass();

            CType base;

            if (checkId("struct")) {
                advance();
                String name = advance().value;
                // Check if followed by a definition body
                if (check(TokenType.LBRACE)) {
                    base = parseStructBody(name);
                } else {
                    base = structs.containsKey(name) ? structs.get(name) :
                            new CType.Struct(name, 0, List.of());
                }
            } else if (checkId("union")) {
                advance();
                String name = advance().value;
                if (check(TokenType.LBRACE)) {
                    base = parseUnionBody(name);
                } else {
                    base = unions.containsKey(name) ? unions.get(name) :
                            new CType.Union(name, 0, List.of());
                }
            } else if (checkId("enum")) {
                advance();
                String name = check(TokenType.IDENTIFIER) ? advance().value : "<anon>";
                if (check(TokenType.LBRACE)) {
                    base = parseEnumBody(name);
                } else {
                    base = enums.containsKey(name) ? enums.get(name) :
                            new CType.Enum(name, 4, List.of());
                }
            } else if (checkId("void")) {
                advance();
                base = new CType.Void();
            } else {
                base = parsePrimitiveOrTypeName();
            }

            // Trailing qualifiers
            while (checkId("const") || checkId("volatile") || checkId("restrict")
                    || checkId("__const") || checkId("__volatile") || checkId("__restrict")) {
                String q = advance().value;
                if (qualifier == null) {
                    if (q.contains("const")) qualifier = CType.Qualifier.CONST;
                    else if (q.contains("volatile")) qualifier = CType.Qualifier.VOLATILE;
                }
            }

            if (qualifier != null) {
                base = new CType.Qualified(qualifier, base);
            }

            return base;
        }

        /**
         * Parses primitive type combinations (unsigned long long int, etc.)
         * or resolves a typedef name from the registry.
         */
        private CType parsePrimitiveOrTypeName() {
            StringBuilder typeBuilder = new StringBuilder();
            boolean hasSigned = false, hasUnsigned = false;
            int longCount = 0;
            boolean hasInt = false, hasShort = false;
            boolean hasChar = false, hasFloat = false, hasDouble = false;

            // Collect type keywords
            boolean collecting = true;
            while (collecting && check(TokenType.IDENTIFIER)) {
                String word = peek().value;
                switch (word) {
                    case "signed" -> { hasSigned = true; advance(); }
                    case "unsigned" -> { hasUnsigned = true; advance(); }
                    case "long" -> { longCount++; advance(); }
                    case "short" -> { hasShort = true; advance(); }
                    case "int" -> { hasInt = true; advance(); }
                    case "char" -> { hasChar = true; advance(); }
                    case "float" -> { hasFloat = true; advance(); }
                    case "double" -> { hasDouble = true; advance(); }
                    default -> collecting = false;
                }
            }

            // If we collected any primitive keywords, resolve them
            if (hasSigned || hasUnsigned || longCount > 0 || hasShort
                    || hasInt || hasChar || hasFloat || hasDouble) {
                return resolvePrimitiveCombination(hasUnsigned, hasSigned,
                        longCount, hasShort, hasInt, hasChar, hasFloat, hasDouble);
            }

            // Otherwise it's a typedef name or unknown identifier
            if (check(TokenType.IDENTIFIER)) {
                String name = advance().value;
                CType resolved = typeRegistry.get(name);
                if (resolved != null) return new CType.Typedef(name, resolved);
                return new CType.Unresolved(name);
            }

            throw new ParseException("Expected type specifier at line " + peek().line
                    + " but got " + peek());
        }

        private CType resolvePrimitiveCombination(boolean unsigned, boolean signed,
                                                  int longCount, boolean hasShort,
                                                  boolean hasInt, boolean hasChar,
                                                  boolean hasFloat, boolean hasDouble) {
            if (hasChar) {
                if (unsigned) return typeRegistry.get("unsigned char");
                return typeRegistry.get("char");
            }
            if (hasFloat) return typeRegistry.get("float");
            if (hasDouble) {
                if (longCount > 0) return typeRegistry.get("long double");
                return typeRegistry.get("double");
            }
            if (hasShort) {
                if (unsigned) return typeRegistry.get("unsigned short");
                return typeRegistry.get("short");
            }
            if (longCount >= 2) {
                if (unsigned) return typeRegistry.get("unsigned long long");
                return typeRegistry.get("long long");
            }
            if (longCount == 1) {
                if (unsigned) return typeRegistry.get("unsigned long");
                return typeRegistry.get("long");
            }
            // Just int, signed int, unsigned int, or bare signed/unsigned
            if (unsigned) return typeRegistry.get("unsigned int");
            return typeRegistry.get("int");
        }


        // =====================================================================
        // FULL TYPE PARSING (specifier + pointers + arrays)
        // =====================================================================

        /**
         * Parses a complete type including pointer indirections.
         * Returns the type without consuming the declarator name.
         */
        CType parseFullType() {
            CType base = parseTypeSpecifier();

            // Pointer levels
            while (check(TokenType.STAR)) {
                advance();
                // Consume pointer qualifiers
                while (checkId("const") || checkId("volatile") || checkId("restrict")
                        || checkId("__const") || checkId("__restrict")) {
                    advance();
                }
                base = new CType.Pointer(base);
            }

            return base;
        }


        // =====================================================================
        // FUNCTION DECLARATION PARSING
        // =====================================================================

        void parseFunctionDeclaration() {
            skipStorageClass();

            CType returnType = parseFullType();
            if (!check(TokenType.IDENTIFIER)) { skipToSemicolon(); return; }

            String funcName = advance().value;

            if (!match(TokenType.LPAREN)) { skipToSemicolon(); return; }

            // Parse parameter list
            List<Parameter> params = new ArrayList<>();
            boolean variadic = false;

            // Empty params or void
            if (check(TokenType.RPAREN)) {
                advance();
            } else if (checkId("void") && peek(1).type == TokenType.RPAREN) {
                advance(); advance(); // skip "void" and ")"
            } else {
                while (!check(TokenType.RPAREN) && !check(TokenType.EOF)) {
                    if (check(TokenType.ELLIPSIS)) {
                        variadic = true;
                        advance();
                        break;
                    }

                    skipStorageClass();
                    CType paramType = parseFullType();

                    // Function pointer parameter: type (*name)(params)
                    if (check(TokenType.LPAREN)) {
                        paramType = parseFunctionPointerType(paramType);
                        String paramName = "fp_arg" + params.size();
                        params.add(new Parameter(paramName, paramType));
                    } else {
                        String paramName = check(TokenType.IDENTIFIER) ? advance().value
                                : "arg" + params.size();

                        // Array parameter: type name[] or type name[N]
                        if (check(TokenType.LBRACKET)) {
                            skipBalanced(TokenType.LBRACKET, TokenType.RBRACKET);
                            paramType = new CType.Pointer(paramType); // arrays decay to pointers
                        }

                        params.add(new Parameter(paramName, paramType));
                    }

                    if (!match(TokenType.COMMA)) break;
                }
                if (check(TokenType.RPAREN)) advance();
            }

            // Skip __attribute__ after parameter list
            while (checkId("__attribute__") || checkId("__asm__") || checkId("__asm")
                    || checkId("__THROW") || checkId("__nonnull") || checkId("__wur")) {
                if (checkId("__attribute__") || checkId("__asm__") || checkId("__asm")) {
                    advance();
                    if (check(TokenType.LPAREN)) skipBalanced(TokenType.LPAREN, TokenType.RPAREN);
                } else {
                    advance();
                    if (check(TokenType.LPAREN)) skipBalanced(TokenType.LPAREN, TokenType.RPAREN);
                }
            }

            // Must end with semicolon (declaration) or we skip function body
            if (check(TokenType.LBRACE)) {
                skipBalanced(TokenType.LBRACE, TokenType.RBRACE);
            } else {
                match(TokenType.SEMICOLON);
            }

            functions.add(new NativeFunction(funcName, returnType, params, variadic));
        }

        /**
         * Parses a function pointer type: returnType (*)(paramTypes)
         * Called when we see LPAREN after a type specifier.
         */
        CType parseFunctionPointerType(CType returnType) {
            expect(TokenType.LPAREN);
            expect(TokenType.STAR);
            // Optional name
            if (check(TokenType.IDENTIFIER)) advance();
            expect(TokenType.RPAREN);

            // Parameter types
            expect(TokenType.LPAREN);
            List<CType> paramTypes = new ArrayList<>();
            if (!check(TokenType.RPAREN)) {
                while (!check(TokenType.RPAREN) && !check(TokenType.EOF)) {
                    if (check(TokenType.ELLIPSIS)) { advance(); break; }
                    paramTypes.add(parseFullType());
                    if (check(TokenType.IDENTIFIER)) advance(); // skip param name
                    if (check(TokenType.LBRACKET)) skipBalanced(TokenType.LBRACKET, TokenType.RBRACKET);
                    if (!match(TokenType.COMMA)) break;
                }
            }
            if (check(TokenType.RPAREN)) advance();

            return new CType.FunctionPointer(returnType, paramTypes);
        }


        // =====================================================================
        // STRUCT / UNION / ENUM PARSING
        // =====================================================================

        void parseStructDefinition() {
            advance(); // skip "struct"
            String name = check(TokenType.IDENTIFIER) ? advance().value : "<anon_" + pos + ">";
            CType.Struct s = parseStructBody(name);
            structs.put(name, s);
            typeRegistry.put("struct " + name, s);
            // Skip to semicolon (struct definition statement end)
            match(TokenType.SEMICOLON);
        }

        CType.Struct parseStructBody(String name) {
            expect(TokenType.LBRACE);
            List<StructField> fields = new ArrayList<>();
            long offset = 0;

            while (!check(TokenType.RBRACE) && !check(TokenType.EOF)) {
                try {
                    skipStorageClass();
                    CType fieldType = parseFullType();

                    // Multiple declarators: int a, b, *c;
                    do {
                        CType declType = fieldType;
                        // Additional pointer levels on declarator
                        while (check(TokenType.STAR)) { advance(); declType = new CType.Pointer(declType); }

                        String fieldName = check(TokenType.IDENTIFIER) ? advance().value
                                : "field_" + fields.size();

                        // Array field: int arr[10];
                        long arrayCount = 0;
                        if (check(TokenType.LBRACKET)) {
                            advance();
                            if (check(TokenType.NUMBER)) {
                                arrayCount = parseNumber(advance().value);
                            }
                            if (check(TokenType.RBRACKET)) advance();
                            if (arrayCount > 0) {
                                declType = new CType.Array(declType, arrayCount);
                            }
                        }

                        // Bitfield: int flags : 3;
                        if (check(TokenType.COLON)) {
                            advance();
                            if (check(TokenType.NUMBER)) advance(); // skip bit width
                        }

                        long fieldSize = estimateTypeSize(declType);
                        // Align offset
                        long alignment = Math.min(8, fieldSize > 0 ? fieldSize : 1);
                        if (alignment > 0) offset = (offset + alignment - 1) & ~(alignment - 1);

                        fields.add(new StructField(fieldName, declType, offset));
                        offset += fieldSize;
                    } while (match(TokenType.COMMA));

                    expect(TokenType.SEMICOLON);
                } catch (ParseException e) {
                    skipToSemicolon();
                }
            }
            if (check(TokenType.RBRACE)) advance();

            // Align total size to largest field alignment (simplified — 8 byte max)
            long totalSize = (offset + 7) & ~7;
            CType.Struct s = new CType.Struct(name, totalSize, fields);
            structs.put(name, s);
            typeRegistry.put("struct " + name, s);
            return s;
        }

        void parseUnionDefinition() {
            advance(); // skip "union"
            String name = check(TokenType.IDENTIFIER) ? advance().value : "<anon_" + pos + ">";
            CType.Union u = parseUnionBody(name);
            unions.put(name, u);
            typeRegistry.put("union " + name, u);
            match(TokenType.SEMICOLON);
        }

        CType.Union parseUnionBody(String name) {
            expect(TokenType.LBRACE);
            List<StructField> fields = new ArrayList<>();
            long maxSize = 0;

            while (!check(TokenType.RBRACE) && !check(TokenType.EOF)) {
                try {
                    skipStorageClass();
                    CType fieldType = parseFullType();
                    String fieldName = check(TokenType.IDENTIFIER) ? advance().value
                            : "field_" + fields.size();
                    if (check(TokenType.LBRACKET)) skipBalanced(TokenType.LBRACKET, TokenType.RBRACKET);
                    expect(TokenType.SEMICOLON);
                    long fieldSize = estimateTypeSize(fieldType);
                    maxSize = Math.max(maxSize, fieldSize);
                    fields.add(new StructField(fieldName, fieldType, 0)); // all at offset 0
                } catch (ParseException e) {
                    skipToSemicolon();
                }
            }
            if (check(TokenType.RBRACE)) advance();

            CType.Union u = new CType.Union(name, maxSize, fields);
            unions.put(name, u);
            return u;
        }

        void parseEnumDefinition() {
            advance(); // skip "enum"
            String name = check(TokenType.IDENTIFIER) ? advance().value : "<anon_" + pos + ">";
            CType.Enum e = parseEnumBody(name);
            enums.put(name, e);
            typeRegistry.put("enum " + name, e);
            match(TokenType.SEMICOLON);
        }

        CType.Enum parseEnumBody(String name) {
            expect(TokenType.LBRACE);
            List<EnumConstant> constants = new ArrayList<>();
            long nextValue = 0;

            while (!check(TokenType.RBRACE) && !check(TokenType.EOF)) {
                if (!check(TokenType.IDENTIFIER)) { advance(); continue; }
                String constName = advance().value;
                long value = nextValue;

                if (match(TokenType.EQUALS)) {
                    // Parse constant expression (simplified — handles literals and simple ops)
                    value = parseConstantExpression();
                }

                constants.add(new EnumConstant(constName, value));
                nextValue = value + 1;
                match(TokenType.COMMA);
            }
            if (check(TokenType.RBRACE)) advance();

            CType.Enum e = new CType.Enum(name, 4, constants);
            enums.put(name, e);
            return e;
        }


        // =====================================================================
        // TYPEDEF PARSING
        // =====================================================================

        void parseTypedef() {
            advance(); // skip "typedef"
            skipStorageClass();

            // typedef struct { ... } name;
            // typedef existing_type new_name;
            // typedef return_type (*func_ptr_name)(params);

            CType baseType = parseTypeSpecifier();

            // Function pointer typedef: typedef int (*name)(int, int);
            if (check(TokenType.LPAREN) && peek(1).type == TokenType.STAR) {
                advance(); // (
                advance(); // *
                String name = check(TokenType.IDENTIFIER) ? advance().value : "<anon_fp>";
                expect(TokenType.RPAREN);

                // Parameter types
                expect(TokenType.LPAREN);
                List<CType> paramTypes = new ArrayList<>();
                if (!check(TokenType.RPAREN)) {
                    while (!check(TokenType.RPAREN) && !check(TokenType.EOF)) {
                        if (check(TokenType.ELLIPSIS)) { advance(); break; }
                        paramTypes.add(parseFullType());
                        if (check(TokenType.IDENTIFIER)) advance();
                        if (check(TokenType.LBRACKET))
                            skipBalanced(TokenType.LBRACKET, TokenType.RBRACKET);
                        if (!match(TokenType.COMMA)) break;
                    }
                }
                if (check(TokenType.RPAREN)) advance();
                match(TokenType.SEMICOLON);

                CType fpType = new CType.FunctionPointer(baseType, paramTypes);
                typedefs.put(name, fpType);
                typeRegistry.put(name, fpType);
                return;
            }

            // Regular typedef: pointer levels + name
            while (check(TokenType.STAR)) {
                advance();
                while (checkId("const") || checkId("volatile") || checkId("restrict")
                        || checkId("__const") || checkId("__restrict")) advance();
                baseType = new CType.Pointer(baseType);
            }

            if (check(TokenType.IDENTIFIER)) {
                String name = advance().value;

                // Array typedef: typedef int arr_t[10];
                if (check(TokenType.LBRACKET)) {
                    advance();
                    long count = 0;
                    if (check(TokenType.NUMBER)) count = parseNumber(advance().value);
                    if (check(TokenType.RBRACKET)) advance();
                    if (count > 0) baseType = new CType.Array(baseType, count);
                }

                typedefs.put(name, baseType);
                typeRegistry.put(name, baseType);
            }

            match(TokenType.SEMICOLON);
        }


        // =====================================================================
        // HELPERS
        // =====================================================================

        private long parseConstantExpression() {
            // Simplified: handles integer literals, hex, negation, simple binary ops
            boolean negate = false;
            if (check(TokenType.MINUS)) { advance(); negate = true; }
            if (check(TokenType.TILDE)) { advance(); } // bitwise not — approximate

            if (check(TokenType.NUMBER)) {
                long val = parseNumber(advance().value);
                // Handle simple shifts and ORs
                while (check(TokenType.LSHIFT) || check(TokenType.PIPE)
                        || check(TokenType.PLUS) || check(TokenType.MINUS)) {
                    TokenType op = advance().type;
                    if (check(TokenType.NUMBER)) {
                        long right = parseNumber(advance().value);
                        val = switch (op) {
                            case LSHIFT -> val << right;
                            case PIPE -> val | right;
                            case PLUS -> val + right;
                            case MINUS -> val - right;
                            default -> val;
                        };
                    } else break;
                }
                return negate ? -val : val;
            }
            if (check(TokenType.CHAR_LITERAL)) {
                String lit = advance().value;
                if (lit.length() >= 3) return lit.charAt(1);
                return 0;
            }
            if (check(TokenType.IDENTIFIER)) {
                advance(); // skip — can't resolve named constants without preprocessor
                return 0;
            }
            if (check(TokenType.LPAREN)) {
                advance();
                long val = parseConstantExpression();
                match(TokenType.RPAREN);
                return val;
            }
            return 0;
        }

        private long parseNumber(String s) {
            s = s.replaceAll("[uUlLfF]+$", ""); // strip suffixes
            try {
                if (s.startsWith("0x") || s.startsWith("0X"))
                    return Long.parseUnsignedLong(s.substring(2), 16);
                if (s.startsWith("0") && s.length() > 1 && !s.contains("."))
                    return Long.parseLong(s, 8);
                return Long.parseLong(s);
            } catch (NumberFormatException e) {
                return 0;
            }
        }

        private long estimateTypeSize(CType type) {
            return switch (type) {
                case CType.Primitive p -> p.byteSize();
                case CType.Pointer ignored -> 8;
                case CType.Struct s -> s.byteSize();
                case CType.Union u -> u.byteSize();
                case CType.Enum ignored -> 4;
                case CType.Typedef t -> estimateTypeSize(t.underlying());
                case CType.Qualified q -> estimateTypeSize(q.underlying());
                case CType.Array a -> a.count() * estimateTypeSize(a.elementType());
                case CType.FunctionPointer ignored -> 8;
                case CType.Void ignored -> 0;
                case CType.Unresolved ignored -> 8; // assume pointer size
            };
        }
    }

    static class ParseException extends RuntimeException {
        ParseException(String msg) { super(msg); }
    }


    // =========================================================================
    // PREPROCESSOR — Run gcc -E to expand includes and macros
    // =========================================================================

    /**
     * Preprocesses a C header file using gcc -E.
     * Returns the preprocessed source as a string.
     *
     * @param headerPath   Path to the .h file
     * @param includeDirs  Additional -I directories (can be empty)
     */
    public static String preprocess(String headerPath, String... includeDirs) throws Exception {
        List<String> command = new ArrayList<>();
        command.add("gcc");
        command.add("-E");           // preprocess only
        command.add("-P");           // suppress line markers (cleaner output)
        command.add("-dD");          // keep #define directives (useful for constants)

        for (String dir : includeDirs) {
            command.add("-I");
            command.add(dir);
        }
        command.add(headerPath);

        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(false);
        Process process = pb.start();

        String output;
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()))) {
            output = reader.lines().collect(java.util.stream.Collectors.joining("\n"));
        }

        // Read stderr for errors
        String errors;
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getErrorStream()))) {
            errors = reader.lines().collect(java.util.stream.Collectors.joining("\n"));
        }

        int exitCode = process.waitFor();
        if (exitCode != 0) {
            throw new RuntimeException("gcc -E failed (exit " + exitCode + "):\n" + errors);
        }

        return output;
    }


    // =========================================================================
    // FFM BINDING — Same mapping logic as DwarfFFMLoader
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
            case CType.Array a -> MemoryLayout.sequenceLayout(a.count(), cTypeToLayout(a.elementType()));
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

    private static MemoryLayout buildStructLayout(CType.Struct s) {
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
        // Skip variadic functions
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

    /**
     * Loads a native library and binds all parsed functions to MethodHandles.
     */
    public static List<BoundFunction> bindLibrary(String libraryPath,
                                                  List<NativeFunction> functions) {
        List<BoundFunction> bound = new ArrayList<>();
        Linker linker = Linker.nativeLinker();

        try (Arena arena = Arena.ofConfined()) {
            SymbolLookup lookup = SymbolLookup.libraryLookup(Path.of(libraryPath), arena);

            for (NativeFunction func : functions) {
                try {
                    FunctionDescriptor desc = buildDescriptor(func);
                    if (desc == null) continue;

                    var symbol = lookup.find(func.name());
                    if (symbol.isEmpty()) continue;

                    MethodHandle handle = linker.downcallHandle(symbol.get(), desc);
                    bound.add(new BoundFunction(func, desc, handle));
                } catch (Exception e) {
                    System.err.println("  SKIP: " + func.name() + " — " + e.getMessage());
                }
            }
        }
        return bound;
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
            case CType.FunctionPointer fp -> typeToString(fp.returnType()) + "(*)(" +
                    fp.paramTypes().stream().map(CHeaderParser::typeToString)
                            .collect(java.util.stream.Collectors.joining(", ")) + ")";
            case CType.Void ignored -> "void";
            case CType.Unresolved u -> u.name() + "?";
        };
    }


    // =========================================================================
    // MAIN — Full pipeline: preprocess → parse → display → bind → invoke
    // =========================================================================

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.out.println("Usage: java --enable-native-access=ALL-UNNAMED CHeaderParser <header.h> [library.so] [-I dir ...]");
            System.out.println();
            System.out.println("Examples:");
            System.out.println("  CHeaderParser /usr/include/math.h /usr/lib/x86_64-linux-gnu/libm.so.6");
            System.out.println("  CHeaderParser /usr/include/pcap/pcap.h /usr/lib/x86_64-linux-gnu/libpcap.so");
            System.out.println("  CHeaderParser /usr/include/zlib.h /usr/lib/x86_64-linux-gnu/libz.so -I /usr/include");
            return;
        }

        String headerPath = args[0];
        String libraryPath = args.length > 1 && !args[1].startsWith("-") ? args[1] : null;

        // Collect -I directories
        List<String> includeDirs = new ArrayList<>();
        for (int i = 1; i < args.length; i++) {
            if (args[i].equals("-I") && i + 1 < args.length) {
                includeDirs.add(args[++i]);
            }
        }

        System.out.println("╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║         CHeaderParser — .h → FFM MethodHandle Pipeline      ║");
        System.out.println("╚══════════════════════════════════════════════════════════════╝");
        System.out.println();

        // --- Phase 1: Preprocess ---
        System.out.println("▶ PHASE 1: Preprocessing " + headerPath);
        String preprocessed = preprocess(headerPath, includeDirs.toArray(new String[0]));
        System.out.printf("  Preprocessed output: %d lines, %d chars%n%n",
                preprocessed.lines().count(), preprocessed.length());

        // --- Phase 2: Tokenize ---
        System.out.println("▶ PHASE 2: Tokenizing");
        List<Token> tokens = tokenize(preprocessed);
        System.out.printf("  Generated %d tokens%n%n", tokens.size());

        // --- Phase 3: Parse ---
        System.out.println("▶ PHASE 3: Parsing declarations");
        Parser parser = new Parser(tokens);
        parser.parseAll();

        System.out.printf("  Found: %d functions, %d structs, %d unions, %d enums, %d typedefs%n%n",
                parser.functions.size(), parser.structs.size(), parser.unions.size(),
                parser.enums.size(), parser.typedefs.size());

        // --- Phase 4: Display functions ---
        System.out.println("▶ PHASE 4: Discovered function signatures");
        System.out.println("─".repeat(75));

        int displayed = 0;
        for (NativeFunction func : parser.functions) {
            System.out.println("  " + func);
            if (++displayed >= 50) {
                System.out.printf("  ... and %d more%n", parser.functions.size() - displayed);
                break;
            }
        }
        System.out.println();

        // --- Phase 5: Display structs ---
        if (!parser.structs.isEmpty()) {
            System.out.println("▶ PHASE 5: Discovered struct layouts");
            System.out.println("─".repeat(75));

            int sc = 0;
            for (var entry : parser.structs.entrySet()) {
                CType.Struct s = entry.getValue();
                System.out.printf("  struct %s (%d bytes):%n", s.name(), s.byteSize());
                for (StructField f : s.fields()) {
                    System.out.printf("    +%-4d %-25s %s%n", f.offset(),
                            typeToString(f.type()), f.name());
                }
                System.out.println();
                if (++sc >= 10) break;
            }
        }

        // --- Phase 6: Display typedefs ---
        if (!parser.typedefs.isEmpty()) {
            System.out.println("▶ PHASE 6: Discovered typedefs");
            System.out.println("─".repeat(75));
            int tc = 0;
            for (var entry : parser.typedefs.entrySet()) {
                System.out.printf("  %-30s → %s%n", entry.getKey(), typeToString(entry.getValue()));
                if (++tc >= 20) {
                    System.out.printf("  ... and %d more%n", parser.typedefs.size() - tc);
                    break;
                }
            }
            System.out.println();
        }

        // --- Phase 7: Generate FunctionDescriptors ---
        System.out.println("▶ PHASE 7: FunctionDescriptor generation");
        System.out.println("─".repeat(75));

        long bindable = parser.functions.stream()
                .filter(f -> buildDescriptor(f) != null).count();
        long variadic = parser.functions.stream().filter(NativeFunction::variadic).count();

        System.out.printf("  %d bindable, %d variadic (skipped), %d total%n%n",
                bindable, variadic, parser.functions.size());

        int dc = 0;
        for (NativeFunction func : parser.functions) {
            FunctionDescriptor desc = buildDescriptor(func);
            if (desc != null) {
                System.out.printf("  %-35s → %s%n", func.name(), desc);
                if (++dc >= 25) break;
            }
        }
        System.out.println();

        // --- Phase 8: Bind and invoke ---
        if (libraryPath != null) {
            System.out.println("▶ PHASE 8: Binding " + libraryPath);
            System.out.println("─".repeat(75));

            List<BoundFunction> bound = bindLibrary(libraryPath, parser.functions);
            System.out.printf("  Successfully bound %d functions%n%n", bound.size());

            // Invoke safe functions (double → double)
            System.out.println("  Sample invocations (double→double functions):");
            for (BoundFunction bf : bound) {
                NativeFunction func = bf.function();
                CType retBase = unwrapType(func.returnType());
                CType paramBase = func.params().size() == 1 ? unwrapType(func.params().getFirst().type()) : null;

                if (func.params().size() == 1
                        && retBase instanceof CType.Primitive ret
                        && ret.encoding() == CType.Encoding.FLOAT && ret.byteSize() == 8
                        && paramBase instanceof CType.Primitive param
                        && param.encoding() == CType.Encoding.FLOAT && param.byteSize() == 8) {
                    try {
                        double result = (double) bf.handle().invoke(1.0);
                        System.out.printf("    %s(1.0) = %.15f%n", func.name(), result);
                    } catch (Throwable t) {
                        System.out.printf("    %s(1.0) → error: %s%n", func.name(), t.getMessage());
                    }
                }
            }
        }

        System.out.println();
        System.out.println("Done.");
    }

    /** Unwraps typedefs and qualifiers to get the base type */
    private static CType unwrapType(CType type) {
        return switch (type) {
            case CType.Typedef t -> unwrapType(t.underlying());
            case CType.Qualified q -> unwrapType(q.underlying());
            default -> type;
        };
    }
}
