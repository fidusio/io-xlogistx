package io.xlogistx.ffm;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.nio.file.Path;
import java.util.*;

/**
 * DwarfFFMLoader — Uses FFM to call libdw (elfutils), parses DWARF debug info
 * from a shared library, discovers all exported function signatures and struct
 * layouts, then loads the library and creates invocable MethodHandles.
 *
 * This is a bootstrap approach: FFM calls libdw to get type info, then uses
 * that type info to create FFM bindings for the target library.
 *
 * Requirements:
 *   - Linux with elfutils installed: sudo apt install libdw-dev elfutils
 *   - Target library compiled with -g (debug info) or its -dbgsym package installed
 *   - JDK 22+ (FFM API finalized)
 *
 * Usage:
 *   javac DwarfFFMLoader.java
 *   java --enable-native-access=ALL-UNNAMED DwarfFFMLoader /usr/lib/x86_64-linux-gnu/libm.so.6
 *
 * Architecture:
 *   1. LibDwBridge    — FFM bindings to libdw + libc (open/close)
 *   2. DwarfParser    — Walks DIE tree, resolves types, extracts signatures
 *   3. NativeFunction — Parsed function with name, return type, parameters
 *   4. NativeStruct   — Parsed struct with fields, sizes, offsets
 *   5. FFMBinder      — Maps parsed types → FunctionDescriptor → MethodHandle
 */
public class DwarfFFMLoader implements AutoCloseable {

    // =========================================================================
    // DATA MODEL — Parsed DWARF type information
    // =========================================================================

    /**
     * Represents a resolved C type extracted from DWARF.
     */
    public sealed interface CType {
        /** Primitive: int, long, float, double, char, bool, void */
        record Primitive(String name, int byteSize, Encoding encoding) implements CType {}

        /** Pointer to another type */
        record Pointer(CType pointee) implements CType {}

        /** Named struct with fields */
        record Struct(String name, long byteSize, List<StructField> fields) implements CType {}

        /** Named union */
        record Union(String name, long byteSize) implements CType {}

        /** Named enum (treated as int) */
        record Enum(String name, int byteSize) implements CType {}

        /** Typedef — resolved to its underlying type */
        record Typedef(String name, CType underlying) implements CType {}

        /** Const/volatile qualifier — resolved to its underlying type */
        record Qualified(CType underlying) implements CType {}

        /** Array of elements */
        record Array(CType elementType, long count) implements CType {}

        /** Void (for void return types) */
        record Void() implements CType {}

        /** Unresolved — type reference could not be followed */
        record Unresolved(String reason) implements CType {}

        enum Encoding {
            SIGNED, UNSIGNED, FLOAT, BOOLEAN, SIGNED_CHAR, UNSIGNED_CHAR, UNKNOWN
        }
    }

    /** A field within a struct */
    public record StructField(String name, CType type, long offset) {}

    /** A function parameter */
    public record Parameter(String name, CType type) {}

    /** A fully resolved native function signature */
    public record NativeFunction(String name, CType returnType, List<Parameter> params) {
        @Override
        public String toString() {
            StringJoiner pj = new StringJoiner(", ");
            for (Parameter p : params) pj.add(typeToString(p.type) + " " + p.name);
            return typeToString(returnType) + " " + name + "(" + pj + ")";
        }
    }

    /** A bound native function: signature + live MethodHandle */
    public record BoundFunction(NativeFunction function, FunctionDescriptor descriptor,
                                MethodHandle handle) {}


    // =========================================================================
    // DWARF CONSTANTS
    // =========================================================================

    // DW_TAG values
    private static final int DW_TAG_subprogram        = 0x2e;
    private static final int DW_TAG_formal_parameter   = 0x05;
    private static final int DW_TAG_base_type          = 0x24;
    private static final int DW_TAG_pointer_type       = 0x0f;
    private static final int DW_TAG_structure_type     = 0x13;
    private static final int DW_TAG_union_type         = 0x17;
    private static final int DW_TAG_typedef            = 0x16;
    private static final int DW_TAG_const_type         = 0x26;
    private static final int DW_TAG_volatile_type      = 0x35;
    private static final int DW_TAG_enumeration_type   = 0x04;
    private static final int DW_TAG_array_type         = 0x01;
    private static final int DW_TAG_member             = 0x0d;
    private static final int DW_TAG_subrange_type      = 0x21;
    private static final int DW_TAG_subroutine_type    = 0x15;
    private static final int DW_TAG_restrict_type      = 0x37;
    private static final int DW_TAG_unspecified_parameters = 0x18;

    // DW_AT attribute names
    private static final int DW_AT_name                = 0x03;
    private static final int DW_AT_type                = 0x49;
    private static final int DW_AT_byte_size           = 0x0b;
    private static final int DW_AT_encoding            = 0x3e;
    private static final int DW_AT_external            = 0x3f;
    private static final int DW_AT_data_member_location = 0x38;
    private static final int DW_AT_upper_bound         = 0x2f;
    private static final int DW_AT_count               = 0x37;

    // DW_ATE base type encodings
    private static final int DW_ATE_signed             = 0x05;
    private static final int DW_ATE_unsigned            = 0x07;
    private static final int DW_ATE_float              = 0x04;
    private static final int DW_ATE_boolean            = 0x02;
    private static final int DW_ATE_signed_char        = 0x06;
    private static final int DW_ATE_unsigned_char      = 0x08;

    // libc constants
    private static final int O_RDONLY                  = 0;

    // libdw constants
    private static final int DWARF_C_READ             = 0;


    // =========================================================================
    // LIBDW STRUCT LAYOUTS (64-bit Linux)
    // =========================================================================

    /**
     * Dwarf_Die in libdw (elfutils):
     *   struct {
     *       void *addr;           // 8 bytes
     *       struct Dwarf_CU *cu;  // 8 bytes
     *       Dwarf_Abbrev *abbrev; // 8 bytes
     *       long int padding__;   // 8 bytes
     *   };
     * Total: 32 bytes, 8-byte aligned
     */
    private static final StructLayout DWARF_DIE_LAYOUT = MemoryLayout.structLayout(
            ValueLayout.ADDRESS.withName("addr"),
            ValueLayout.ADDRESS.withName("cu"),
            ValueLayout.ADDRESS.withName("abbrev"),
            ValueLayout.JAVA_LONG.withName("padding")
    );
    private static final long DWARF_DIE_SIZE = DWARF_DIE_LAYOUT.byteSize(); // 32

    /**
     * Dwarf_Attribute in libdw:
     *   struct {
     *       unsigned int code;     // 4 bytes
     *       unsigned int form;     // 4 bytes
     *       unsigned char *valp;   // 8 bytes
     *       struct Dwarf_CU *cu;   // 8 bytes
     *   };
     * Total: 24 bytes, 8-byte aligned
     */
    private static final StructLayout DWARF_ATTR_LAYOUT = MemoryLayout.structLayout(
            ValueLayout.JAVA_INT.withName("code"),
            ValueLayout.JAVA_INT.withName("form"),
            ValueLayout.ADDRESS.withName("valp"),
            ValueLayout.ADDRESS.withName("cu")
    );
    private static final long DWARF_ATTR_SIZE = DWARF_ATTR_LAYOUT.byteSize(); // 24


    // =========================================================================
    // FFM BRIDGE TO LIBDW — MethodHandles for all required libdw functions
    // =========================================================================

    private final Arena arena;
    private final Linker linker;

    // libc handles
    private final MethodHandle open_mh;     // int open(const char *path, int flags)
    private final MethodHandle close_mh;    // int close(int fd)

    // libdw handles
    private final MethodHandle dwarf_begin_mh;      // Dwarf *dwarf_begin(int fd, Dwarf_Cmd cmd)
    private final MethodHandle dwarf_end_mh;         // int dwarf_end(Dwarf *dwarf)
    private final MethodHandle dwarf_nextcu_mh;      // int dwarf_nextcu(Dwarf*, Off, Off*, size_t*, Off*, uint8_t*, uint8_t*)
    private final MethodHandle dwarf_offdie_mh;      // Dwarf_Die *dwarf_offdie(Dwarf*, Off, Dwarf_Die *result)
    private final MethodHandle dwarf_child_mh;       // int dwarf_child(Dwarf_Die*, Dwarf_Die *result)
    private final MethodHandle dwarf_siblingof_mh;   // int dwarf_siblingof(Dwarf_Die*, Dwarf_Die *result)
    private final MethodHandle dwarf_tag_mh;         // int dwarf_tag(Dwarf_Die*)
    private final MethodHandle dwarf_diename_mh;     // const char *dwarf_diename(Dwarf_Die*)
    private final MethodHandle dwarf_attr_mh;        // Dwarf_Attribute *dwarf_attr(Dwarf_Die*, uint, Dwarf_Attribute *result)
    private final MethodHandle dwarf_formref_die_mh; // Dwarf_Die *dwarf_formref_die(Dwarf_Attribute*, Dwarf_Die *result)
    private final MethodHandle dwarf_formudata_mh;   // int dwarf_formudata(Dwarf_Attribute*, Dwarf_Word *result)
    private final MethodHandle dwarf_formflag_mh;    // int dwarf_formflag(Dwarf_Attribute*, bool *result)
    private final MethodHandle dwarf_dieoffset_mh;   // Dwarf_Off dwarf_dieoffset(Dwarf_Die*)
    private final MethodHandle dwarf_errmsg_mh;      // const char *dwarf_errmsg(int error)

    // State
    private MemorySegment dwarfHandle; // Dwarf* pointer from dwarf_begin
    private int fd = -1;

    // Type cache: DIE offset → resolved CType (avoids infinite recursion on self-referential structs)
    private final Map<Long, CType> typeCache = new HashMap<>();

    // Parsed results
    private final List<NativeFunction> functions = new ArrayList<>();
    private final Map<String, CType.Struct> structs = new LinkedHashMap<>();


    // =========================================================================
    // CONSTRUCTOR — Bind all libdw functions via FFM
    // =========================================================================

    public DwarfFFMLoader() {
        this.arena = Arena.ofConfined();
        this.linker = Linker.nativeLinker();

        // --- Bind libc open/close ---
        SymbolLookup defaultLookup = linker.defaultLookup();
        SymbolLookup libcLookup = SymbolLookup.loaderLookup();

        // For libc functions, try default lookup first, then loader lookup
        open_mh = linker.downcallHandle(
                findSymbol(defaultLookup, libcLookup, "open"),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT));

        close_mh = linker.downcallHandle(
                findSymbol(defaultLookup, libcLookup, "close"),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT));

        // --- Load libdw and bind all required functions ---
        SymbolLookup libdw = SymbolLookup.libraryLookup("libdw.so.1", arena);

        dwarf_begin_mh = linker.downcallHandle(
                libdw.find("dwarf_begin").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT));

        dwarf_end_mh = linker.downcallHandle(
                libdw.find("dwarf_end").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));

        // int dwarf_nextcu(Dwarf*, Dwarf_Off off, Dwarf_Off *next_off,
        //                  size_t *header_size, Dwarf_Off *abbrev_offset,
        //                  uint8_t *address_size, uint8_t *offset_size)
        dwarf_nextcu_mh = linker.downcallHandle(
                libdw.find("dwarf_nextcu").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT,
                        ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS, ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS, ValueLayout.ADDRESS));

        // Dwarf_Die *dwarf_offdie(Dwarf *dbg, Dwarf_Off offset, Dwarf_Die *result)
        dwarf_offdie_mh = linker.downcallHandle(
                libdw.find("dwarf_offdie").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));

        // int dwarf_child(Dwarf_Die *die, Dwarf_Die *result)
        dwarf_child_mh = linker.downcallHandle(
                libdw.find("dwarf_child").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS));

        // int dwarf_siblingof(Dwarf_Die *die, Dwarf_Die *result)
        dwarf_siblingof_mh = linker.downcallHandle(
                libdw.find("dwarf_siblingof").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS));

        // int dwarf_tag(Dwarf_Die *die)
        dwarf_tag_mh = linker.downcallHandle(
                libdw.find("dwarf_tag").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));

        // const char *dwarf_diename(Dwarf_Die *die)
        dwarf_diename_mh = linker.downcallHandle(
                libdw.find("dwarf_diename").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS));

        // Dwarf_Attribute *dwarf_attr(Dwarf_Die *die, unsigned int name, Dwarf_Attribute *result)
        dwarf_attr_mh = linker.downcallHandle(
                libdw.find("dwarf_attr").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.ADDRESS,
                        ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.ADDRESS));

        // Dwarf_Die *dwarf_formref_die(Dwarf_Attribute *attr, Dwarf_Die *result)
        dwarf_formref_die_mh = linker.downcallHandle(
                libdw.find("dwarf_formref_die").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));

        // int dwarf_formudata(Dwarf_Attribute *attr, Dwarf_Word *valuep)
        dwarf_formudata_mh = linker.downcallHandle(
                libdw.find("dwarf_formudata").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS));

        // int dwarf_formflag(Dwarf_Attribute *attr, bool *valuep)
        dwarf_formflag_mh = linker.downcallHandle(
                libdw.find("dwarf_formflag").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS));

        // Dwarf_Off dwarf_dieoffset(Dwarf_Die *die)
        dwarf_dieoffset_mh = linker.downcallHandle(
                libdw.find("dwarf_dieoffset").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));

        // const char *dwarf_errmsg(int error) — -1 for last error
        dwarf_errmsg_mh = linker.downcallHandle(
                libdw.find("dwarf_errmsg").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
    }

    private MemorySegment findSymbol(SymbolLookup... lookups) {
        throw new NoSuchElementException("Not used directly — see overload");
    }

    private MemorySegment findSymbol(SymbolLookup primary, SymbolLookup fallback, String name) {
        return primary.find(name)
                .or(() -> fallback.find(name))
                .orElseThrow(() -> new NoSuchElementException("Symbol not found: " + name));
    }


    // =========================================================================
    // DWARF PARSING — Open library, walk CUs, extract functions and types
    // =========================================================================

    /**
     * Opens a shared library's DWARF debug info and parses all exported
     * function signatures and struct definitions.
     *
     * @param libraryPath Path to .so file (must have debug info or separate .debug)
     */
    public void parseDwarf(String libraryPath) throws Throwable {
        // Open the file via libc open()
        MemorySegment pathStr = arena.allocateFrom(libraryPath);
        fd = (int) open_mh.invoke(pathStr, O_RDONLY);
        if (fd < 0) {
            throw new RuntimeException("Failed to open: " + libraryPath);
        }

        // Initialize libdw
        dwarfHandle = (MemorySegment) dwarf_begin_mh.invoke(fd, DWARF_C_READ);
        if (dwarfHandle.address() == 0) {
            MemorySegment errMsg = (MemorySegment) dwarf_errmsg_mh.invoke(-1);
            String err = errMsg.address() != 0
                    ? errMsg.reinterpret(256).getString(0)
                    : "unknown error";
            throw new RuntimeException("dwarf_begin failed: " + err
                    + " — is the library compiled with -g or does a -dbgsym package exist?");
        }

        // Iterate compilation units
        MemorySegment nextOff = arena.allocate(ValueLayout.JAVA_LONG);
        MemorySegment headerSize = arena.allocate(ValueLayout.JAVA_LONG);

        long cuOffset = 0;
        while (true) {
            int rc = (int) dwarf_nextcu_mh.invoke(dwarfHandle, cuOffset, nextOff,
                    headerSize, MemorySegment.NULL, MemorySegment.NULL, MemorySegment.NULL);
            if (rc != 0) break; // no more CUs

            long hdrSize = headerSize.get(ValueLayout.JAVA_LONG, 0);

            // Get the CU's root DIE
            MemorySegment cuDie = arena.allocate(DWARF_DIE_LAYOUT);
            MemorySegment result = (MemorySegment) dwarf_offdie_mh.invoke(
                    dwarfHandle, cuOffset + hdrSize, cuDie);

            if (result.address() != 0) {
                // Walk all children of the CU
                walkChildren(cuDie);
            }

            cuOffset = nextOff.get(ValueLayout.JAVA_LONG, 0);
        }
    }

    /**
     * Recursively walks the children of a DIE, extracting functions and types.
     */
    private void walkChildren(MemorySegment parentDie) throws Throwable {
        MemorySegment child = arena.allocate(DWARF_DIE_LAYOUT);
        int rc = (int) dwarf_child_mh.invoke(parentDie, child);
        if (rc != 0) return; // no children

        do {
            int tag = (int) dwarf_tag_mh.invoke(child);

            switch (tag) {
                case DW_TAG_subprogram -> processFunction(child);
                case DW_TAG_structure_type -> processStructType(child);
                // types are resolved lazily when referenced by functions
            }

            // Allocate fresh DIE for next sibling (reusing can cause issues
            // with some libdw versions if internal state is shared)
            MemorySegment next = arena.allocate(DWARF_DIE_LAYOUT);
            rc = (int) dwarf_siblingof_mh.invoke(child, next);
            child = next;
        } while (rc == 0);
    }

    /**
     * Processes a DW_TAG_subprogram DIE — extracts function name, return type,
     * and parameters. Only processes externally visible functions.
     */
    private void processFunction(MemorySegment die) throws Throwable {
        // Get function name
        String name = getDieName(die);
        if (name == null) return;

        // Check if externally visible (DW_AT_external = true)
        // Not all functions have this attribute; if missing, include anyway
        Boolean external = getAttrFlag(die, DW_AT_external);
        if (external != null && !external) return;

        // Get return type
        CType returnType = resolveTypeAttribute(die);
        if (returnType == null) returnType = new CType.Void();

        // Get parameters by walking children
        List<Parameter> params = new ArrayList<>();
        MemorySegment paramDie = arena.allocate(DWARF_DIE_LAYOUT);
        int rc = (int) dwarf_child_mh.invoke(die, paramDie);

        if (rc == 0) {
            do {
                int tag = (int) dwarf_tag_mh.invoke(paramDie);
                if (tag == DW_TAG_formal_parameter) {
                    String paramName = getDieName(paramDie);
                    if (paramName == null) paramName = "arg" + params.size();
                    CType paramType = resolveTypeAttribute(paramDie);
                    if (paramType == null) paramType = new CType.Unresolved("no type");
                    params.add(new Parameter(paramName, paramType));
                } else if (tag == DW_TAG_unspecified_parameters) {
                    // variadic function (e.g., printf) — mark and stop
                    params.add(new Parameter("...", new CType.Unresolved("variadic")));
                    break;
                }

                MemorySegment nextParam = arena.allocate(DWARF_DIE_LAYOUT);
                rc = (int) dwarf_siblingof_mh.invoke(paramDie, nextParam);
                paramDie = nextParam;
            } while (rc == 0);
        }

        functions.add(new NativeFunction(name, returnType, params));
    }

    /**
     * Processes a DW_TAG_structure_type DIE — extracts struct layout with fields.
     */
    private void processStructType(MemorySegment die) throws Throwable {
        String name = getDieName(die);
        if (name == null) return;

        long dieOffset = (long) dwarf_dieoffset_mh.invoke(die);

        // Check if already cached (avoid re-processing)
        if (typeCache.containsKey(dieOffset)) return;

        Long byteSize = getAttrUdata(die, DW_AT_byte_size);
        if (byteSize == null) return; // forward declaration, no size

        List<StructField> fields = new ArrayList<>();

        // Walk member children
        MemorySegment memberDie = arena.allocate(DWARF_DIE_LAYOUT);
        int rc = (int) dwarf_child_mh.invoke(die, memberDie);
        if (rc == 0) {
            do {
                int tag = (int) dwarf_tag_mh.invoke(memberDie);
                if (tag == DW_TAG_member) {
                    String fieldName = getDieName(memberDie);
                    if (fieldName == null) fieldName = "field_" + fields.size();
                    CType fieldType = resolveTypeAttribute(memberDie);
                    if (fieldType == null) fieldType = new CType.Unresolved("no type");
                    Long offset = getAttrUdata(memberDie, DW_AT_data_member_location);
                    fields.add(new StructField(fieldName, fieldType, offset != null ? offset : 0));
                }

                MemorySegment nextMember = arena.allocate(DWARF_DIE_LAYOUT);
                rc = (int) dwarf_siblingof_mh.invoke(memberDie, nextMember);
                memberDie = nextMember;
            } while (rc == 0);
        }

        CType.Struct struct = new CType.Struct(name, byteSize, fields);
        typeCache.put(dieOffset, struct);
        structs.put(name, struct);
    }


    // =========================================================================
    // TYPE RESOLUTION — Chase DWARF type reference chains to base types
    // =========================================================================

    /**
     * Resolves the DW_AT_type attribute of a DIE to a CType.
     * Follows the type reference chain: pointer → typedef → const → base_type
     */
    private CType resolveTypeAttribute(MemorySegment die) throws Throwable {
        // Get DW_AT_type attribute
        MemorySegment attr = arena.allocate(DWARF_ATTR_LAYOUT);
        MemorySegment attrResult = (MemorySegment) dwarf_attr_mh.invoke(die, DW_AT_type, attr);
        if (attrResult.address() == 0) return null; // no type attribute → void

        // Follow the reference to the type DIE
        MemorySegment typeDie = arena.allocate(DWARF_DIE_LAYOUT);
        MemorySegment refResult = (MemorySegment) dwarf_formref_die_mh.invoke(attr, typeDie);
        if (refResult.address() == 0) return new CType.Unresolved("formref failed");

        return resolveTypeDie(typeDie);
    }

    /**
     * Resolves a type DIE to a CType, with caching to handle recursive types.
     */
    private CType resolveTypeDie(MemorySegment typeDie) throws Throwable {
        long offset = (long) dwarf_dieoffset_mh.invoke(typeDie);

        // Check cache first (prevents infinite recursion on self-referential structs)
        CType cached = typeCache.get(offset);
        if (cached != null) return cached;

        int tag = (int) dwarf_tag_mh.invoke(typeDie);

        CType resolved = switch (tag) {
            case DW_TAG_base_type -> resolveBaseType(typeDie);
            case DW_TAG_pointer_type -> resolvePointerType(typeDie);
            case DW_TAG_structure_type -> resolveStructRef(typeDie, offset);
            case DW_TAG_union_type -> resolveUnionRef(typeDie);
            case DW_TAG_typedef -> resolveTypedef(typeDie);
            case DW_TAG_const_type, DW_TAG_volatile_type, DW_TAG_restrict_type ->
                    resolveQualifiedType(typeDie);
            case DW_TAG_enumeration_type -> resolveEnumType(typeDie);
            case DW_TAG_array_type -> resolveArrayType(typeDie);
            case DW_TAG_subroutine_type -> new CType.Pointer(new CType.Void()); // function pointer → treat as ADDRESS
            default -> new CType.Unresolved("unknown tag: 0x" + Integer.toHexString(tag));
        };

        typeCache.put(offset, resolved);
        return resolved;
    }

    private CType resolveBaseType(MemorySegment die) throws Throwable {
        String name = getDieName(die);
        if (name == null) name = "unknown";

        Long byteSize = getAttrUdata(die, DW_AT_byte_size);
        Long encoding = getAttrUdata(die, DW_AT_encoding);

        CType.Encoding enc = CType.Encoding.UNKNOWN;
        if (encoding != null) {
            enc = switch (encoding.intValue()) {
                case DW_ATE_signed -> CType.Encoding.SIGNED;
                case DW_ATE_unsigned -> CType.Encoding.UNSIGNED;
                case DW_ATE_float -> CType.Encoding.FLOAT;
                case DW_ATE_boolean -> CType.Encoding.BOOLEAN;
                case DW_ATE_signed_char -> CType.Encoding.SIGNED_CHAR;
                case DW_ATE_unsigned_char -> CType.Encoding.UNSIGNED_CHAR;
                default -> CType.Encoding.UNKNOWN;
            };
        }

        return new CType.Primitive(name, byteSize != null ? byteSize.intValue() : 0, enc);
    }

    private CType resolvePointerType(MemorySegment die) throws Throwable {
        CType pointee = resolveTypeAttribute(die);
        if (pointee == null) pointee = new CType.Void(); // void* — DW_AT_type absent
        return new CType.Pointer(pointee);
    }

    private CType resolveStructRef(MemorySegment die, long offset) throws Throwable {
        String name = getDieName(die);
        Long byteSize = getAttrUdata(die, DW_AT_byte_size);

        if (byteSize == null) {
            // Forward declaration — no body
            return new CType.Struct(name != null ? name : "<anon>", 0, List.of());
        }

        // Put a placeholder in cache BEFORE processing fields (breaks recursion)
        CType.Struct placeholder = new CType.Struct(
                name != null ? name : "<anon>", byteSize, List.of());
        typeCache.put(offset, placeholder);

        // Now process fields
        List<StructField> fields = new ArrayList<>();
        MemorySegment memberDie = arena.allocate(DWARF_DIE_LAYOUT);
        int rc = (int) dwarf_child_mh.invoke(die, memberDie);
        if (rc == 0) {
            do {
                int tag = (int) dwarf_tag_mh.invoke(memberDie);
                if (tag == DW_TAG_member) {
                    String fieldName = getDieName(memberDie);
                    CType fieldType = resolveTypeAttribute(memberDie);
                    Long fieldOffset = getAttrUdata(memberDie, DW_AT_data_member_location);
                    fields.add(new StructField(
                            fieldName != null ? fieldName : "field_" + fields.size(),
                            fieldType != null ? fieldType : new CType.Unresolved("no type"),
                            fieldOffset != null ? fieldOffset : 0));
                }
                MemorySegment next = arena.allocate(DWARF_DIE_LAYOUT);
                rc = (int) dwarf_siblingof_mh.invoke(memberDie, next);
                memberDie = next;
            } while (rc == 0);
        }

        CType.Struct full = new CType.Struct(name != null ? name : "<anon>", byteSize, fields);
        typeCache.put(offset, full); // replace placeholder
        return full;
    }

    private CType resolveUnionRef(MemorySegment die) throws Throwable {
        String name = getDieName(die);
        Long byteSize = getAttrUdata(die, DW_AT_byte_size);
        return new CType.Union(name != null ? name : "<anon>",
                byteSize != null ? byteSize : 0);
    }

    private CType resolveTypedef(MemorySegment die) throws Throwable {
        String name = getDieName(die);
        CType underlying = resolveTypeAttribute(die);
        if (underlying == null) underlying = new CType.Void();
        return new CType.Typedef(name != null ? name : "<anon>", underlying);
    }

    private CType resolveQualifiedType(MemorySegment die) throws Throwable {
        CType underlying = resolveTypeAttribute(die);
        if (underlying == null) underlying = new CType.Void(); // const void
        return new CType.Qualified(underlying);
    }

    private CType resolveEnumType(MemorySegment die) throws Throwable {
        String name = getDieName(die);
        Long byteSize = getAttrUdata(die, DW_AT_byte_size);
        return new CType.Enum(name != null ? name : "<anon>",
                byteSize != null ? byteSize.intValue() : 4);
    }

    private CType resolveArrayType(MemorySegment die) throws Throwable {
        CType elementType = resolveTypeAttribute(die);
        if (elementType == null) elementType = new CType.Unresolved("no element type");

        // Array bounds are in a DW_TAG_subrange_type child
        long count = 0;
        MemorySegment child = arena.allocate(DWARF_DIE_LAYOUT);
        if ((int) dwarf_child_mh.invoke(die, child) == 0) {
            int childTag = (int) dwarf_tag_mh.invoke(child);
            if (childTag == DW_TAG_subrange_type) {
                Long upperBound = getAttrUdata(child, DW_AT_upper_bound);
                Long countVal = getAttrUdata(child, DW_AT_count);
                if (countVal != null) count = countVal;
                else if (upperBound != null) count = upperBound + 1;
            }
        }

        return new CType.Array(elementType, count);
    }


    // =========================================================================
    // ATTRIBUTE HELPERS — Read name, udata, flag from DIE attributes
    // =========================================================================

    private String getDieName(MemorySegment die) throws Throwable {
        MemorySegment namePtr = (MemorySegment) dwarf_diename_mh.invoke(die);
        if (namePtr.address() == 0) return null;
        return namePtr.reinterpret(256).getString(0);
    }

    private Long getAttrUdata(MemorySegment die, int attrName) throws Throwable {
        MemorySegment attr = arena.allocate(DWARF_ATTR_LAYOUT);
        MemorySegment result = (MemorySegment) dwarf_attr_mh.invoke(die, attrName, attr);
        if (result.address() == 0) return null;

        MemorySegment value = arena.allocate(ValueLayout.JAVA_LONG);
        int rc = (int) dwarf_formudata_mh.invoke(attr, value);
        if (rc != 0) return null;
        return value.get(ValueLayout.JAVA_LONG, 0);
    }

    private Boolean getAttrFlag(MemorySegment die, int attrName) throws Throwable {
        MemorySegment attr = arena.allocate(DWARF_ATTR_LAYOUT);
        MemorySegment result = (MemorySegment) dwarf_attr_mh.invoke(die, attrName, attr);
        if (result.address() == 0) return null;

        MemorySegment value = arena.allocate(ValueLayout.JAVA_INT);
        int rc = (int) dwarf_formflag_mh.invoke(attr, value);
        if (rc != 0) return null;
        return value.get(ValueLayout.JAVA_INT, 0) != 0;
    }


    // =========================================================================
    // FFM BINDER — Map CType → FunctionDescriptor → MethodHandle
    // =========================================================================

    /**
     * Maps a resolved CType to an FFM MemoryLayout for use in FunctionDescriptors.
     * This is where C types become Java FFM types.
     */
    public static MemoryLayout cTypeToLayout(CType type) {
        return switch (type) {
            case CType.Primitive p -> primitiveToLayout(p);
            case CType.Pointer ignored -> ValueLayout.ADDRESS;
            case CType.Struct s -> buildStructLayout(s);
            case CType.Union u -> MemoryLayout.paddingLayout(u.byteSize());
            case CType.Enum e -> e.byteSize() <= 4 ? ValueLayout.JAVA_INT : ValueLayout.JAVA_LONG;
            case CType.Typedef t -> cTypeToLayout(t.underlying());
            case CType.Qualified q -> cTypeToLayout(q.underlying());
            case CType.Array a -> MemoryLayout.sequenceLayout(a.count(), cTypeToLayout(a.elementType()));
            case CType.Void ignored -> null; // void return → no layout
            case CType.Unresolved ignored -> ValueLayout.ADDRESS; // best guess for unknowns
        };
    }

    private static MemoryLayout primitiveToLayout(CType.Primitive p) {
        return switch (p.encoding()) {
            case FLOAT -> switch (p.byteSize()) {
                case 4 -> ValueLayout.JAVA_FLOAT;
                case 8 -> ValueLayout.JAVA_DOUBLE;
                default -> ValueLayout.JAVA_DOUBLE;
            };
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
        if (s.fields().isEmpty() || s.byteSize() == 0) {
            return MemoryLayout.paddingLayout(s.byteSize() > 0 ? s.byteSize() : 1);
        }

        List<MemoryLayout> members = new ArrayList<>();
        long currentOffset = 0;

        for (StructField field : s.fields()) {
            // Insert padding if there's a gap
            if (field.offset() > currentOffset) {
                members.add(MemoryLayout.paddingLayout(field.offset() - currentOffset));
            }

            MemoryLayout fieldLayout = cTypeToLayout(field.type());
            if (fieldLayout != null) {
                members.add(fieldLayout.withName(field.name()));
                currentOffset = field.offset() + fieldLayout.byteSize();
            }
        }

        // Trailing padding
        if (currentOffset < s.byteSize()) {
            members.add(MemoryLayout.paddingLayout(s.byteSize() - currentOffset));
        }

        return MemoryLayout.structLayout(members.toArray(new MemoryLayout[0]));
    }

    /**
     * Creates a FunctionDescriptor from a parsed NativeFunction.
     * Returns null if the function has variadic parameters (not supported by FFM downcalls).
     */
    public static FunctionDescriptor buildDescriptor(NativeFunction func) {
        // Skip variadic functions — FFM downcall doesn't support them directly
        for (Parameter p : func.params()) {
            if (p.type() instanceof CType.Unresolved u && u.reason().equals("variadic")) {
                return null;
            }
        }

        MemoryLayout returnLayout = cTypeToLayout(func.returnType());
        MemoryLayout[] paramLayouts = func.params().stream()
                .map(p -> cTypeToLayout(p.type()))
                .filter(Objects::nonNull)
                .toArray(MemoryLayout[]::new);

        if (returnLayout != null) {
            return FunctionDescriptor.of(returnLayout, paramLayouts);
        } else {
            return FunctionDescriptor.ofVoid(paramLayouts);
        }
    }

    /**
     * Loads the target library and creates MethodHandles for all parseable functions.
     */
    public List<BoundFunction> bindLibrary(String libraryPath) {
        List<BoundFunction> bound = new ArrayList<>();
        Linker nativeLinker = Linker.nativeLinker();

        try (Arena libArena = Arena.ofConfined()) {
            SymbolLookup lookup = SymbolLookup.libraryLookup(Path.of(libraryPath), libArena);

            for (NativeFunction func : functions) {
                try {
                    FunctionDescriptor descriptor = buildDescriptor(func);
                    if (descriptor == null) continue; // skip variadic

                    var symbol = lookup.find(func.name());
                    if (symbol.isEmpty()) continue; // not exported in this build

                    MethodHandle handle = nativeLinker.downcallHandle(symbol.get(), descriptor);
                    bound.add(new BoundFunction(func, descriptor, handle));
                } catch (Exception e) {
                    // Skip functions that fail to bind (unusual layouts, etc)
                    System.err.println("  SKIP: " + func.name() + " — " + e.getMessage());
                }
            }
        }

        return bound;
    }


    // =========================================================================
    // TYPE DISPLAY HELPERS
    // =========================================================================

    public static String typeToString(CType type) {
        return switch (type) {
            case CType.Primitive p -> p.name();
            case CType.Pointer p -> typeToString(p.pointee()) + "*";
            case CType.Struct s -> "struct " + s.name();
            case CType.Union u -> "union " + u.name();
            case CType.Enum e -> "enum " + e.name();
            case CType.Typedef t -> t.name();
            case CType.Qualified q -> "const " + typeToString(q.underlying());
            case CType.Array a -> typeToString(a.elementType()) + "[" + a.count() + "]";
            case CType.Void ignored -> "void";
            case CType.Unresolved u -> "?" + u.reason();
        };
    }


    // =========================================================================
    // ACCESSORS
    // =========================================================================

    public List<NativeFunction> getFunctions() { return Collections.unmodifiableList(functions); }
    public Map<String, CType.Struct> getStructs() { return Collections.unmodifiableMap(structs); }


    // =========================================================================
    // CLEANUP
    // =========================================================================

    @Override
    public void close() {
        try {
            if (dwarfHandle != null && dwarfHandle.address() != 0) {
                dwarf_end_mh.invoke(dwarfHandle);
            }
            if (fd >= 0) {
                close_mh.invoke(fd);
            }
        } catch (Throwable t) {
            System.err.println("Cleanup error: " + t.getMessage());
        }
        arena.close();
    }


    // =========================================================================
    // MAIN — Demo: parse DWARF, display signatures, bind and invoke
    // =========================================================================

    public static void main(String[] args) throws Throwable {
        if (args.length < 1) {
            System.out.println("Usage: java --enable-native-access=ALL-UNNAMED DwarfFFMLoader <library.so>");
            System.out.println();
            System.out.println("Examples:");
            System.out.println("  DwarfFFMLoader /usr/lib/x86_64-linux-gnu/libm.so.6");
            System.out.println("  DwarfFFMLoader /usr/lib/x86_64-linux-gnu/libpcap.so.1");
            System.out.println("  DwarfFFMLoader /usr/lib/x86_64-linux-gnu/libz.so.1");
            System.out.println();
            System.out.println("Note: library must have DWARF debug info.");
            System.out.println("  Install debug symbols: sudo apt install <lib>-dbgsym");
            System.out.println("  Or compile with:       gcc -g -shared -o libfoo.so foo.c");
            return;
        }

        String libraryPath = args[0];

        System.out.println("╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║              DwarfFFMLoader — DWARF → FFM Bridge            ║");
        System.out.println("╚══════════════════════════════════════════════════════════════╝");
        System.out.println();

        // --- Phase 1: Parse DWARF debug info ---
        System.out.println("▶ PHASE 1: Parsing DWARF debug info from " + libraryPath);
        System.out.println();

        try (DwarfFFMLoader loader = new DwarfFFMLoader()) {
            loader.parseDwarf(libraryPath);

            List<NativeFunction> functions = loader.getFunctions();
            Map<String, CType.Struct> structs = loader.getStructs();

            System.out.printf("  Discovered %d functions, %d structs%n%n", functions.size(), structs.size());

            // --- Phase 2: Display discovered function signatures ---
            System.out.println("▶ PHASE 2: Discovered function signatures");
            System.out.println("─".repeat(70));

            int displayed = 0;
            for (NativeFunction func : functions) {
                System.out.println("  " + func);
                if (++displayed >= 40) {
                    System.out.printf("  ... and %d more functions%n", functions.size() - displayed);
                    break;
                }
            }
            System.out.println();

            // --- Phase 3: Display discovered structs ---
            if (!structs.isEmpty()) {
                System.out.println("▶ PHASE 3: Discovered struct layouts");
                System.out.println("─".repeat(70));

                int structCount = 0;
                for (var entry : structs.entrySet()) {
                    CType.Struct s = entry.getValue();
                    System.out.printf("  struct %s (%d bytes):%n", s.name(), s.byteSize());
                    for (StructField f : s.fields()) {
                        System.out.printf("    +%-4d %-20s %s%n", f.offset(),
                                typeToString(f.type()), f.name());
                    }
                    System.out.println();
                    if (++structCount >= 10) {
                        System.out.printf("  ... and %d more structs%n", structs.size() - structCount);
                        break;
                    }
                }
            }

            // --- Phase 4: Create FunctionDescriptors ---
            System.out.println("▶ PHASE 4: Generated FunctionDescriptors");
            System.out.println("─".repeat(70));

            int descCount = 0;
            for (NativeFunction func : functions) {
                FunctionDescriptor desc = buildDescriptor(func);
                if (desc != null) {
                    System.out.printf("  %-30s → %s%n", func.name(), desc);
                    if (++descCount >= 20) {
                        long total = functions.stream()
                                .filter(f -> buildDescriptor(f) != null).count();
                        System.out.printf("  ... %d total bindable functions%n", total);
                        break;
                    }
                }
            }
            System.out.println();

            // --- Phase 5: Bind and invoke ---
            System.out.println("▶ PHASE 5: Binding library and invoking functions");
            System.out.println("─".repeat(70));

            List<BoundFunction> bound = loader.bindLibrary(libraryPath);
            System.out.printf("  Successfully bound %d functions%n%n", bound.size());

            // Try invoking functions that take a single double and return double
            // (safe to call without side effects)
            for (BoundFunction bf : bound) {
                NativeFunction func = bf.function();
                if (func.params().size() == 1
                        && func.returnType() instanceof CType.Primitive ret
                        && ret.encoding() == CType.Encoding.FLOAT
                        && ret.byteSize() == 8
                        && func.params().getFirst().type() instanceof CType.Primitive param
                        && param.encoding() == CType.Encoding.FLOAT
                        && param.byteSize() == 8) {

                    try {
                        double result = (double) bf.handle().invoke(1.0);
                        System.out.printf("  %s(1.0) = %.15f%n", func.name(), result);
                    } catch (Throwable t) {
                        System.out.printf("  %s(1.0) → error: %s%n", func.name(), t.getMessage());
                    }
                }
            }
        }

        System.out.println();
        System.out.println("Done.");
    }
}
