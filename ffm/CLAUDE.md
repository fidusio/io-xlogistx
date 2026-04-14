# Claude Code Instructions for the ffm module

## Purpose

Runtime, in-process alternative to `jextract`. Given a C header and/or a shared
library, discover native function signatures and struct layouts, then produce
invocable `java.lang.invoke.MethodHandle`s via the JDK 25 FFM API. Also serves
as general-purpose library introspection (list functions, structs, typedefs,
enums).

## Layout

```
ffm/
├── pom.xml                      Java 25, depends on xlogistx-core + xlogistx-common
└── src/main/java/io/xlogistx/ffm/
    ├── NativeBindingFactory.java   Unified entry point + canonical CType model
    ├── CPreprocessor.java          Pure-Java C preprocessor (replaces gcc -E)
    ├── CHeaderParser.java          Tokenizer + recursive-descent declaration parser
    ├── DwarfFFMLoader.java         libdw bindings + DWARF DIE walker
    └── FFMUtil.java                High-level facade + CLI (`main`)
```

No tests yet.

## Three discovery strategies

All three converge on the same `CType → FunctionDescriptor → MethodHandle` pipeline
and the same unified `CType` sealed hierarchy in `NativeBindingFactory`.

| Strategy | Inputs | External deps | Notes |
|---|---|---|---|
| `HEADER_PURE_JAVA` | `.h` + `.so` | none | Default for `FFMUtil`. Uses `CPreprocessor` + `CHeaderParser`. |
| `HEADER_GCC` | `.h` + `.so` | `gcc` on PATH | Same parser, but preprocessing via `gcc -E`. Use to sanity-check the pure path. |
| `DWARF` | `.so` only | `libdw.so.1` + debug symbols | Linux-only. Library must be built with `-g` or have a matching `-dbgsym`. |

## How to drive it

### CLI (FFMUtil.main)
```
FFMUtil lib=<path> [strategy=pure|gcc|dwarf] [header=<path>]
        [include=<p1,p2,...>] [define=N=V,N2=V2,...]
        [platform=linux-x86_64|linux-aarch64|macos-x86_64|macos-aarch64]
        [show=all|summary|functions|structs|typedefs|enums]
        [debug=true] [dump=<path>]
```

Strategy defaults: `pure` if `header=` given, else `dwarf`.

### Programmatic
Two interchangeable styles in `FFMUtil`:
1. Fluent: `FFMUtil.library(libPath).header(h).includePath(...).load()` → `Library` (AutoCloseable).
2. Static: `FFMUtil.loadHeader/loadHeaderGcc/loadDwarf(...)` → raw `NativeBindings`;
   `FFMUtil.describe(bindings)` → `LibraryCapabilities` record.

## Build / run

```bash
# Build
mvn -pl ffm -am compile

# Run main (FFMUtil)
java --enable-native-access=ALL-UNNAMED -cp <classpath> io.xlogistx.ffm.FFMUtil \
     lib=/usr/lib/aarch64-linux-gnu/libm.so.6 header=/usr/include/math.h \
     strategy=pure platform=linux-aarch64 show=summary
```

Note: `--enable-native-access=ALL-UNNAMED` is **required** on JDK 25 — the
surefire/compiler `<argLine>` for this is currently commented out in
`ffm/pom.xml`. Re-enable it before adding tests.

## Architectural rules

1. **Single canonical CType lives in `NativeBindingFactory`.** Each parser
   (`CHeaderParser`, `DwarfFFMLoader`) owns its own `CType` variant and is
   converted in `NativeBindingFactory.convertParserType` / `convertDwarfType`.
   Do not expose parser-specific types through the public API.

2. **`NativeBindings` owns a shared `Arena`.** Closing it invalidates every
   `MethodHandle` handed out. `FFMUtil.Library` is the thin AutoCloseable
   wrapper — prefer it over raw `NativeBindings` for anything that allocates.

3. **The fluent `Loader` is the public entry point.** Add new config knobs
   there (e.g. `.platform(...)`, `.define(...)`, `.useGcc()`). Do not export
   builder details from `NativeBindingFactory.HeaderBuilder` directly.

4. **Comments must be stripped before directive scanning.** `CPreprocessor`
   calls `stripComments(source)` in `processSource` — this is intentional
   (glibc's `cdefs.h` contains `#define __has_attribute(foo) 0` *inside* an
   explanatory comment; without pre-stripping, line-by-line directive matching
   misinterprets it as a real directive and corrupts the macro table).

## Known limitations / gotchas

- **Platform sizing is hardcoded for LP64 little-endian.** Default platform is
  `LINUX_X86_64`. On aarch64 you MUST pass `platform=linux-aarch64` — otherwise
  `CPreprocessor.registerStandardPaths` seeds the wrong `/usr/include/<triple>`
  and all sub-headers are silently skipped, producing 0 functions.

- **No Windows platform.** `CPreprocessor.Platform` has no `WINDOWS_*` variant
  and no MSVC-style system include seeding. The parser also assumes LP64
  (`long = 8`), which is wrong for Windows LLP64 (`long = 4`).

- **Missing headers are silently skipped.** `CPreprocessor.processFile` returns
  quietly if the path doesn't exist. Good for tolerating optional system
  headers; bad if you typo'd the main header. Use `debug=true` in `FFMUtil`
  to print preprocessed length and token count — tokens=1 means preprocessor
  produced nothing parseable.

- **`NativeBindings` constructor swallows per-function bind errors.** A
  mis-sized struct parameter silently drops that function from the bind. If a
  function you expect to be bound is missing, temporarily instrument
  `NativeBindingFactory.NativeBindings` line ~128 to log the exception.

- **Variadic functions are never bound.** FFM requires a specialized handle
  per call site for variadic calls, so `bindings.getBoundFunctionNames()`
  excludes them even when the symbol is exported. They still appear in
  `getAllFunctions()`.

- **Enums only surface via typedefs.** `NativeBindings` exposes `getTypedefs()`
  but not a standalone enum map; anonymous `enum { ... }` blocks are parsed
  into `CHeaderParser.Parser.enums` but not converted. Extend
  `NativeBindingFactory.convertTypedefs` / add a new converter if you need
  standalone enums in `LibraryCapabilities.enums()`.

- **DWARF struct layouts are baked in.** `DwarfFFMLoader` hardcodes
  `Dwarf_Die` (32 B) and `Dwarf_Attribute` (24 B) layouts matching libdw's
  64-bit ABI. If libdw's struct sizes change in a future elfutils release,
  these must be updated.

- **DWARF path uses `Arena.ofConfined()`.** Cannot be driven from multiple
  threads. The header paths use `Arena.ofShared()`.

## ParamUtil semantics (easy to get wrong)

`org.zoxweb.shared.util.ParamUtil.ParamMap.stringValue(key, boolean optional)`
— the boolean is **optional**, not "required":

- `stringValue(key, true)`  → optional; returns `null` if missing.
- `stringValue(key, false)` → required; throws `IllegalArgumentException`.

Always pass `true` for optional CLI params. Don't wrap in try/catch to simulate
optionality.

## When adding features

- **New discovery strategy?** Add a `Strategy` enum value, a builder in
  `NativeBindingFactory`, a converter to the canonical `CType`, and a
  `FFMUtil.loadXxx` + `Loader.xxx()` shortcut. Do not add new user-visible
  CType variants unless all three existing parsers can emit them.

- **New preprocessor knob?** Add to `CPreprocessor` and expose via
  `NativeBindingFactory.HeaderBuilder` AND `FFMUtil.Loader` AND `FFMUtil`
  CLI flags — keep the three surfaces in sync.

- **New capability listing?** Extend `LibraryCapabilities` record + its
  `prettyReport()` + `FFMUtil.Library.xxxReport()` shortcut + CLI `show=`
  switch.

## Debugging checklist when you get 0 functions

1. Run with `debug=true` → check preprocessed length and token count.
2. If `length` is big but `tokens` tiny → likely a tokenizer hit an
   unterminated `/*`. Count `/*` vs `*/` in the dumped output.
3. If counts match but tokens still tiny → the tokenizer is choking on a
   literal; try `strategy=gcc` to isolate.
4. If gcc path also fails → headers aren't resolving; add explicit
   `include=` paths for your distro (Debian aarch64:
   `/usr/include,/usr/include/aarch64-linux-gnu`).
5. Confirm `platform=` matches your arch. Default is `linux-x86_64`.
