# Native library for xlogistx-s2t

This folder holds the SOURCE of the native speech library. Maven does not compile it.
The compiled result is checked in under
`../src/main/resources/native/<platform>/` and packaged into the JAR.

| File | What it is |
|---|---|
| `xs2t_shim.c` | The nine C functions Java binds (`xs2t_*`). See the comment at its top. |
| `CMakeLists.txt` | Builds whisper.cpp + ggml + the shim into one standalone library. |

whisper.cpp itself is not copied here. The build expects a clone of it in a
`whisper.cpp` subfolder next to `CMakeLists.txt`.

## Current binary

| | |
|---|---|
| Platform | Windows x86-64 |
| whisper.cpp | tag `v1.9.1` |
| Toolchain | CLion bundled MinGW (GCC 15.2.0), CMake, Ninja |
| CPU target | portable: SSE4.2, AVX, AVX2, FMA, F16C, BMI2 (no AVX-512) |
| Shim ABI | 1 |
| Files | `libwinpthread-1.dll` (72 KB), `libwhisper.dll` (5.4 MB) |
| Built | 2026-11-24, in `D:\dev\data\vscode\Whisper` |

## Rebuild on Windows with CLion's bundled tools

No Visual Studio needed. In PowerShell, from a working folder that contains this
`CMakeLists.txt` and `xs2t_shim.c` (the CLion project `D:\dev\data\vscode\Whisper` is
set up this way):

```powershell
# once
git clone --depth 1 --branch v1.9.1 https://github.com/ggml-org/whisper.cpp.git

# every build ($c = your CLion install's bin folder)
$c = 'D:\Programs\JetBrains\CLion\bin'
$env:PATH = "$c\mingw\bin;$c\ninja\win\x64;$c\cmake\win\x64\bin;$env:PATH"

cmake -S . -B cmake-build-release -G Ninja -DCMAKE_BUILD_TYPE=Release `
      "-DCMAKE_C_COMPILER=$c\mingw\bin\gcc.exe" `
      "-DCMAKE_CXX_COMPILER=$c\mingw\bin\g++.exe" `
      "-DCMAKE_MAKE_PROGRAM=$c\ninja\win\x64\ninja.exe"

cmake --build cmake-build-release --target whisper_standalone
```

Result: `cmake-build-release\bin\libwhisper.dll`. Then copy two files into the module:

```powershell
$dest = 'D:\dev\data\java\projects\io-xlogistx\xlogistx-s2t\src\main\resources\native\windows-x86_64'
Copy-Item cmake-build-release\bin\libwhisper.dll $dest -Force
Copy-Item "$c\mingw\bin\libwinpthread-1.dll"      $dest -Force
```

and run the live test:

```powershell
mvn -pl xlogistx-s2t test -DskipTests=false "-Ds2t.model=D:/dev/data/vscode/Whisper/models/ggml-base.en.bin"
```

## Build options

| Option | Default | Meaning |
|---|---|---|
| `-DWHISPER_STANDALONE_NATIVE=OFF` | OFF | Portable build with the instruction sets pinned in `CMakeLists.txt`. |
| `-DWHISPER_STANDALONE_NATIVE=ON` | | Tuned to the build machine's CPU. Faster there, crashes on a CPU lacking any feature it used (the first build here used AVX-512). Never ship this. |

## Checks after a build

```powershell
# what the DLL needs at run time: only Windows DLLs and libwinpthread-1.dll
& "$c\mingw\bin\objdump.exe" -p cmake-build-release\bin\libwhisper.dll | findstr "DLL Name"

# the shim functions are exported
& "$c\mingw\bin\objdump.exe" -p cmake-build-release\bin\libwhisper.dll | findstr xs2t_
```

Expected imports: `ADVAPI32.dll`, `KERNEL32.dll`, `msvcrt.dll`, `libwinpthread-1.dll`.

## Why two files and not one

CLion's bundled MinGW builds winpthread against the UCRT while libstdc++, libgcc and
the default C runtime are msvcrt. Linking winpthread statically (`-static`) fails with
`undefined reference to __intrinsic_setjmpex`. The DLL form of winpthread is the
combination that toolchain itself uses, so `libwinpthread-1.dll` ships beside
`libwhisper.dll` and Java loads it first. A toolchain that is UCRT throughout
(for example MSYS2 UCRT64) could produce a single file.

## Changing the shim

1. Edit `xs2t_shim.c`. If a function's signature or meaning changes, bump
   `XS2T_ABI_VERSION`.
2. Mirror the change in `io.xlogistx.s2t.whisper.WhisperNative` and set
   `SUPPORTED_ABI` to the same number.
3. Rebuild, copy, run the live test.

Keep this folder and the CLion project's copies of `xs2t_shim.c` and `CMakeLists.txt`
identical.

## Other platforms

`xs2t_shim.c` and `CMakeLists.txt` are portable C and CMake. For Linux or macOS the
same `cmake` commands with the platform's own compiler produce `libwhisper.so` or
`libwhisper.dylib`; the `if (MINGW)` block is skipped. Build Linux on the oldest
distribution to be supported (glibc sets the floor). Then follow "To add macOS or
Linux" in `../CLAUDE.md`.

## Licenses

whisper.cpp and ggml are MIT. `libwinpthread-1.dll` is part of mingw-w64
(winpthreads). The statically linked libstdc++ and libgcc are GPL with the GCC
Runtime Library Exception. Review these before shipping in a commercial product.
