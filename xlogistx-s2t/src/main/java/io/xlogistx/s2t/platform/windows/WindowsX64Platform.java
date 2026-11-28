package io.xlogistx.s2t.platform.windows;

import io.xlogistx.s2t.platform.NativePlatform;

import java.util.List;

/**
 * Windows on 64-bit Intel/AMD.
 * <p>
 * Two files, built with CLion's bundled MinGW (see {@code native/README.md}):
 * <ol>
 *   <li>{@code libwinpthread-1.dll} - the MinGW thread runtime. It cannot be linked
 *       into the main DLL with that toolchain, so it ships beside it and must be
 *       loaded first: once it is in the process, Windows resolves the main DLL's
 *       import of it by name.</li>
 *   <li>{@code libwhisper.dll} - whisper.cpp, ggml, libstdc++ and libgcc in one file,
 *       exporting the {@code xs2t_*} functions the bindings use.</li>
 * </ol>
 * The build is portable: SSE4.2, AVX, AVX2, FMA, F16C and BMI2, no AVX-512. It needs
 * a CPU with AVX2.
 */
public final class WindowsX64Platform implements NativePlatform {

    public static final WindowsX64Platform INSTANCE = new WindowsX64Platform();

    private static final List<String> FILES = List.of("libwinpthread-1.dll", "libwhisper.dll");

    private WindowsX64Platform() {
    }

    @Override
    public String id() {
        return "windows-x86_64";
    }

    @Override
    public String resourceDir() {
        return "native/windows-x86_64";
    }

    @Override
    public List<String> libraryFiles() {
        return FILES;
    }

    @Override
    public String toString() {
        return id();
    }
}
