package io.xlogistx.s2t.whisper;

import io.xlogistx.s2t.S2TException;
import io.xlogistx.s2t.platform.NativeLibraryLoader;
import io.xlogistx.s2t.platform.NativePlatform;
import io.xlogistx.s2t.platform.NativePlatforms;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.invoke.MethodHandle;
import java.nio.file.Path;

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_INT;

/**
 * FFM bindings for the {@code xs2t_*} functions exported by the native speech library.
 * <p>
 * These nine functions are a shim compiled into the library ({@code native/xs2t_shim.c})
 * in front of whisper.cpp. whisper.cpp's own API passes two large structs by value, and
 * both change between its releases; the shim takes only pointers, ints and C strings, so
 * nothing here describes a whisper struct and a whisper upgrade needs no Java change.
 * The identical binding works on every platform.
 * <p>
 * The library is loaded once per JVM. {@link #SUPPORTED_ABI} must equal the shim's
 * {@code XS2T_ABI_VERSION}; a library with another value is refused at load time
 * instead of misbehaving later.
 */
final class WhisperNative {

    /** The shim function set this class was written against. */
    static final int SUPPORTED_ABI = 1;

    /** Bits for the {@code flags} argument of {@link #transcribe}. Mirror {@code XS2T_FLAG_*}. */
    static final int FLAG_SINGLE_SEGMENT = 0x01;
    static final int FLAG_NO_CONTEXT = 0x02;
    static final int FLAG_TRANSLATE = 0x04;

    private static WhisperNative instance;

    private final Path libraryPath;
    private final MethodHandle hAbiVersion;
    private final MethodHandle hWhisperVersion;
    private final MethodHandle hSystemInfo;
    private final MethodHandle hSetLogEnabled;
    private final MethodHandle hOpen;
    private final MethodHandle hClose;
    private final MethodHandle hTranscribe;
    private final MethodHandle hSegmentCount;
    private final MethodHandle hSegmentText;

    private WhisperNative(Path libraryPath, Linker linker, SymbolLookup lookup) throws S2TException {
        this.libraryPath = libraryPath;
        hAbiVersion = bind(linker, lookup, "xs2t_abi_version",
                           FunctionDescriptor.of(JAVA_INT));
        hWhisperVersion = bind(linker, lookup, "xs2t_whisper_version",
                               FunctionDescriptor.of(ADDRESS));
        hSystemInfo = bind(linker, lookup, "xs2t_system_info",
                           FunctionDescriptor.of(ADDRESS));
        hSetLogEnabled = bind(linker, lookup, "xs2t_set_log_enabled",
                              FunctionDescriptor.ofVoid(JAVA_INT));
        hOpen = bind(linker, lookup, "xs2t_open",
                     FunctionDescriptor.of(ADDRESS, ADDRESS, JAVA_INT));
        hClose = bind(linker, lookup, "xs2t_close",
                      FunctionDescriptor.ofVoid(ADDRESS));
        hTranscribe = bind(linker, lookup, "xs2t_transcribe",
                           FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, JAVA_INT, JAVA_INT,
                                                 ADDRESS, ADDRESS, JAVA_INT));
        hSegmentCount = bind(linker, lookup, "xs2t_segment_count",
                             FunctionDescriptor.of(JAVA_INT, ADDRESS));
        hSegmentText = bind(linker, lookup, "xs2t_segment_text",
                            FunctionDescriptor.of(ADDRESS, ADDRESS, JAVA_INT));
    }

    /**
     * Returns the process-wide bindings, loading the library on first use.
     *
     * @param nativeCacheDir where the packaged library is unpacked on first use
     * @throws S2TException on an unsupported platform, an unloadable library, or a
     *                      library built from a different shim version
     */
    static synchronized WhisperNative get(Path nativeCacheDir) throws S2TException {
        if (instance == null) {
            NativePlatform platform = NativePlatforms.current();
            Path library = NativeLibraryLoader.load(platform, nativeCacheDir);

            SymbolLookup lookup;
            try {
                lookup = SymbolLookup.libraryLookup(library, Arena.global());
            } catch (IllegalArgumentException e) {
                throw new S2TException("Cannot load the speech library " + library + " for "
                        + platform.id() + ": " + e.getMessage(), e);
            }

            WhisperNative loaded = new WhisperNative(library, Linker.nativeLinker(), lookup);
            int abi = loaded.abiVersion();
            if (abi != SUPPORTED_ABI) {
                throw new S2TException("The speech library " + library + " reports shim version "
                        + abi + " but this build of xlogistx-s2t needs version " + SUPPORTED_ABI
                        + ". Rebuild the library and the module from the same sources.");
            }
            // Published only after every check passed.
            instance = loaded;
        }
        return instance;
    }

    private static MethodHandle bind(Linker linker, SymbolLookup lookup, String name,
                                     FunctionDescriptor descriptor) throws S2TException {
        MemorySegment symbol = lookup.find(name).orElse(null);
        if (symbol == null) {
            throw new S2TException("The speech library does not export " + name
                    + ". It was not built from native/xs2t_shim.c, or is an older build.");
        }
        return linker.downcallHandle(symbol, descriptor);
    }

    Path libraryPath() {
        return libraryPath;
    }

    int abiVersion() throws S2TException {
        try {
            return (int) hAbiVersion.invokeExact();
        } catch (Throwable t) {
            throw failure("xs2t_abi_version", t);
        }
    }

    /** The whisper.cpp release the library was built from, for example {@code 1.9.1}. */
    String whisperVersion() throws S2TException {
        try {
            return cString((MemorySegment) hWhisperVersion.invokeExact());
        } catch (Throwable t) {
            throw failure("xs2t_whisper_version", t);
        }
    }

    /** The CPU features the library uses. */
    String systemInfo() throws S2TException {
        try {
            return cString((MemorySegment) hSystemInfo.invokeExact());
        } catch (Throwable t) {
            throw failure("xs2t_system_info", t);
        }
    }

    void setLogEnabled(boolean enabled) throws S2TException {
        try {
            hSetLogEnabled.invokeExact(enabled ? 1 : 0);
        } catch (Throwable t) {
            throw failure("xs2t_set_log_enabled", t);
        }
    }

    /** @return the context pointer, or {@link MemorySegment#NULL} when the model did not load */
    MemorySegment open(MemorySegment modelPath, boolean useGpu) throws S2TException {
        try {
            return (MemorySegment) hOpen.invokeExact(modelPath, useGpu ? 1 : 0);
        } catch (Throwable t) {
            throw failure("xs2t_open", t);
        }
    }

    void close(MemorySegment context) throws S2TException {
        try {
            hClose.invokeExact(context);
        } catch (Throwable t) {
            throw failure("xs2t_close", t);
        }
    }

    /** @return 0 on success, otherwise the shim's or whisper's error code */
    int transcribe(MemorySegment context, MemorySegment samples, int sampleCount, int threads,
                   MemorySegment language, MemorySegment initialPrompt, int flags) throws S2TException {
        try {
            return (int) hTranscribe.invokeExact(context, samples, sampleCount, threads,
                                                 language, initialPrompt, flags);
        } catch (Throwable t) {
            throw failure("xs2t_transcribe", t);
        }
    }

    int segmentCount(MemorySegment context) throws S2TException {
        try {
            return (int) hSegmentCount.invokeExact(context);
        } catch (Throwable t) {
            throw failure("xs2t_segment_count", t);
        }
    }

    /** @return the segment's text, or {@code null} when the index is out of range */
    String segmentText(MemorySegment context, int index) throws S2TException {
        try {
            return cString((MemorySegment) hSegmentText.invokeExact(context, index));
        } catch (Throwable t) {
            throw failure("xs2t_segment_text", t);
        }
    }

    /** Copies a NUL-terminated UTF-8 string out of native memory; {@code null} for NULL. */
    private static String cString(MemorySegment pointer) {
        if (pointer == null || pointer.equals(MemorySegment.NULL)) {
            return null;
        }
        return pointer.reinterpret(Long.MAX_VALUE).getString(0);
    }

    /**
     * {@code invokeExact} is declared to throw {@code Throwable}. Errors and unchecked
     * exceptions are passed through untouched; anything else is a failed native call.
     */
    private static S2TException failure(String function, Throwable t) {
        if (t instanceof Error error) {
            throw error;
        }
        if (t instanceof RuntimeException runtime) {
            throw runtime;
        }
        return new S2TException("Native call " + function + " failed: " + t, t);
    }
}
