package io.xlogistx.s2t.platform;

import java.util.List;

/**
 * Everything about the native speech library that differs between operating systems.
 * <p>
 * The library's C API is identical everywhere, so the bindings, the transcriber, audio
 * capture and the session are shared verbatim. Only two things are not portable, and
 * they are all an implementation answers: which directory inside the JAR holds this
 * platform's binaries, and which files to load, in what order.
 * <p>
 * To add a platform: build the native library for it (see {@code native/README.md}),
 * put the files under {@code src/main/resources/<resourceDir>/}, add a class beside
 * {@link io.xlogistx.s2t.platform.windows.WindowsX64Platform} in its own package, and
 * return it from {@link NativePlatforms#forOs}. Nothing else changes.
 */
public interface NativePlatform {

    /** Short stable name, for example {@code windows-x86_64}. Used in paths and messages. */
    String id();

    /** Classpath directory holding the binaries, without leading or trailing slash. */
    String resourceDir();

    /**
     * File names to load, dependencies first. The LAST entry is the speech library
     * itself, the one whose functions are bound.
     */
    List<String> libraryFiles();

    /** The speech library: the last entry of {@link #libraryFiles()}. */
    default String mainLibrary() {
        List<String> files = libraryFiles();
        return files.get(files.size() - 1);
    }
}
