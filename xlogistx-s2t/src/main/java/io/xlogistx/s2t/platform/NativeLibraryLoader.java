package io.xlogistx.s2t.platform;

import io.xlogistx.s2t.S2TException;

import java.io.IOException;
import java.io.InputStream;
import java.lang.foreign.Arena;
import java.lang.foreign.SymbolLookup;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Gets a platform's native libraries from the JAR onto disk and into the process.
 * <p>
 * The operating system loader cannot read a library from inside a JAR - including a
 * JAR nested in another by jar-loader - so every file is first copied to a cache
 * directory. The directory name includes a fingerprint of the files' contents, so a
 * new build of the library never collides with an old copy that another running JVM
 * still has open.
 * <p>
 * Dependencies are loaded here; the speech library itself is only located, and its
 * path returned for the bindings to open.
 */
public final class NativeLibraryLoader {

    /**
     * Optional. A directory that already contains the platform's files; when set,
     * nothing is unpacked and the files are loaded from there. For development against
     * a freshly built library.
     */
    public static final String DIR_PROPERTY = "xlogistx.s2t.native.dir";

    /** Platform id to the located speech library. Loading happens once per JVM. */
    private static final Map<String, Path> LOADED = new HashMap<>();

    private NativeLibraryLoader() {
    }

    /**
     * Unpacks (unless {@link #DIR_PROPERTY} is set), loads every dependency in order,
     * and returns the absolute path of the speech library.
     *
     * @param cacheRoot where to unpack, for example {@code ~/.xlogistx/s2t/native}
     * @throws S2TException when a file is not packaged, cannot be written, or a
     *                      dependency cannot be loaded
     */
    public static synchronized Path load(NativePlatform platform, Path cacheRoot) throws S2TException {
        Path already = LOADED.get(platform.id());
        if (already != null) {
            return already;
        }

        Path dir = directoryFor(platform, cacheRoot);
        List<String> files = platform.libraryFiles();

        for (int i = 0; i < files.size() - 1; i++) {
            Path dependency = dir.resolve(files.get(i)).toAbsolutePath();
            requireFile(dependency, platform);
            try {
                // Global arena: the dependency must stay loaded for the life of the JVM.
                SymbolLookup.libraryLookup(dependency, Arena.global());
            } catch (IllegalArgumentException e) {
                throw new S2TException("Cannot load native dependency " + dependency
                        + " for " + platform.id() + ": " + e.getMessage(), e);
            }
        }

        Path main = dir.resolve(platform.mainLibrary()).toAbsolutePath();
        requireFile(main, platform);
        LOADED.put(platform.id(), main);
        return main;
    }

    private static Path directoryFor(NativePlatform platform, Path cacheRoot) throws S2TException {
        String override = System.getProperty(DIR_PROPERTY);
        if (override != null && !override.isBlank()) {
            Path dir = Path.of(override);
            if (!Files.isDirectory(dir)) {
                throw new S2TException(DIR_PROPERTY + " is not a directory: " + override);
            }
            return dir;
        }
        return unpack(platform, cacheRoot);
    }

    private static Path unpack(NativePlatform platform, Path cacheRoot) throws S2TException {
        Map<String, byte[]> contents = new LinkedHashMap<>();
        MessageDigest sha;
        try {
            sha = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new S2TException("SHA-256 is not available in this JVM", e);
        }

        for (String file : platform.libraryFiles()) {
            String resource = "/" + platform.resourceDir() + "/" + file;
            try (InputStream in = NativeLibraryLoader.class.getResourceAsStream(resource)) {
                if (in == null) {
                    throw new S2TException("Native library " + resource
                            + " is not packaged in this build of xlogistx-s2t");
                }
                byte[] bytes = in.readAllBytes();
                contents.put(file, bytes);
                sha.update(bytes);
            } catch (IOException e) {
                throw new S2TException("Cannot read packaged native library " + resource, e);
            }
        }

        String fingerprint = HexFormat.of().formatHex(sha.digest(), 0, 8);
        Path dir = cacheRoot.resolve(platform.id()).resolve(fingerprint).toAbsolutePath();
        try {
            Files.createDirectories(dir);
            for (Map.Entry<String, byte[]> entry : contents.entrySet()) {
                writeIfAbsent(dir.resolve(entry.getKey()), entry.getValue());
            }
        } catch (IOException e) {
            throw new S2TException("Cannot unpack native libraries into " + dir
                    + ": " + e.getMessage(), e);
        }
        return dir;
    }

    /**
     * Writes through a temporary file and an atomic move, so another JVM starting at
     * the same moment never sees a half-written library. An existing file of the right
     * size is left alone: the directory is named after the content, so it is the same
     * file.
     */
    private static void writeIfAbsent(Path target, byte[] bytes) throws IOException {
        if (sameSize(target, bytes.length)) {
            return;
        }
        Path tmp = Files.createTempFile(target.getParent(), target.getFileName().toString(), ".tmp");
        try {
            Files.write(tmp, bytes);
            Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) {
            // Another process may have won the race and now holds the file open.
            if (!sameSize(target, bytes.length)) {
                throw e;
            }
        } finally {
            Files.deleteIfExists(tmp);
        }
    }

    private static boolean sameSize(Path file, long size) throws IOException {
        return Files.isRegularFile(file) && Files.size(file) == size;
    }

    private static void requireFile(Path file, NativePlatform platform) throws S2TException {
        if (!Files.isRegularFile(file)) {
            throw new S2TException("Native library file is missing for " + platform.id() + ": " + file);
        }
    }
}
