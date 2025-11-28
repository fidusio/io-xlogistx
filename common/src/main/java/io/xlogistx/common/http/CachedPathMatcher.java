package io.xlogistx.common.http;


import org.zoxweb.server.io.IOUtil;
import org.zoxweb.shared.util.RegistrarMapDefault;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.NotDirectoryException;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

public class CachedPathMatcher {

    //private final Map<Path, Map<String, Path>> DIRECTORY_CACHE = new ConcurrentHashMap<>();

    private final RegistrarMapDefault<Path, Map<String, Path>> pathCache = new RegistrarMapDefault<>();
    /**
     * Resolve a filename inside a directory using case-insensitive matching,
     * with caching to avoid re-reading directory.
     */
    public Path resolveCaseInsensitive(Path directory, String name) throws IOException {
        if (!Files.isDirectory(directory)) {
            throw new NotDirectoryException(directory.toString());
        }

        Map<String, Path> cache = pathCache.lookup(directory);

        if (cache == null) {
            cache = loadDirectoryCache(directory);
            pathCache.register(directory, cache);
        }

        Path match = cache.get(name.toLowerCase());
        return (match != null) ? match : directory.resolve(name);
    }

    /**
     * Recursive version: resolves multi-part paths "A/B/C" case-insensitively.
     */
    public Path resolveCaseInsensitiveRecursive(Path base, String subpath, boolean fileOnly) throws IOException {
        Path current = base;

        for (String part : subpath.split("[/\\\\]+")) {
            if (part.isEmpty()) continue;

            // Directory must exist
            if (!Files.exists(current) || !Files.isDirectory(current)) {
                return null;  // base doesn't exist or no longer a directory
            }

            Map<String, Path> cache =  pathCache.lookup(current);
            if (cache == null) {
                cache = loadDirectoryCache(current);
                pathCache.register(current, cache);
            }

            Path next = cache.get(part.toLowerCase());
            if (next == null) {
                return null;  // NO MATCH found → return null
            }

            current = next;
        }

        return fileOnly ? IOUtil.regularFileOrNull(current) : current;
    }


    /**
     * Load a directory into the case-insensitive cache.
     */
    private synchronized Map<String, Path> loadDirectoryCache(Path dir) throws IOException {
        Map<String, Path> map = new HashMap<>();

        try (DirectoryStream<Path> stream = Files.newDirectoryStream(dir)) {
            for (Path entry : stream) {
                map.put(entry.getFileName().toString().toLowerCase(), entry);
            }
        }

        return map;
    }

    /**
     * Optional: clear cache externally if needed
     */
    public synchronized void clearCache() {
        pathCache.clear(true);
    }
}
