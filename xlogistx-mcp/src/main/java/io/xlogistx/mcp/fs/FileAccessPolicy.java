package io.xlogistx.mcp.fs;

import java.io.IOException;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * Confines every file operation to a fixed set of root folders.
 * <p>
 * Rules:
 * <ul>
 *   <li>Roots are resolved to their real paths once, at construction.</li>
 *   <li>A relative path is resolved against the first root.</li>
 *   <li>An existing target is checked by its <em>real</em> path, so a symbolic link or junction
 *   that points outside the roots is refused.</li>
 *   <li>A target that does not exist yet (write, create) is checked through the real path of its
 *   nearest existing ancestor, so {@code ..} and links in the parent chain cannot escape.</li>
 *   <li>Containment uses {@link Path#startsWith(Path)}, which compares whole name elements:
 *   root {@code /data} does not admit {@code /data2}.</li>
 *   <li>In read-only mode every write resolution is refused.</li>
 * </ul>
 */
public final class FileAccessPolicy {

    private final List<Path> roots;
    private final boolean readOnly;

    public FileAccessPolicy(Collection<String> rootPaths, boolean readOnly) throws IOException {
        if (rootPaths == null || rootPaths.isEmpty())
            throw new IllegalArgumentException("At least one root folder is required");
        List<Path> list = new ArrayList<>();
        for (String r : rootPaths) {
            String t = r == null ? null : r.trim();
            if (t == null || t.isEmpty())
                continue;
            Path p = Paths.get(t).toAbsolutePath().normalize();
            if (!Files.isDirectory(p))
                throw new IllegalArgumentException("Root is not an existing directory: " + p);
            Path real = p.toRealPath();
            if (!list.contains(real))
                list.add(real);
        }
        if (list.isEmpty())
            throw new IllegalArgumentException("At least one root folder is required");
        this.roots = Collections.unmodifiableList(list);
        this.readOnly = readOnly;
    }

    public List<Path> getRoots() {
        return roots;
    }

    public boolean isReadOnly() {
        return readOnly;
    }

    /** Resolve a path that must already exist, following links, and check it is inside a root. */
    public Path resolveExisting(String input) throws IOException {
        Path abs = toAbsolute(input);
        if (!Files.exists(abs, LinkOption.NOFOLLOW_LINKS))
            throw new NoSuchFileException(abs.toString());
        Path real = abs.toRealPath();
        requireInside(real, input);
        return real;
    }

    /** Resolve a path to create or overwrite; it may not exist yet. */
    public Path resolveForWrite(String input) throws IOException {
        if (readOnly)
            throw new AccessDeniedException(input, null, "the server is read-only");
        Path abs = toAbsolute(input);

        Path existing = abs;
        while (existing != null && !Files.exists(existing, LinkOption.NOFOLLOW_LINKS))
            existing = existing.getParent();
        if (existing == null)
            throw new AccessDeniedException(input, null, "outside the allowed roots");

        Path target = existing.toRealPath().resolve(existing.relativize(abs)).normalize();
        requireInside(target, input);
        if (roots.contains(target))
            throw new AccessDeniedException(input, null, "a root folder itself cannot be replaced");
        return target;
    }

    public boolean isInside(Path real) {
        for (Path r : roots) {
            if (real.startsWith(r))
                return true;
        }
        return false;
    }

    private void requireInside(Path real, String input) throws AccessDeniedException {
        if (!isInside(real))
            throw new AccessDeniedException(input, null, "outside the allowed roots");
    }

    private Path toAbsolute(String input) {
        if (input == null || input.trim().isEmpty())
            throw new IllegalArgumentException("path is required");
        if (input.indexOf('\0') >= 0)
            throw new IllegalArgumentException("path contains a NUL character");
        Path p;
        try {
            p = Paths.get(input.trim());
        } catch (InvalidPathException e) {
            throw new IllegalArgumentException("Invalid path: " + e.getMessage());
        }
        if (!p.isAbsolute())
            p = roots.get(0).resolve(p);
        return p.toAbsolutePath().normalize();
    }
}
