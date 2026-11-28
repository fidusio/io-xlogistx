package io.xlogistx.mcp.fs;

import io.xlogistx.mcp.MCPTool;
import io.xlogistx.mcp.SchemaBuilder;
import io.xlogistx.mcp.ToolArgs;
import org.zoxweb.shared.util.NVGenericMap;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.*;
import java.util.regex.Pattern;

/**
 * File system tools, all confined by a {@link FileAccessPolicy}.
 * <p>
 * Read tools: {@code list_allowed_roots}, {@code get_file_info}, {@code read_file},
 * {@code list_directory}, {@code search_files}, {@code search_text}.
 * Write tools (left out when the policy is read-only): {@code write_file}, {@code edit_file},
 * {@code create_directory}. There is no delete or move tool yet.
 * <p>
 * Walks never follow symbolic links, and {@code search_text} skips link files, so a link inside
 * a root cannot be used to read outside it.
 */
public final class FileSystemTools {

    private FileSystemTools() {
    }

    /** Size and count limits; the endpoint fills them from its configuration. */
    public static final class Limits {
        /** Most characters read_file returns in one call. */
        public int maxReadChars = 1024 * 1024;
        /** Most entries returned by list_directory, search_files and search_text. */
        public int maxResults = 500;
        /** Files larger than this are skipped by search_text. */
        public long maxSearchFileBytes = 4L * 1024 * 1024;
        /** Largest file write_file and edit_file will write. */
        public int maxWriteBytes = 4 * 1024 * 1024;
        /** Deepest list_directory may go. */
        public int maxListDepth = 8;
        /** Deepest search_files and search_text may go. */
        public int maxSearchDepth = 32;
    }

    /** Directories the walks do not descend into (they are still listed). */
    static final Set<String> SKIP_DIRS = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(".git", "node_modules")));
    static final int MAX_MATCH_LINE_CHARS = 300;
    private static final int BINARY_PROBE_BYTES = 8192;

    public static List<MCPTool> create(FileAccessPolicy policy, Limits limits) {
        List<MCPTool> list = new ArrayList<>();
        list.add(new ListAllowedRoots(policy, limits));
        list.add(new GetFileInfo(policy, limits));
        list.add(new ReadFile(policy, limits));
        list.add(new ListDirectory(policy, limits));
        list.add(new SearchFiles(policy, limits));
        list.add(new SearchText(policy, limits));
        if (!policy.isReadOnly()) {
            list.add(new WriteFile(policy, limits));
            list.add(new EditFile(policy, limits));
            list.add(new CreateDirectory(policy, limits));
        }
        return list;
    }

    // ---------------------------------------------------------------- base

    abstract static class FSTool implements MCPTool {
        final FileAccessPolicy policy;
        final Limits limits;
        private final String name;
        private final String description;
        private final boolean readOnly;

        FSTool(FileAccessPolicy policy, Limits limits, String name, String description, boolean readOnly) {
            this.policy = policy;
            this.limits = limits;
            this.name = name;
            this.description = description;
            this.readOnly = readOnly;
        }

        @Override
        public String getName() {
            return name;
        }

        @Override
        public String getDescription() {
            return description;
        }

        @Override
        public boolean isReadOnly() {
            return readOnly;
        }

        /**
         * True when a directory met during a walk resolves outside the roots. Walks do not follow
         * symbolic links, but on Windows a directory junction reports as a plain directory, so
         * every directory below the start is checked by its real path before it is entered.
         */
        boolean escapes(Path dir) {
            try {
                return !policy.isInside(dir.toRealPath());
            } catch (IOException e) {
                return true;
            }
        }
    }

    // ---------------------------------------------------------------- read tools

    static final class ListAllowedRoots extends FSTool {
        ListAllowedRoots(FileAccessPolicy policy, Limits limits) {
            super(policy, limits, "list_allowed_roots",
                    "List the root folders this server may access. Every path given to the other tools must be inside one "
                            + "of them; a relative path is resolved against the first root. Call this first.",
                    true);
        }

        @Override
        public NVGenericMap inputSchema() {
            return SchemaBuilder.object().build();
        }

        @Override
        public String call(NVGenericMap arguments) {
            StringBuilder sb = new StringBuilder();
            sb.append("Allowed roots (").append(policy.isReadOnly() ? "read-only" : "read-write").append("):\n");
            for (Path root : policy.getRoots())
                sb.append(root).append('\n');
            return sb.toString();
        }
    }

    static final class GetFileInfo extends FSTool {
        GetFileInfo(FileAccessPolicy policy, Limits limits) {
            super(policy, limits, "get_file_info",
                    "Get metadata for a file or directory: type, size in bytes, modified and created times, and whether it "
                            + "is readable and writable.",
                    true);
        }

        @Override
        public NVGenericMap inputSchema() {
            return SchemaBuilder.object()
                    .string("path", "File or directory path", true)
                    .build();
        }

        @Override
        public String call(NVGenericMap arguments) throws IOException {
            Path p = policy.resolveExisting(ToolArgs.requiredNonBlank(arguments, "path"));
            BasicFileAttributes a = Files.readAttributes(p, BasicFileAttributes.class);
            String type = a.isDirectory() ? "directory" : a.isRegularFile() ? "file" : "other";
            return "path: " + p + '\n'
                    + "type: " + type + '\n'
                    + "size: " + a.size() + " bytes\n"
                    + "modified: " + a.lastModifiedTime().toInstant() + '\n'
                    + "created: " + a.creationTime().toInstant() + '\n'
                    + "readable: " + Files.isReadable(p) + '\n'
                    + "writable: " + (!policy.isReadOnly() && Files.isWritable(p)) + '\n';
        }
    }

    static final class ReadFile extends FSTool {
        ReadFile(FileAccessPolicy policy, Limits limits) {
            super(policy, limits, "read_file",
                    "Read a UTF-8 text file. Returns the file's text exactly, without line numbers. For a long file, read it "
                            + "in parts with offset (first line, 1-based) and limit (number of lines); a note at the end says "
                            + "where to continue. Binary files are refused.",
                    true);
        }

        @Override
        public NVGenericMap inputSchema() {
            return SchemaBuilder.object()
                    .string("path", "File path", true)
                    .integer("offset", "First line to return, 1-based (default 1)", false, 1, Integer.MAX_VALUE)
                    .integer("limit", "Most lines to return (default 2000)", false, 1, 1_000_000)
                    .build();
        }

        @Override
        public String call(NVGenericMap arguments) throws IOException {
            Path p = policy.resolveExisting(ToolArgs.requiredNonBlank(arguments, "path"));
            int offset = ToolArgs.optionalInt(arguments, "offset", 1, 1, Integer.MAX_VALUE);
            int limit = ToolArgs.optionalInt(arguments, "limit", 2000, 1, 1_000_000);

            if (Files.isDirectory(p))
                throw new IllegalArgumentException("Is a directory, use list_directory: " + p);
            if (isBinary(p))
                throw new IllegalArgumentException("Binary file (" + Files.size(p) + " bytes), not shown: " + p);

            StringBuilder sb = new StringBuilder();
            int lineNo = 0;
            int first = -1;
            int last = -1;
            boolean more = false;
            try (BufferedReader r = reader(p)) {
                String line;
                while ((line = r.readLine()) != null) {
                    lineNo++;
                    if (lineNo < offset)
                        continue;
                    if (last - first + 1 >= limit && first > 0) {
                        more = true;
                        break;
                    }
                    if (sb.length() + line.length() + 1 > limits.maxReadChars && first > 0) {
                        more = true;
                        break;
                    }
                    if (first < 0)
                        first = lineNo;
                    last = lineNo;
                    if (line.length() > limits.maxReadChars) {
                        // a single huge line (minified file): return its start only
                        sb.append(line, 0, limits.maxReadChars).append(" ...[line truncated]\n");
                        more = true;
                        break;
                    }
                    sb.append(line).append('\n');
                }
            }

            if (lineNo == 0)
                return "[empty file]";
            if (first < 0)
                return "[the file has " + lineNo + " lines; offset " + offset + " is past the end]";
            if (more)
                sb.append("\n[showing lines ").append(first).append('-').append(last)
                        .append("; more follows, continue with offset=").append(last + 1).append("]\n");
            else if (first > 1)
                sb.append("\n[showing lines ").append(first).append('-').append(last).append(", the end of the file]\n");
            return sb.toString();
        }
    }

    static final class ListDirectory extends FSTool {
        ListDirectory(FileAccessPolicy policy, Limits limits) {
            super(policy, limits, "list_directory",
                    "List a directory's entries, marked [DIR], [FILE] (with size in bytes) or [LINK]. depth 1 lists only the "
                            + "directory itself; a larger depth also lists subfolders. .git and node_modules are listed but "
                            + "not entered.",
                    true);
        }

        @Override
        public NVGenericMap inputSchema() {
            return SchemaBuilder.object()
                    .string("path", "Directory path", true)
                    .integer("depth", "How many levels to list (default 1)", false, 1, limits.maxListDepth)
                    .build();
        }

        @Override
        public String call(NVGenericMap arguments) throws IOException {
            final Path dir = policy.resolveExisting(ToolArgs.requiredNonBlank(arguments, "path"));
            int depth = ToolArgs.optionalInt(arguments, "depth", 1, 1, limits.maxListDepth);
            if (!Files.isDirectory(dir))
                throw new NotDirectoryException(dir.toString());

            final List<String> entries = new ArrayList<>();
            final boolean[] truncated = {false};
            Files.walkFileTree(dir, EnumSet.noneOf(FileVisitOption.class), depth, new SimpleFileVisitor<Path>() {
                @Override
                public FileVisitResult preVisitDirectory(Path d, BasicFileAttributes attrs) {
                    if (d.equals(dir))
                        return FileVisitResult.CONTINUE;
                    if (escapes(d))
                        return add("[LINK] " + rel(dir, d) + "/  (points outside the allowed roots, not entered)")
                                ? FileVisitResult.SKIP_SUBTREE : FileVisitResult.TERMINATE;
                    if (!add("[DIR]  " + rel(dir, d) + "/"))
                        return FileVisitResult.TERMINATE;
                    return SKIP_DIRS.contains(String.valueOf(d.getFileName())) ? FileVisitResult.SKIP_SUBTREE : FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFile(Path f, BasicFileAttributes attrs) {
                    String entry;
                    if (attrs.isDirectory())   // directories at the depth limit arrive here
                        entry = "[DIR]  " + rel(dir, f) + "/";
                    else if (attrs.isSymbolicLink())
                        entry = "[LINK] " + rel(dir, f);
                    else
                        entry = "[FILE] " + rel(dir, f) + "  (" + attrs.size() + " bytes)";
                    return add(entry) ? FileVisitResult.CONTINUE : FileVisitResult.TERMINATE;
                }

                @Override
                public FileVisitResult visitFileFailed(Path f, IOException e) {
                    return add("[?]    " + rel(dir, f) + "  (" + e.getClass().getSimpleName() + ")")
                            ? FileVisitResult.CONTINUE : FileVisitResult.TERMINATE;
                }

                private boolean add(String entry) {
                    if (entries.size() >= limits.maxResults) {
                        truncated[0] = true;
                        return false;
                    }
                    entries.add(entry);
                    return true;
                }
            });

            Collections.sort(entries, new Comparator<String>() {
                @Override
                public int compare(String a, String b) {
                    return a.substring(7).compareToIgnoreCase(b.substring(7));
                }
            });
            StringBuilder sb = new StringBuilder();
            sb.append("Directory: ").append(dir).append('\n');
            if (entries.isEmpty())
                sb.append("[empty]\n");
            for (String e : entries)
                sb.append(e).append('\n');
            if (truncated[0])
                sb.append("[stopped at ").append(limits.maxResults).append(" entries; list a subfolder or use a smaller depth]\n");
            return sb.toString();
        }
    }

    static final class SearchFiles extends FSTool {
        SearchFiles(FileAccessPolicy policy, Limits limits) {
            super(policy, limits, "search_files",
                    "Find files and folders under a directory by glob pattern. A pattern without a slash matches the file "
                            + "name at any depth (*.java, pom.xml); a pattern with a slash matches the path relative to the "
                            + "directory (src/**/*Test.java). .git and node_modules are not entered.",
                    true);
        }

        @Override
        public NVGenericMap inputSchema() {
            return SchemaBuilder.object()
                    .string("path", "Directory to search under", true)
                    .string("pattern", "Glob pattern, e.g. *.java or src/**/*.json", true)
                    .integer("max_results", "Most results to return (default " + limits.maxResults + ")", false, 1, limits.maxResults)
                    .build();
        }

        @Override
        public String call(NVGenericMap arguments) throws IOException {
            final Path dir = policy.resolveExisting(ToolArgs.requiredNonBlank(arguments, "path"));
            String pattern = ToolArgs.requiredNonBlank(arguments, "pattern").trim();
            final int max = ToolArgs.optionalInt(arguments, "max_results", limits.maxResults, 1, limits.maxResults);
            if (!Files.isDirectory(dir))
                throw new NotDirectoryException(dir.toString());

            final PathMatcher matcher = dir.getFileSystem().getPathMatcher("glob:" + pattern);
            final boolean nameOnly = pattern.indexOf('/') < 0 && pattern.indexOf('\\') < 0;
            final List<String> found = new ArrayList<>();
            final boolean[] truncated = {false};

            Files.walkFileTree(dir, EnumSet.noneOf(FileVisitOption.class), limits.maxSearchDepth, new SimpleFileVisitor<Path>() {
                @Override
                public FileVisitResult preVisitDirectory(Path d, BasicFileAttributes attrs) {
                    if (d.equals(dir))
                        return FileVisitResult.CONTINUE;
                    if (escapes(d))
                        return FileVisitResult.SKIP_SUBTREE;
                    if (matches(d) && !add(rel(dir, d) + "/"))
                        return FileVisitResult.TERMINATE;
                    return SKIP_DIRS.contains(String.valueOf(d.getFileName())) ? FileVisitResult.SKIP_SUBTREE : FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFile(Path f, BasicFileAttributes attrs) {
                    if (matches(f) && !add(rel(dir, f) + (attrs.isDirectory() ? "/" : "")))
                        return FileVisitResult.TERMINATE;
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFileFailed(Path f, IOException e) {
                    return FileVisitResult.CONTINUE;
                }

                private boolean matches(Path p) {
                    Path target = nameOnly ? p.getFileName() : dir.relativize(p);
                    return target != null && matcher.matches(target);
                }

                private boolean add(String s) {
                    if (found.size() >= max) {
                        truncated[0] = true;
                        return false;
                    }
                    found.add(s);
                    return true;
                }
            });

            Collections.sort(found, String.CASE_INSENSITIVE_ORDER);
            StringBuilder sb = new StringBuilder();
            sb.append(found.size()).append(found.size() == 1 ? " match" : " matches").append(" under ").append(dir).append('\n');
            for (String s : found)
                sb.append(s).append('\n');
            if (truncated[0])
                sb.append("[stopped at ").append(max).append(" results; narrow the pattern or the directory]\n");
            return sb.toString();
        }
    }

    static final class SearchText extends FSTool {
        SearchText(FileAccessPolicy policy, Limits limits) {
            super(policy, limits, "search_text",
                    "Search file contents for text or a regular expression, under a directory or in one file. Returns "
                            + "path:line: text for each matching line. Case-insensitive unless case_sensitive is true. "
                            + "Binary files, links and files over the size limit are skipped.",
                    true);
        }

        @Override
        public NVGenericMap inputSchema() {
            return SchemaBuilder.object()
                    .string("path", "Directory or file to search", true)
                    .string("query", "Text to find, or a Java regular expression when regex is true", true)
                    .bool("regex", "Treat query as a regular expression (default false)")
                    .bool("case_sensitive", "Match case exactly (default false)")
                    .string("file_pattern", "Only search files whose name matches this glob, e.g. *.java", false)
                    .integer("max_results", "Most matching lines to return (default " + limits.maxResults + ")", false, 1, limits.maxResults)
                    .build();
        }

        @Override
        public String call(NVGenericMap arguments) throws IOException {
            final Path start = policy.resolveExisting(ToolArgs.requiredNonBlank(arguments, "path"));
            String query = ToolArgs.requiredString(arguments, "query");
            if (query.isEmpty())
                throw new IllegalArgumentException("Argument must not be empty: query");
            boolean regex = ToolArgs.optionalBoolean(arguments, "regex", false);
            boolean caseSensitive = ToolArgs.optionalBoolean(arguments, "case_sensitive", false);
            String filePattern = ToolArgs.optionalString(arguments, "file_pattern", null);
            final int max = ToolArgs.optionalInt(arguments, "max_results", limits.maxResults, 1, limits.maxResults);

            int flags = caseSensitive ? 0 : Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE;
            final Pattern pattern = Pattern.compile(regex ? query : Pattern.quote(query), flags);
            final PathMatcher fileMatcher = filePattern == null || filePattern.trim().isEmpty()
                    ? null
                    : start.getFileSystem().getPathMatcher("glob:" + filePattern.trim());

            final Path base = Files.isDirectory(start) ? start : start.getParent();
            final List<String> hits = new ArrayList<>();
            final int[] skippedLarge = {0};
            final boolean[] truncated = {false};

            Files.walkFileTree(start, EnumSet.noneOf(FileVisitOption.class), limits.maxSearchDepth, new SimpleFileVisitor<Path>() {
                @Override
                public FileVisitResult preVisitDirectory(Path d, BasicFileAttributes attrs) {
                    if (!d.equals(start) && (SKIP_DIRS.contains(String.valueOf(d.getFileName())) || escapes(d)))
                        return FileVisitResult.SKIP_SUBTREE;
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFile(Path f, BasicFileAttributes attrs) {
                    if (!attrs.isRegularFile() || attrs.isSymbolicLink())
                        return FileVisitResult.CONTINUE;
                    if (fileMatcher != null && !fileMatcher.matches(f.getFileName()))
                        return FileVisitResult.CONTINUE;
                    if (attrs.size() > limits.maxSearchFileBytes) {
                        skippedLarge[0]++;
                        return FileVisitResult.CONTINUE;
                    }
                    try {
                        if (isBinary(f))
                            return FileVisitResult.CONTINUE;
                        try (BufferedReader r = reader(f)) {
                            String line;
                            int lineNo = 0;
                            while ((line = r.readLine()) != null) {
                                lineNo++;
                                if (pattern.matcher(line).find()) {
                                    if (hits.size() >= max) {
                                        truncated[0] = true;
                                        return FileVisitResult.TERMINATE;
                                    }
                                    String text = line.length() > MAX_MATCH_LINE_CHARS
                                            ? line.substring(0, MAX_MATCH_LINE_CHARS) + "..."
                                            : line;
                                    hits.add(rel(base, f) + ":" + lineNo + ": " + text.trim());
                                }
                            }
                        }
                    } catch (IOException e) {
                        // unreadable file: skip it
                    }
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFileFailed(Path f, IOException e) {
                    return FileVisitResult.CONTINUE;
                }
            });

            StringBuilder sb = new StringBuilder();
            sb.append(hits.size()).append(hits.size() == 1 ? " matching line" : " matching lines").append(" under ").append(base).append('\n');
            for (String h : hits)
                sb.append(h).append('\n');
            if (truncated[0])
                sb.append("[stopped at ").append(max).append(" results; narrow the query, the path or file_pattern]\n");
            if (skippedLarge[0] > 0)
                sb.append("[skipped ").append(skippedLarge[0]).append(" file(s) over ").append(limits.maxSearchFileBytes).append(" bytes]\n");
            return sb.toString();
        }
    }

    // ---------------------------------------------------------------- write tools

    static final class WriteFile extends FSTool {
        WriteFile(FileAccessPolicy policy, Limits limits) {
            super(policy, limits, "write_file",
                    "Create a text file, or replace an existing file's entire content, encoded as UTF-8. The parent folder "
                            + "must exist unless create_parents is true. To change part of a file, use edit_file.",
                    false);
        }

        @Override
        public NVGenericMap inputSchema() {
            return SchemaBuilder.object()
                    .string("path", "File path", true)
                    .string("content", "The complete new content of the file", true)
                    .bool("create_parents", "Create missing parent folders (default false)")
                    .build();
        }

        @Override
        public String call(NVGenericMap arguments) throws IOException {
            String path = ToolArgs.requiredNonBlank(arguments, "path");
            String content = ToolArgs.requiredString(arguments, "content");
            boolean createParents = ToolArgs.optionalBoolean(arguments, "create_parents", false);

            byte[] bytes = content.getBytes(StandardCharsets.UTF_8);
            if (bytes.length > limits.maxWriteBytes)
                throw new IllegalArgumentException("Content is " + bytes.length + " bytes; the limit is " + limits.maxWriteBytes);

            Path target = policy.resolveForWrite(path);
            if (Files.isDirectory(target))
                throw new IllegalArgumentException("Is a directory: " + target);
            Path parent = target.getParent();
            if (parent != null && !Files.isDirectory(parent)) {
                if (!createParents)
                    throw new NoSuchFileException(parent + " (the parent folder does not exist; set create_parents to true)");
                Files.createDirectories(parent);
            }
            boolean existed = Files.exists(target);
            Files.write(target, bytes);
            return (existed ? "Replaced " : "Created ") + target + " (" + bytes.length + " bytes)";
        }
    }

    static final class EditFile extends FSTool {
        EditFile(FileAccessPolicy policy, Limits limits) {
            super(policy, limits, "edit_file",
                    "Replace exact text in a UTF-8 text file. old_text must match the file exactly, including spaces and "
                            + "line breaks, and must occur once unless replace_all is true; include surrounding lines to make "
                            + "it unique. Read the file first.",
                    false);
        }

        @Override
        public NVGenericMap inputSchema() {
            return SchemaBuilder.object()
                    .string("path", "File path", true)
                    .string("old_text", "Exact text to replace", true)
                    .string("new_text", "Replacement text (may be empty to delete)", true)
                    .bool("replace_all", "Replace every occurrence (default false)")
                    .build();
        }

        @Override
        public String call(NVGenericMap arguments) throws IOException {
            String path = ToolArgs.requiredNonBlank(arguments, "path");
            String oldText = ToolArgs.requiredString(arguments, "old_text");
            String newText = ToolArgs.requiredString(arguments, "new_text");
            boolean replaceAll = ToolArgs.optionalBoolean(arguments, "replace_all", false);
            if (oldText.isEmpty())
                throw new IllegalArgumentException("old_text must not be empty");

            Path target = policy.resolveForWrite(path);
            if (!Files.isRegularFile(target))
                throw new NoSuchFileException(target.toString());
            if (Files.size(target) > limits.maxWriteBytes)
                throw new IllegalArgumentException("File is over " + limits.maxWriteBytes + " bytes; edit_file will not rewrite it");

            String text = strictUTF8(Files.readAllBytes(target), target);
            int count = count(text, oldText);

            // read_file returns lines joined with \n; retry against a CRLF file in its own line endings
            if (count == 0 && text.contains("\r\n") && oldText.contains("\n") && !oldText.contains("\r\n")) {
                String crlfOld = oldText.replace("\n", "\r\n");
                int crlfCount = count(text, crlfOld);
                if (crlfCount > 0) {
                    oldText = crlfOld;
                    newText = newText.replace("\r\n", "\n").replace("\n", "\r\n");
                    count = crlfCount;
                }
            }

            if (count == 0)
                throw new IllegalArgumentException("old_text was not found in " + target);
            if (count > 1 && !replaceAll)
                throw new IllegalArgumentException("old_text occurs " + count + " times in " + target
                        + "; include more surrounding text to make it unique, or set replace_all to true");

            String updated;
            if (replaceAll) {
                updated = text.replace(oldText, newText);
            } else {
                int at = text.indexOf(oldText);
                updated = text.substring(0, at) + newText + text.substring(at + oldText.length());
            }
            byte[] bytes = updated.getBytes(StandardCharsets.UTF_8);
            if (bytes.length > limits.maxWriteBytes)
                throw new IllegalArgumentException("The edited file would be " + bytes.length + " bytes; the limit is " + limits.maxWriteBytes);
            Files.write(target, bytes);
            int replaced = replaceAll ? count : 1;
            return "Edited " + target + ": replaced " + replaced + (replaced == 1 ? " occurrence" : " occurrences");
        }
    }

    static final class CreateDirectory extends FSTool {
        CreateDirectory(FileAccessPolicy policy, Limits limits) {
            super(policy, limits, "create_directory",
                    "Create a directory, including any missing parent directories. Succeeds if it already exists.",
                    false);
        }

        @Override
        public NVGenericMap inputSchema() {
            return SchemaBuilder.object()
                    .string("path", "Directory path", true)
                    .build();
        }

        @Override
        public String call(NVGenericMap arguments) throws IOException {
            Path target = policy.resolveForWrite(ToolArgs.requiredNonBlank(arguments, "path"));
            if (Files.isDirectory(target))
                return "Already exists: " + target;
            Files.createDirectories(target);
            return "Created directory " + target;
        }
    }

    // ---------------------------------------------------------------- helpers

    /** Lenient UTF-8 reader: malformed bytes become U+FFFD instead of failing the read. */
    static BufferedReader reader(Path p) throws IOException {
        return new BufferedReader(new InputStreamReader(Files.newInputStream(p), StandardCharsets.UTF_8));
    }

    /** A NUL byte in the first 8 KB marks the file as binary. */
    static boolean isBinary(Path p) throws IOException {
        try (InputStream in = Files.newInputStream(p)) {
            byte[] buf = new byte[BINARY_PROBE_BYTES];
            int n = in.read(buf);
            for (int i = 0; i < n; i++) {
                if (buf[i] == 0)
                    return true;
            }
        }
        return false;
    }

    /** Decode strictly so an edit never rewrites a non-UTF-8 file with replacement characters. */
    static String strictUTF8(byte[] bytes, Path p) {
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes))
                    .toString();
        } catch (CharacterCodingException e) {
            throw new IllegalArgumentException("Not valid UTF-8, edit_file only edits UTF-8 text: " + p);
        }
    }

    static int count(String text, String part) {
        int n = 0;
        int i = 0;
        while ((i = text.indexOf(part, i)) >= 0) {
            n++;
            i += part.length();
        }
        return n;
    }

    /** Path relative to base, with forward slashes on every platform. */
    static String rel(Path base, Path p) {
        String s = base.relativize(p).toString();
        return s.replace('\\', '/');
    }
}
