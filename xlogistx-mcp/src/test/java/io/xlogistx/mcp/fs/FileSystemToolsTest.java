package io.xlogistx.mcp.fs;

import io.xlogistx.mcp.MCPTool;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.zoxweb.shared.util.NVBoolean;
import org.zoxweb.shared.util.NVGenericMap;
import org.zoxweb.shared.util.NVInt;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AccessDeniedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class FileSystemToolsTest {

    @TempDir
    Path root;

    @TempDir
    Path outside;

    private Map<String, MCPTool> tools(boolean readOnly) throws IOException {
        FileAccessPolicy policy = new FileAccessPolicy(Collections.singletonList(root.toString()), readOnly);
        Map<String, MCPTool> m = new HashMap<>();
        for (MCPTool t : FileSystemTools.create(policy, new FileSystemTools.Limits()))
            m.put(t.getName(), t);
        return m;
    }

    private static NVGenericMap args(Object... kv) {
        NVGenericMap m = new NVGenericMap("arguments");
        for (int i = 0; i < kv.length; i += 2) {
            String name = (String) kv[i];
            Object v = kv[i + 1];
            if (v instanceof Boolean)
                m.add(new NVBoolean(name, (Boolean) v));
            else if (v instanceof Integer)
                m.add(new NVInt(name, (Integer) v));
            else
                m.add(name, v.toString());
        }
        return m;
    }

    private String call(String tool, Object... kv) throws Exception {
        return tools(false).get(tool).call(args(kv));
    }

    @Test
    public void readOnlyModeLeavesOutTheWriteTools() throws Exception {
        Map<String, MCPTool> ro = tools(true);
        assertTrue(ro.containsKey("read_file"));
        assertFalse(ro.containsKey("write_file"));
        assertFalse(ro.containsKey("edit_file"));
        assertFalse(ro.containsKey("create_directory"));
        assertEquals(9, tools(false).size());
    }

    @Test
    public void writeReadEditRoundTrip() throws Exception {
        String created = call("write_file", "path", "a/b.txt", "content", "one\ntwo\nthree\n", "create_parents", true);
        assertTrue(created.startsWith("Created "), created);
        assertEquals("one\ntwo\nthree\n", call("read_file", "path", "a/b.txt"));

        call("edit_file", "path", root.resolve("a/b.txt").toString(), "old_text", "two", "new_text", "2");
        assertEquals("one\n2\nthree\n", new String(Files.readAllBytes(root.resolve("a/b.txt")), StandardCharsets.UTF_8));

        assertTrue(call("write_file", "path", "a/b.txt", "content", "").startsWith("Replaced "));
        assertEquals("[empty file]", call("read_file", "path", "a/b.txt"));
    }

    @Test
    public void writeNeedsAnExistingParentUnlessAsked() {
        assertThrows(java.nio.file.NoSuchFileException.class,
                () -> call("write_file", "path", "missing/x.txt", "content", "x"));
    }

    @Test
    public void readFileInParts() throws Exception {
        StringBuilder sb = new StringBuilder();
        for (int i = 1; i <= 10; i++)
            sb.append("line").append(i).append('\n');
        Files.write(root.resolve("ten.txt"), sb.toString().getBytes(StandardCharsets.UTF_8));

        String part = call("read_file", "path", "ten.txt", "offset", 3, "limit", 2);
        assertTrue(part.startsWith("line3\nline4\n"), part);
        assertTrue(part.contains("offset=5"), part);

        String tail = call("read_file", "path", "ten.txt", "offset", 9);
        assertTrue(tail.startsWith("line9\nline10\n"), tail);
        assertTrue(tail.contains("the end of the file"), tail);

        assertTrue(call("read_file", "path", "ten.txt", "offset", 50).contains("past the end"));
    }

    @Test
    public void dotDotAndAbsolutePathsOutsideAreRefused() throws Exception {
        Files.write(outside.resolve("secret.txt"), "s".getBytes(StandardCharsets.UTF_8));
        String viaDotDot = "../" + outside.getFileName() + "/secret.txt";

        assertThrows(AccessDeniedException.class, () -> call("read_file", "path", viaDotDot));
        assertThrows(AccessDeniedException.class, () -> call("read_file", "path", outside.resolve("secret.txt").toString()));
        assertThrows(AccessDeniedException.class, () -> call("write_file", "path", outside.resolve("new.txt").toString(), "content", "x"));
        assertThrows(AccessDeniedException.class, () -> call("list_directory", "path", ".."));
        assertFalse(Files.exists(outside.resolve("new.txt")));
    }

    @Test
    public void aSiblingWithTheSamePrefixIsNotInside() throws Exception {
        Path sibling = Paths.get(root.toString() + "-evil");
        Files.createDirectories(sibling);
        try {
            Files.write(sibling.resolve("x.txt"), "x".getBytes(StandardCharsets.UTF_8));
            assertThrows(AccessDeniedException.class, () -> call("read_file", "path", sibling.resolve("x.txt").toString()));
        } finally {
            Files.deleteIfExists(sibling.resolve("x.txt"));
            Files.deleteIfExists(sibling);
        }
    }

    @Test
    public void aRootCannotBeReplaced() {
        assertThrows(AccessDeniedException.class, () -> call("write_file", "path", root.toString(), "content", "x"));
    }

    @Test
    public void aLinkPointingOutsideIsRefused() throws Exception {
        Files.write(outside.resolve("secret.txt"), "classified".getBytes(StandardCharsets.UTF_8));
        Path link = root.resolve("link");
        try {
            Files.createSymbolicLink(link, outside);
        } catch (UnsupportedOperationException | IOException | SecurityException e) {
            // Windows without symlink rights: a directory junction needs none and escapes the same way
            Assumptions.assumeTrue(windowsJunction(link, outside), "neither symbolic links nor junctions available: " + e);
        }
        assertThrows(AccessDeniedException.class, () -> call("read_file", "path", "link/secret.txt"));
        assertThrows(AccessDeniedException.class, () -> call("write_file", "path", "link/new.txt", "content", "x"));
        assertFalse(call("search_text", "path", ".", "query", "classified").contains("secret.txt"),
                "the walk must not follow the link");
        assertFalse(call("search_files", "path", ".", "pattern", "*.txt").contains("secret.txt"));
        String listing = call("list_directory", "path", ".", "depth", 3);
        assertFalse(listing.contains("secret.txt"), listing);
    }

    private static boolean windowsJunction(Path link, Path target) {
        if (!System.getProperty("os.name", "").toLowerCase().contains("windows"))
            return false;
        try {
            Process p = new ProcessBuilder("cmd", "/c", "mklink", "/J", link.toString(), target.toString())
                    .redirectErrorStream(true).start();
            return p.waitFor() == 0 && Files.exists(link);
        } catch (Exception e) {
            return false;
        }
    }

    @Test
    public void editNeedsAUniqueMatchUnlessReplaceAll() throws Exception {
        Files.write(root.resolve("x.txt"), "x and x".getBytes(StandardCharsets.UTF_8));
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> call("edit_file", "path", "x.txt", "old_text", "x", "new_text", "y"));
        assertTrue(e.getMessage().contains("2 times"), e.getMessage());
        assertThrows(IllegalArgumentException.class,
                () -> call("edit_file", "path", "x.txt", "old_text", "zzz", "new_text", "y"));

        call("edit_file", "path", "x.txt", "old_text", "x", "new_text", "y", "replace_all", true);
        assertEquals("y and y", new String(Files.readAllBytes(root.resolve("x.txt")), StandardCharsets.UTF_8));
    }

    @Test
    public void editKeepsCRLFLineEndings() throws Exception {
        Files.write(root.resolve("crlf.txt"), "a\r\nb\r\nc\r\n".getBytes(StandardCharsets.UTF_8));
        call("edit_file", "path", "crlf.txt", "old_text", "a\nb", "new_text", "A\nB");
        assertEquals("A\r\nB\r\nc\r\n", new String(Files.readAllBytes(root.resolve("crlf.txt")), StandardCharsets.UTF_8));
    }

    @Test
    public void editRefusesAFileThatIsNotUTF8() throws Exception {
        Files.write(root.resolve("latin1.txt"), new byte[]{'a', (byte) 0xE9, 'b'});
        assertThrows(IllegalArgumentException.class,
                () -> call("edit_file", "path", "latin1.txt", "old_text", "a", "new_text", "c"));
        assertArrayEquals(new byte[]{'a', (byte) 0xE9, 'b'}, Files.readAllBytes(root.resolve("latin1.txt")));
    }

    @Test
    public void binaryFilesAreRefusedByReadAndSkippedBySearch() throws Exception {
        Files.write(root.resolve("bin.dat"), new byte[]{'n', 'e', 'e', 'd', 'l', 'e', 0, 1, 2});
        assertThrows(IllegalArgumentException.class, () -> call("read_file", "path", "bin.dat"));
        assertTrue(call("search_text", "path", ".", "query", "needle").startsWith("0 matching lines"));
    }

    @Test
    public void searchFilesByNameAndByPath() throws Exception {
        Files.createDirectories(root.resolve("src/main"));
        Files.createDirectories(root.resolve("src/test"));
        Files.createDirectories(root.resolve(".git"));
        Files.write(root.resolve("src/main/App.java"), new byte[0]);
        Files.write(root.resolve("src/test/AppTest.java"), new byte[0]);
        Files.write(root.resolve(".git/Hidden.java"), new byte[0]);
        Files.write(root.resolve("readme.md"), new byte[0]);

        String byName = call("search_files", "path", ".", "pattern", "*.java");
        assertTrue(byName.startsWith("2 matches"), byName);
        assertTrue(byName.contains("src/main/App.java") && byName.contains("src/test/AppTest.java"), byName);
        assertFalse(byName.contains("Hidden.java"), ".git is not entered");

        String byPath = call("search_files", "path", ".", "pattern", "src/test/*.java");
        assertTrue(byPath.startsWith("1 match"), byPath);
    }

    @Test
    public void searchText() throws Exception {
        Files.createDirectories(root.resolve("d"));
        Files.write(root.resolve("d/a.txt"), "alpha\nBeta\ngamma\n".getBytes(StandardCharsets.UTF_8));
        Files.write(root.resolve("d/b.log"), "beta here too\n".getBytes(StandardCharsets.UTF_8));

        String any = call("search_text", "path", ".", "query", "beta");
        assertTrue(any.startsWith("2 matching lines"), any);
        assertTrue(any.contains("d/a.txt:2: Beta"), any);

        assertTrue(call("search_text", "path", ".", "query", "beta", "case_sensitive", true).startsWith("1 matching line"));
        assertTrue(call("search_text", "path", ".", "query", "beta", "file_pattern", "*.txt").startsWith("1 matching line"));
        assertTrue(call("search_text", "path", ".", "query", "^g.m", "regex", true).contains("a.txt:3: gamma"));
        assertTrue(call("search_text", "path", "d/a.txt", "query", "alpha").contains("a.txt:1: alpha"));
    }

    @Test
    public void listDirectoryByDepth() throws Exception {
        Files.createDirectories(root.resolve("top/inner"));
        Files.write(root.resolve("top/inner/deep.txt"), "x".getBytes(StandardCharsets.UTF_8));
        Files.write(root.resolve("file.txt"), "12345".getBytes(StandardCharsets.UTF_8));

        String one = call("list_directory", "path", ".");
        assertTrue(one.contains("[DIR]  top/"), one);
        assertTrue(one.contains("[FILE] file.txt  (5 bytes)"), one);
        assertFalse(one.contains("deep.txt"), one);

        String three = call("list_directory", "path", ".", "depth", 3);
        assertTrue(three.contains("[FILE] top/inner/deep.txt"), three);
    }

    @Test
    public void createDirectoryAndFileInfo() throws Exception {
        assertTrue(call("create_directory", "path", "x/y/z").startsWith("Created directory"));
        assertTrue(call("create_directory", "path", "x/y/z").startsWith("Already exists"));
        assertTrue(call("get_file_info", "path", "x/y").contains("type: directory"));
    }

    @Test
    public void listAllowedRoots() throws Exception {
        String roots = call("list_allowed_roots");
        assertTrue(roots.contains("read-write"), roots);
        assertTrue(roots.contains(root.toRealPath().toString()), roots);
    }
}
