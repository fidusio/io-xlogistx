package io.xlogistx.gui;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.encryption.AccessPermission;
import org.apache.pdfbox.pdmodel.encryption.InvalidPasswordException;
import org.apache.pdfbox.pdmodel.encryption.StandardProtectionPolicy;
import org.apache.pdfbox.text.PDFTextStripper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.swing.*;
import java.awt.*;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.function.BooleanSupplier;

import static org.junit.jupiter.api.Assertions.*;

/** Password-protected PDFs in {@link PDFViewerPanel}: opening with a prompt, saving, changing and removing the protection. */
public class PDFSecurityTest {

    private static final String OPEN = "open-me", OWNER = "the-owner";
    private static byte[] plainPDF;
    private static byte[] protectedPDF;
    private PDFViewerPanel panel;
    private File dir;

    @BeforeAll
    static void headless() throws Exception {
        System.setProperty("java.awt.headless", "true");
        plainPDF = MDToPDF.mdToPDF("# Page one\n\nSecret text here.\n\n<div style=\"page-break-before: always\"></div>\n\n# Page two\n\nMore text.\n\n<div style=\"page-break-before: always\"></div>\n\n# Page three\n\nLast.").toByteArray();
        try (PDDocument doc = Loader.loadPDF(plainPDF)) {
            AccessPermission ap = new AccessPermission();
            ap.setCanPrint(false);
            StandardProtectionPolicy policy = new StandardProtectionPolicy(OWNER, OPEN, ap);
            policy.setEncryptionKeyLength(128);
            doc.protect(policy);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            doc.save(out);
            protectedPDF = out.toByteArray();
        }
        assertThrows(InvalidPasswordException.class, () -> Loader.loadPDF(protectedPDF).close(), "the fixture needs a password");
    }

    @BeforeEach
    void setUp() throws Exception {
        dir = Files.createTempDirectory("pdfsecurity").toFile();
        panel = onEDT(() -> {
            PDFViewerPanel p = new PDFViewerPanel();
            p.setSize(600, 800);
            layoutTree(p);
            return p;
        });
    }

    @AfterEach
    void tearDown() throws Exception {
        onEDT(() -> {
            panel.close();
            return null;
        });
        File[] files = dir.listFiles();
        if (files != null)
            for (File f : files)
                f.delete();
        dir.delete();
    }

    @Test
    void valueClass() {
        assertFalse(PDFSecurity.NONE.isProtected());
        assertEquals("No password", PDFSecurity.NONE.describe());
        assertSame(PDFSecurity.NONE, PDFSecurity.of("", null, null), "nothing set = NONE");
        assertSame(PDFSecurity.NONE, PDFSecurity.of(null, "", new AccessPermission()));

        PDFSecurity s = PDFSecurity.of("a", "", null);
        assertTrue(s.isProtected());
        assertTrue(s.needsPasswordToOpen());
        assertEquals("a", s.effectiveOwnerPassword(), "owner = open password when empty");
        assertTrue(s.allAllowed());
        assertEquals("Password to open", s.describe());

        AccessPermission ap = new AccessPermission();
        ap.setCanPrint(false);
        ap.setCanExtractContent(false);
        PDFSecurity r = PDFSecurity.of("", "boss", ap);
        assertTrue(r.isProtected());
        assertFalse(r.needsPasswordToOpen());
        assertFalse(r.allAllowed());
        assertFalse(r.getPermissions().canPrint());
        assertTrue(r.getPermissions().canModify());
        assertEquals("Opens without a password, separate owner password; printing not allowed; copying not allowed", r.describe());
        assertEquals(PDFSecurity.of("", "boss", ap), r);
        assertNotEquals(PDFSecurity.of("", "boss", null), r);
        ap.setCanPrint(true); // the value keeps its own copy of the bits
        assertFalse(r.getPermissions().canPrint());
    }

    @Test
    void opensWithThePromptAndSavesEncrypted() throws Exception {
        File src = write("locked.pdf", protectedPDF);
        List<Integer> attempts = new ArrayList<>();
        List<String> names = new ArrayList<>();
        onEDT(() -> panel.setPasswordPrompt((name, attempt) -> {
            names.add(name);
            attempts.add(attempt);
            return attempt == 0 ? "wrong" : OPEN; // the first try is refused
        }));
        onEDT(() -> {
            panel.setPDF(src);
            return null;
        });
        waitFor(() -> panel.getPageCount() == 3, 10_000);
        assertEquals(Arrays.asList(0, 1), attempts, "asked twice, the attempt counting the refusals");
        assertEquals("locked.pdf", names.get(0));
        PDFSecurity s = onEDT(panel::getSecurity);
        assertTrue(s.isProtected());
        assertEquals(OPEN, s.getOpenPassword());
        assertFalse(s.getPermissions().canPrint(), "the file's permissions are read back");
        assertTrue(s.getPermissions().canModify());
        assertFalse(onEDT(panel::isModified));
        assertFalse(onEDT(() -> panel.search("More text")).isEmpty(), "the pages are readable");

        // saving keeps the same password and permissions (PDFBox would otherwise refuse to save)
        File out = new File(dir, "copy.pdf");
        onEDT(() -> {
            panel.save(out);
            return null;
        });
        waitFor(() -> out.length() > 0 && out.equals(panel.getFile()), 10_000);
        assertThrows(InvalidPasswordException.class, () -> Loader.loadPDF(out).close(), "still protected");
        try (PDDocument doc = Loader.loadPDF(out, OPEN)) {
            assertEquals(3, doc.getNumberOfPages());
            assertTrue(doc.isEncrypted());
            assertFalse(new AccessPermission(doc.getEncryption().getPermissions()).canPrint());
            assertTrue(text(doc).contains("Secret text here"));
        }

        // removing the protection: the next save is a plain file; the document stays usable
        assertTrue(onEDT(() -> panel.setSecurity(PDFSecurity.NONE)));
        assertTrue(onEDT(panel::isModified));
        assertSame(PDFSecurity.NONE, onEDT(panel::getSecurity));
        File plain = new File(dir, "plain.pdf");
        onEDT(() -> {
            panel.save(plain);
            return null;
        });
        waitFor(() -> plain.length() > 0 && plain.equals(panel.getFile()), 10_000);
        try (PDDocument doc = Loader.loadPDF(plain)) {
            assertFalse(doc.isEncrypted());
            assertEquals(3, doc.getNumberOfPages());
            assertTrue(text(doc).contains("Last."));
        }
    }

    @Test
    void protectsAPlainDocumentAndSavesTwice() throws Exception {
        File src = write("plain.pdf", plainPDF);
        onEDT(() -> {
            panel.setPDF(src);
            return null;
        });
        waitFor(() -> panel.getPageCount() == 3, 10_000);
        assertSame(PDFSecurity.NONE, onEDT(panel::getSecurity));

        AccessPermission ap = new AccessPermission();
        ap.setCanExtractContent(false);
        PDFSecurity s = PDFSecurity.of("new-pass", "boss", ap);
        boolean[] fired = new boolean[1];
        onEDT(() -> {
            panel.addPropertyChangeListener("security", e -> fired[0] = true);
            return panel.setSecurity(s);
        });
        assertTrue(fired[0], "property change");
        assertEquals(s, onEDT(panel::getSecurity));
        assertTrue(onEDT(panel::isModified));
        assertFalse(onEDT(() -> panel.search("Last.")).isEmpty(), "the document in memory stays readable");

        File out = new File(dir, "locked.pdf");
        onEDT(() -> {
            panel.save(out);
            return null;
        });
        waitFor(() -> out.length() > 0 && out.equals(panel.getFile()), 10_000);
        assertFalse(onEDT(panel::isModified));
        assertThrows(InvalidPasswordException.class, () -> Loader.loadPDF(out).close());
        assertThrows(InvalidPasswordException.class, () -> Loader.loadPDF(out, "wrong").close());
        try (PDDocument doc = Loader.loadPDF(out, "new-pass")) {
            assertTrue(doc.isEncrypted());
            AccessPermission read = new AccessPermission(doc.getEncryption().getPermissions());
            assertFalse(read.canExtractContent());
            assertTrue(read.canPrint());
            assertFalse(doc.getCurrentAccessPermission().isOwnerPermission(), "the open password is not the owner's");
        }
        try (PDDocument doc = Loader.loadPDF(out, "boss")) {
            assertTrue(doc.getCurrentAccessPermission().isOwnerPermission(), "the owner password is separate");
        }

        // a second save of the same document, after an edit, is encrypted the same way
        onEDT(() -> {
            panel.deletePages(new int[]{2});
            panel.save(out);
            return null;
        });
        waitFor(() -> !panel.isModified(), 10_000);
        try (PDDocument doc = Loader.loadPDF(out, "new-pass")) {
            assertEquals(2, doc.getNumberOfPages());
            assertTrue(text(doc).contains("More text"));
        }
    }

    @Test
    void cancelledPromptOpensNothing() throws Exception {
        File src = write("locked.pdf", protectedPDF);
        int[] asked = new int[1];
        onEDT(() -> panel.setPasswordPrompt((name, attempt) -> {
            asked[0]++;
            return null;
        }));
        onEDT(() -> {
            panel.setPDF(src);
            return null;
        });
        waitFor(() -> asked[0] == 1, 10_000);
        Thread.sleep(300);
        assertNull(onEDT(panel::getDocument), "nothing opened, no error");
        assertNull(onEDT(panel::getFile));

        // an insert whose prompt is cancelled changes nothing either
        File plain = write("plain.pdf", plainPDF);
        onEDT(() -> {
            panel.setPDF(plain);
            return null;
        });
        waitFor(() -> panel.getPageCount() == 3, 10_000);
        onEDT(() -> {
            panel.insertPDF(src, 3);
            return null;
        });
        waitFor(() -> asked[0] == 2, 10_000);
        Thread.sleep(300);
        assertEquals(3, onEDT(panel::getPageCount));
        assertFalse(onEDT(panel::isModified));

        // the headless default prompt gives up at once
        onEDT(() -> panel.setPasswordPrompt(null));
        onEDT(() -> {
            panel.insertPDF(src, 3);
            return null;
        });
        Thread.sleep(500);
        assertEquals(3, onEDT(panel::getPageCount));
    }

    @Test
    void hostParsedEncryptedDocumentKeepsItsPermissions() throws Exception {
        PDDocument doc = Loader.loadPDF(protectedPDF, OPEN);
        onEDT(() -> panel.setDocument(doc, true));
        PDFSecurity s = onEDT(panel::getSecurity);
        assertTrue(s.isProtected(), "the restrictions stay");
        assertFalse(s.needsPasswordToOpen(), "the password is unknown to the panel");
        assertFalse(s.getPermissions().canPrint());
        File out = new File(dir, "host.pdf");
        onEDT(() -> {
            panel.save(out);
            return null;
        });
        waitFor(() -> out.length() > 0 && out.equals(panel.getFile()), 10_000);
        try (PDDocument saved = Loader.loadPDF(out)) {
            assertTrue(saved.isEncrypted());
            assertFalse(new AccessPermission(saved.getEncryption().getPermissions()).canPrint());
        }
    }

    // ------------------------------------------------------------------ helpers

    private File write(String name, byte[] bytes) throws Exception {
        File f = new File(dir, name);
        Files.write(f.toPath(), bytes);
        return f;
    }

    private static String text(PDDocument doc) throws Exception {
        return new PDFTextStripper().getText(doc);
    }

    private static void layoutTree(Component c) {
        c.doLayout();
        if (c instanceof Container)
            for (Component child : ((Container) c).getComponents())
                layoutTree(child);
        if (c instanceof Container)
            c.doLayout();
    }

    private static <T> T onEDT(Callable<T> call) throws Exception {
        if (SwingUtilities.isEventDispatchThread())
            return call.call();
        Object[] result = new Object[1];
        Exception[] error = new Exception[1];
        SwingUtilities.invokeAndWait(() -> {
            try {
                result[0] = call.call();
            } catch (Exception e) {
                error[0] = e;
            }
        });
        if (error[0] != null)
            throw error[0];
        @SuppressWarnings("unchecked")
        T t = (T) result[0];
        return t;
    }

    private void waitFor(BooleanSupplier condition, long timeoutMs) throws Exception {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < deadline) {
            if (onEDT(condition::getAsBoolean))
                return;
            Thread.sleep(50);
        }
        fail("condition not met within " + timeoutMs + " ms");
    }
}
