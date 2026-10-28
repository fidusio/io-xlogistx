package io.xlogistx.editor.pdf;

import io.xlogistx.gui.MDToPDF;
import io.xlogistx.gui.pdf.PDFSecurity;
import io.xlogistx.gui.pdf.PDFViewerPanel;
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
import java.util.List;
import java.util.concurrent.Callable;
import java.util.function.BooleanSupplier;

import static org.junit.jupiter.api.Assertions.*;

/** Document passwords in the editor: opening a protected file, setting / changing / removing the protection as undo steps, saving. */
public class DocumentPasswordTest {

    private static final String OPEN = "open-me";
    private static byte[] plainPDF;
    private static byte[] protectedPDF;
    private PDFEditorPane pane;
    private PDFViewerPanel viewer;
    private File dir;

    @BeforeAll
    static void headless() throws Exception {
        System.setProperty("java.awt.headless", "true");
        plainPDF = MDToPDF.mdToPDF("# One\n\nFirst page.\n\n<div style=\"page-break-before: always\"></div>\n\n# Two\n\nSecond page.").toByteArray();
        try (PDDocument doc = Loader.loadPDF(plainPDF)) {
            AccessPermission ap = new AccessPermission();
            ap.setCanPrint(false);
            doc.protect(new StandardProtectionPolicy("owner-pw", OPEN, ap));
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            doc.save(out);
            protectedPDF = out.toByteArray();
        }
    }

    @BeforeEach
    void setUp() throws Exception {
        dir = Files.createTempDirectory("pdfeditor-password").toFile();
        pane = onEDT(() -> {
            PDFEditorPane p = new PDFEditorPane();
            p.setSize(700, 900);
            layoutTree(p);
            return p;
        });
        viewer = pane.getViewer();
    }

    @AfterEach
    void tearDown() throws Exception {
        onEDT(() -> {
            viewer.close();
            return null;
        });
        File[] files = dir.listFiles();
        if (files != null)
            for (File f : files)
                f.delete();
        dir.delete();
    }

    @Test
    void protectedFileOpensWithThePromptAndIsSavedProtected() throws Exception {
        File locked = write("locked.pdf", protectedPDF);
        List<Integer> attempts = new ArrayList<>();
        onEDT(() -> viewer.setPasswordPrompt((name, attempt) -> {
            attempts.add(attempt);
            return OPEN;
        }));
        onEDT(() -> pane.open(locked));
        waitFor(() -> locked.equals(viewer.getFile()), 10_000);
        assertEquals(1, attempts.size());
        PDFSecurity loaded = pane.getDocumentSecurity();
        assertTrue(loaded.isProtected());
        assertEquals(OPEN, loaded.getOpenPassword());
        assertFalse(loaded.getPermissions().canPrint());
        assertFalse(pane.isModified(), "opening is not a change");
        assertEquals(0, pane.getEditModel().getUndoDepth());
        onEDT(() -> pane.setEditable(true));
        assertTrue(pane.getStatusDetail().startsWith("Protected: Password to open"), pane.getStatusDetail());
        assertTrue(pane.getStatusDetail().contains("printing not allowed"));

        // an edit, then save over the file: still protected by the same password, the edit inside
        assertTrue(onEDT(() -> pane.rotatePages(new int[]{0}, 90)));
        onEDT(() -> pane.save());
        waitFor(() -> !pane.isModified(), 10_000);
        assertThrows(InvalidPasswordException.class, () -> Loader.loadPDF(locked).close());
        try (PDDocument doc = Loader.loadPDF(locked, OPEN)) {
            assertEquals(90, doc.getPage(0).getRotation());
            assertFalse(new AccessPermission(doc.getEncryption().getPermissions()).canPrint());
            assertTrue(new PDFTextStripper().getText(doc).contains("Second page"));
        }
        assertTrue(pane.canUndo(), "the history survives the save");
        assertEquals(2, viewer.getPageCount());
    }

    @Test
    void settingChangingAndRemovingThePasswordAreUndoSteps() throws Exception {
        File work = write("work.pdf", plainPDF);
        onEDT(() -> pane.open(work));
        waitFor(() -> work.equals(viewer.getFile()), 10_000);
        assertSame(PDFSecurity.NONE, pane.getDocumentSecurity());
        assertEquals("", pane.getStatusDetail());

        PDFSecurity first = PDFSecurity.of("abc", "", null);
        assertTrue(onEDT(() -> pane.setDocumentSecurity(first)));
        assertTrue(pane.isEditable(), "turns Edit on like every edit");
        assertTrue(pane.isModified());
        assertEquals(1, pane.getEditModel().getUndoDepth());
        assertEquals("Set document password", pane.getEditModel().peekUndo().name());
        assertEquals(first, pane.getDocumentSecurity());
        assertEquals("Protected: Password to open", pane.getStatusDetail());
        assertFalse(onEDT(() -> pane.setDocumentSecurity(first)), "the same value is no edit");
        assertEquals(1, pane.getEditModel().getUndoDepth());

        AccessPermission ap = new AccessPermission();
        ap.setCanPrint(false);
        PDFSecurity second = PDFSecurity.of("abc", "", ap);
        assertTrue(onEDT(() -> pane.setDocumentSecurity(second)));
        assertEquals("Change document permissions", pane.getEditModel().peekUndo().name());
        PDFSecurity third = PDFSecurity.of("xyz", "boss", ap);
        assertTrue(onEDT(() -> pane.setDocumentSecurity(third)));
        assertEquals("Change document password", pane.getEditModel().peekUndo().name());
        assertTrue(onEDT(() -> pane.setDocumentSecurity(null)));
        assertEquals("Remove document password", pane.getEditModel().peekUndo().name());
        assertSame(PDFSecurity.NONE, pane.getDocumentSecurity());
        assertEquals(4, pane.getEditModel().getUndoDepth());

        onEDT(pane::undo);
        assertEquals(third, pane.getDocumentSecurity());
        onEDT(pane::undo);
        onEDT(pane::undo);
        assertEquals(first, pane.getDocumentSecurity());
        onEDT(pane::undo);
        assertSame(PDFSecurity.NONE, pane.getDocumentSecurity());
        assertFalse(pane.isModified(), "back at the saved state");
        assertEquals("", pane.getStatusDetail());
        onEDT(pane::redo);
        assertEquals(first, pane.getDocumentSecurity());

        // the viewer's own entry point goes through the delegate, so it is undoable too
        assertTrue(onEDT(() -> viewer.setSecurity(third)));
        assertEquals(2, pane.getEditModel().getUndoDepth());
        assertEquals(third, pane.getDocumentSecurity());

        // saved with the current protection; the file on disk needs the new password
        onEDT(() -> pane.save());
        waitFor(() -> !pane.isModified(), 10_000);
        assertThrows(InvalidPasswordException.class, () -> Loader.loadPDF(work).close());
        try (PDDocument doc = Loader.loadPDF(work, "xyz")) {
            assertEquals(2, doc.getNumberOfPages());
            assertFalse(new AccessPermission(doc.getEncryption().getPermissions()).canPrint());
            assertTrue(new PDFTextStripper().getText(doc).contains("First page"));
        }
        try (PDDocument doc = Loader.loadPDF(work, "boss")) {
            assertTrue(doc.getCurrentAccessPermission().isOwnerPermission());
        }
        assertEquals(2, viewer.getPageCount(), "the document on screen is untouched");

        // removing it and saving again gives a plain file
        assertTrue(onEDT(() -> pane.setDocumentSecurity(PDFSecurity.NONE)));
        onEDT(() -> pane.save());
        waitFor(() -> !pane.isModified(), 10_000);
        try (PDDocument doc = Loader.loadPDF(work)) {
            assertFalse(doc.isEncrypted());
            assertTrue(new PDFTextStripper().getText(doc).contains("Second page"));
        }
    }

    @Test
    void fileMenuHasTheEntryAndNothingLoadedIsRefused() throws Exception {
        JMenuBar bar = onEDT(pane::createMenuBar);
        JMenu file = bar.getMenu(0);
        List<String> items = new ArrayList<>();
        for (int i = 0; i < file.getItemCount(); i++)
            if (file.getItem(i) != null)
                items.add(file.getItem(i).getText());
        assertTrue(items.contains("Document password..."), items.toString());
        assertTrue(items.indexOf("Document password...") > items.indexOf("Save As..."));
        assertFalse(onEDT(() -> pane.setDocumentSecurity(PDFSecurity.of("x", "", null))), "no document");
        assertFalse(onEDT(pane::documentPasswordDialog), "no document: no dialog");
    }

    // ------------------------------------------------------------------ helpers

    private File write(String name, byte[] bytes) throws Exception {
        File f = new File(dir, name);
        Files.write(f.toPath(), bytes);
        return f;
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
