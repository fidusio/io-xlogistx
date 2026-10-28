package io.xlogistx.editor.pdf;

import io.xlogistx.gui.MDToPDF;
import io.xlogistx.gui.pdf.PDFViewerPanel;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.text.PDFTextStripper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.function.BooleanSupplier;

import static org.junit.jupiter.api.Assertions.*;

/** Tier 1: rotating and moving pages through {@link PDFEditorPane}, undoable and persisted. */
public class PageOpsEditTest {

    private static final String PAGE_BREAK = "\n\n<div style=\"page-break-before: always\"></div>\n\n";
    private static byte[] threePagePDF;
    private PDFEditorPane pane;
    private PDFViewerPanel viewer;

    @BeforeAll
    static void headless() throws Exception {
        System.setProperty("java.awt.headless", "true");
        threePagePDF = MDToPDF.mdToPDF("# One\n\nfirst page text" + PAGE_BREAK + "# Two\n\nsecond page text" + PAGE_BREAK + "# Three\n\nthird page text").toByteArray();
    }

    @BeforeEach
    void setUp() throws Exception {
        pane = onEDT(() -> {
            PDFEditorPane p = new PDFEditorPane();
            p.setSize(700, 900);
            layoutTree(p);
            return p;
        });
        viewer = pane.getViewer();
        PDDocument doc = Loader.loadPDF(threePagePDF);
        onEDT(() -> {
            viewer.setDocument(doc, true);
            layoutTree(pane);
            pane.setEditable(true);
            return null;
        });
    }

    @AfterEach
    void tearDown() throws Exception {
        onEDT(() -> {
            viewer.close();
            return null;
        });
    }

    @Test
    void rotationIsUndoableAndPersists() throws Exception {
        assertEquals(0, rotation(0));
        assertTrue(onEDT(() -> pane.rotatePages(new int[]{0}, 90)));
        assertEquals(90, rotation(0));
        assertEquals(0, rotation(1));
        assertTrue(pane.isModified());
        assertEquals("Rotate 1 page clockwise", pane.getEditModel().peekUndo().name());

        onEDT(pane::undo);
        assertEquals(0, rotation(0));
        assertFalse(pane.isModified());
        onEDT(pane::redo);
        assertEquals(90, rotation(0));

        assertTrue(onEDT(() -> pane.rotatePages(new int[]{1, 0, 1}, -90)));
        assertEquals(0, rotation(0), "90 - 90");
        assertEquals(270, rotation(1), "0 - 90 wraps");
        assertEquals("Rotate 2 pages counter-clockwise", pane.getEditModel().peekUndo().name());

        File out = File.createTempFile("pdfeditor-rotate", ".pdf");
        out.deleteOnExit();
        onEDT(() -> {
            viewer.save(out);
            return null;
        });
        waitFor(() -> !pane.isModified(), 15000);
        try (PDDocument saved = Loader.loadPDF(out)) {
            assertEquals(0, saved.getPage(0).getRotation());
            assertEquals(270, saved.getPage(1).getRotation());
        }
        assertThrows(IllegalArgumentException.class, () -> new RotatePagesEdit(viewer, new int[]{0}, 45));
        assertThrows(IllegalArgumentException.class, () -> new RotatePagesEdit(viewer, new int[0], 90));
    }

    @Test
    void rotatedPageRendersLandscape() throws Exception {
        waitFor(() -> viewer.getPageImage(0) != null, 10000);
        assertTrue(onEDT(() -> viewer.getPageImage(0)).getHeight() > onEDT(() -> viewer.getPageImage(0)).getWidth());
        onEDT(() -> pane.rotatePages(new int[]{0}, 90));
        waitFor(() -> viewer.getPageImage(0) != null, 10000);
        assertTrue(onEDT(() -> viewer.getPageImage(0)).getWidth() > onEDT(() -> viewer.getPageImage(0)).getHeight());
    }

    @Test
    void movingPagesReordersAndUndoRestores() throws Exception {
        assertEquals(Arrays.asList("first page text", "second page text", "third page text"), texts());
        assertTrue(onEDT(() -> pane.movePages(new int[]{2, 1}, 0)), "pages 2-3 to the beginning");
        assertEquals(Arrays.asList("second page text", "third page text", "first page text"), texts());
        MovePagesEdit edit = (MovePagesEdit) pane.getEditModel().peekUndo();
        assertArrayEquals(new int[]{0, 1}, edit.getLandingIndexes());
        assertEquals("Move 2 pages", edit.name());
        assertEquals(Arrays.asList(2), onEDT(() -> viewer.find("first page text")), "page views and text were rebuilt");

        onEDT(pane::undo);
        assertEquals(Arrays.asList("first page text", "second page text", "third page text"), texts());
        assertFalse(pane.isModified());
        onEDT(pane::redo);
        assertEquals(Arrays.asList("second page text", "third page text", "first page text"), texts());
        onEDT(pane::undo);

        assertTrue(onEDT(() -> pane.movePages(new int[]{0}, 3)), "page 1 to the end");
        assertEquals(Arrays.asList("second page text", "third page text", "first page text"), texts());
        onEDT(pane::undo);
        assertTrue(onEDT(() -> pane.movePages(new int[]{0}, 2)), "page 1 after page 2 (in front of the page at index 2)");
        assertEquals(Arrays.asList("second page text", "first page text", "third page text"), texts());
        onEDT(pane::undo);
        assertEquals(Arrays.asList("first page text", "second page text", "third page text"), texts());
        assertThrows(IllegalArgumentException.class, () -> new MovePagesEdit(viewer, new int[0], 0));
    }

    @Test
    void pageOpsAreOneUndoStepEachAndClearOnReload() throws Exception {
        onEDT(() -> pane.rotatePages(new int[]{0}, 90));
        onEDT(() -> pane.movePages(new int[]{0}, 3));
        assertEquals(2, pane.getEditModel().getUndoDepth());
        PDDocument doc = Loader.loadPDF(threePagePDF);
        onEDT(() -> viewer.setDocument(doc, true));
        assertFalse(pane.canUndo());
        assertEquals(0, rotation(0));
    }

    // ---------------------------------------------------------------- helpers

    private int rotation(int page) throws Exception {
        return onEDT(() -> {
            synchronized (viewer.getDocumentLock()) {
                return viewer.getDocument().getPage(page).getRotation();
            }
        });
    }

    private List<String> texts() throws Exception {
        return onEDT(() -> {
            synchronized (viewer.getDocumentLock()) {
                String[] out = new String[viewer.getDocument().getNumberOfPages()];
                for (int i = 0; i < out.length; i++) {
                    PDFTextStripper s = new PDFTextStripper();
                    s.setStartPage(i + 1);
                    s.setEndPage(i + 1);
                    String[] lines = s.getText(viewer.getDocument()).trim().split("\\R");
                    out[i] = lines[lines.length - 1].trim();
                }
                return Arrays.asList(out);
            }
        });
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
