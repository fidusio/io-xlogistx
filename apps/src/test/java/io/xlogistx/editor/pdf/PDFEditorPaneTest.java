package io.xlogistx.editor.pdf;

import io.xlogistx.gui.MDToPDF;
import io.xlogistx.gui.PDFViewerPanel;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.text.PDFTextStripper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BooleanSupplier;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Headless tests for {@link PDFEditorPane}: the viewer's inserts and deletes
 * become undoable edits, the modified mark follows the saved state, the Edit
 * toggle gates Undo/Redo.
 */
public class PDFEditorPaneTest {

    private static final String PAGE_BREAK = "\n\n<div style=\"page-break-before: always\"></div>\n\n";
    private static final String THREE_PAGES =
            "# Page One\n\nfirst page text" + PAGE_BREAK +
            "# Page Two\n\nsecond page text" + PAGE_BREAK +
            "# Page Three\n\nthird page text";

    private static byte[] threePagePDF;
    private static byte[] extraPagePDF;
    private PDFEditorPane pane;
    private PDFViewerPanel viewer;

    @BeforeAll
    static void headless() throws Exception {
        System.setProperty("java.awt.headless", "true");
        threePagePDF = MDToPDF.mdToPDF(THREE_PAGES).toByteArray();
        extraPagePDF = MDToPDF.mdToPDF("# Extra\n\ninserted page text").toByteArray();
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
    }

    @AfterEach
    void tearDown() throws Exception {
        onEDT(() -> {
            viewer.close();
            return null;
        });
    }

    @Test
    void viewerToolbarMovesAboveTheEditRow() throws Exception {
        JToolBar viewRow = viewer.getToolbar();
        assertTrue(viewRow.isVisible());
        assertNotSame(viewer, viewRow.getParent(), "re-parented out of the viewer");
        assertTrue(SwingUtilities.isDescendingFrom(viewRow, pane));
        assertTrue(SwingUtilities.isDescendingFrom(pane.getEditToolbar(), pane));
        assertSame(viewRow.getParent(), pane.getEditToolbar().getParent(), "both rows share the stack");
        assertEquals("", pane.getDocumentTitle());
        assertFalse(pane.isEditable());
    }

    @Test
    void insertThenUndoRestoresPageCount() throws Exception {
        load(threePagePDF);
        List<PDPage> original = pages();
        onEDT(() -> pane.setEditable(true));
        AtomicInteger changes = new AtomicInteger();
        pane.addChangeListener(e -> changes.incrementAndGet());

        PDDocument extra = Loader.loadPDF(extraPagePDF);
        assertEquals(1, (int) onEDT(() -> viewer.insertDocument(extra, 1)));
        extra.close();
        assertEquals(4, viewer.getPageCount());
        assertTrue(pane.canUndo());
        assertFalse(pane.canRedo());
        assertEquals("Insert 1 page", pane.getEditModel().peekUndo().name());
        assertEquals("inserted page text", text(1));
        PDPage inserted = pages().get(1);
        assertTrue(changes.get() > 0);

        onEDT(pane::undo);
        assertEquals(3, viewer.getPageCount());
        assertEquals(original, pages(), "the original page objects in their order");
        assertTrue(pane.canRedo());

        onEDT(pane::redo);
        assertEquals(4, viewer.getPageCount());
        assertEquals(inserted, pages().get(1), "redo puts the same page object back");
        assertEquals(original.get(1), pages().get(2));
        assertEquals("inserted page text", text(1));
    }

    @Test
    void deleteThenUndoRestoresSamePageObjects() throws Exception {
        load(threePagePDF);
        List<PDPage> original = pages();
        onEDT(() -> pane.setEditable(true));

        assertEquals(2, (int) onEDT(() -> viewer.deletePages(new int[]{2, 0})));
        assertEquals(1, viewer.getPageCount());
        assertEquals(original.get(1), pages().get(0));
        assertEquals("Delete 2 pages", pane.getEditModel().peekUndo().name());

        onEDT(pane::undo);
        assertEquals(original, pages(), "exact order restored, lowest index first");
        assertEquals("first page text", text(0));
        assertEquals("third page text", text(2));

        onEDT(pane::redo);
        assertEquals(Arrays.asList(original.get(1)), pages());

        // typed selection goes through the same path
        onEDT(pane::undo);
        assertEquals(1, (int) onEDT(() -> viewer.deletePages("2")));
        assertEquals(Arrays.asList(original.get(0), original.get(2)), pages());
        onEDT(pane::undo);
        assertEquals(original, pages());
        assertThrows(IllegalArgumentException.class, () -> onEDT(() -> viewer.deletePages(new int[]{0, 1, 2})), "never the whole document");
        assertEquals(original, pages());
    }

    @Test
    void undoBackToSavedStateIsNotModified() throws Exception {
        load(threePagePDF);
        onEDT(() -> pane.setEditable(true));
        assertFalse(pane.isModified());
        assertEquals("Untitled", pane.getDocumentTitle());

        onEDT(() -> viewer.deletePages(new int[]{0}));
        assertTrue(pane.isModified());
        assertTrue(onEDT(() -> viewer.isModified()), "the viewer defers to the pane");
        assertEquals("Untitled *", pane.getDocumentTitle());
        onEDT(pane::undo);
        assertFalse(pane.isModified(), "back at the loaded state");
        onEDT(pane::redo);
        assertTrue(pane.isModified());

        File out = File.createTempFile("pdfeditor", ".pdf");
        out.deleteOnExit();
        onEDT(() -> {
            viewer.save(out);
            return null;
        });
        waitFor(() -> !pane.isModified(), 15000);
        assertTrue(out.length() > 0);
        assertEquals(out.getName(), pane.getDocumentTitle());
        assertTrue(pane.canUndo(), "saving keeps the history");
        onEDT(pane::undo);
        assertTrue(pane.isModified(), "before the saved state");
        assertEquals(out.getName() + " *", pane.getDocumentTitle());
        onEDT(pane::redo);
        assertFalse(pane.isModified());

        try (PDDocument saved = Loader.loadPDF(out)) {
            assertEquals(2, saved.getNumberOfPages(), "the file holds the edited page set");
        }

        // loading another document voids the history
        load(threePagePDF);
        assertFalse(pane.canUndo());
        assertFalse(pane.canRedo());
        assertFalse(pane.isModified());
    }

    @Test
    void editToggleGatesUndoRedoButtonsAndKeys() throws Exception {
        load(threePagePDF);
        JButton undo = button("Undo"), redo = button("Redo");
        assertFalse(undo.isEnabled());

        // edits are recorded while editing is off, but cannot be undone until it is on
        onEDT(() -> viewer.deletePages(new int[]{0}));
        assertEquals(2, viewer.getPageCount());
        assertFalse(pane.canUndo());
        assertFalse(undo.isEnabled());
        onEDT(pane::undo);
        assertEquals(2, viewer.getPageCount(), "undo is a no-op while editing is off");

        onEDT(() -> pane.setEditable(true));
        assertTrue(pane.isEditable());
        assertTrue(toggle().isSelected());
        assertTrue(undo.isEnabled());
        assertFalse(redo.isEnabled());
        assertTrue(undo.getToolTipText().startsWith("Undo: Delete 1 page"));

        // Ctrl+Z / Ctrl+Y are bound on the pane
        InputMap im = pane.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT);
        assertEquals("undo", im.get(KeyStroke.getKeyStroke(KeyEvent.VK_Z, InputEvent.CTRL_DOWN_MASK)));
        assertEquals("redo", im.get(KeyStroke.getKeyStroke(KeyEvent.VK_Y, InputEvent.CTRL_DOWN_MASK)));
        assertEquals("redo", im.get(KeyStroke.getKeyStroke(KeyEvent.VK_Z, InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK)));
        onEDT(() -> {
            pane.getActionMap().get("undo").actionPerformed(new ActionEvent(pane, ActionEvent.ACTION_PERFORMED, "undo"));
            return null;
        });
        assertEquals(3, viewer.getPageCount());
        assertFalse(undo.isEnabled());
        assertTrue(redo.isEnabled());
        assertTrue(redo.getToolTipText().startsWith("Redo: Delete 1 page"));
        onEDT(() -> {
            pane.getActionMap().get("redo").actionPerformed(new ActionEvent(pane, ActionEvent.ACTION_PERFORMED, "redo"));
            return null;
        });
        assertEquals(2, viewer.getPageCount());

        // the toolbar toggle drives setEditable
        onEDT(() -> {
            toggle().doClick();
            return null;
        });
        assertFalse(pane.isEditable());
        assertFalse(undo.isEnabled());
        assertFalse(pane.canUndo());
    }

    @Test
    void menuBarAndFrameAreBuildable() throws Exception {
        JMenuBar bar = onEDT(pane::createMenuBar);
        assertEquals(7, bar.getMenuCount());
        assertEquals("File", bar.getMenu(0).getText());
        assertEquals("Edit", bar.getMenu(1).getText());
        assertEquals("View", bar.getMenu(2).getText());
        assertEquals("Page", bar.getMenu(3).getText());
        assertEquals("Annotate", bar.getMenu(4).getText());
        assertEquals("Form", bar.getMenu(5).getText());
        assertEquals("Help", bar.getMenu(6).getText());
        assertThrows(NullPointerException.class, () -> new PDFEditorPane(null));
        assertThrows(NullPointerException.class, () -> pane.open(null));
        assertThrows(NullPointerException.class, () -> pane.addChangeListener(null));
    }

    // ---------------------------------------------------------------- helpers

    private void load(byte[] pdf) throws Exception {
        PDDocument doc = Loader.loadPDF(pdf);
        onEDT(() -> {
            viewer.setDocument(doc, true);
            layoutTree(pane);
            return null;
        });
    }

    /** The page objects in document order. */
    private List<PDPage> pages() throws Exception {
        return onEDT(() -> {
            synchronized (viewer.getDocumentLock()) {
                List<PDPage> ret = new ArrayList<>();
                for (PDPage p : viewer.getDocument().getPages())
                    ret.add(p);
                return ret;
            }
        });
    }

    /** The body text (second line) of a page. */
    private String text(int page) throws Exception {
        return onEDT(() -> {
            synchronized (viewer.getDocumentLock()) {
                PDFTextStripper s = new PDFTextStripper();
                s.setStartPage(page + 1);
                s.setEndPage(page + 1);
                String[] lines = s.getText(viewer.getDocument()).trim().split("\\R");
                return lines[lines.length - 1].trim();
            }
        });
    }

    private JButton button(String tooltipPrefix) {
        for (Component c : pane.getEditToolbar().getComponents())
            if (c instanceof JButton && ((JButton) c).getToolTipText() != null && ((JButton) c).getToolTipText().startsWith(tooltipPrefix))
                return (JButton) c;
        throw new IllegalStateException("no button " + tooltipPrefix);
    }

    private JToggleButton toggle() {
        for (Component c : pane.getEditToolbar().getComponents())
            if (c instanceof JToggleButton)
                return (JToggleButton) c;
        throw new IllegalStateException("no toggle");
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
