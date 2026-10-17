package io.xlogistx.editor.pdf;

import io.xlogistx.editor.pdf.tools.SelectAnnotationTool;
import io.xlogistx.gui.MDToPDF;
import io.xlogistx.gui.PDFToolContext;
import io.xlogistx.gui.PDFViewerPanel;
import io.xlogistx.gui.pdf.PageTransform;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotation;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.swing.Action;
import javax.swing.JComponent;
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;
import java.awt.Component;
import java.awt.Container;
import java.awt.Point;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.MouseEvent;
import java.awt.geom.Rectangle2D;
import java.awt.image.BufferedImage;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Headless tests of the editor's usability layer: the contextual edit row (the
 * style strip and the Delete / Properties group appear only when they apply),
 * the status line, the one-letter tool keys, the right-click menu and the
 * arrow-key nudge that merges a burst into one undo step.
 */
public class UsabilityTest {

    private static byte[] onePagePDF;
    private PDFEditorPane pane;
    private PDFViewerPanel viewer;

    @BeforeAll
    static void headless() throws Exception {
        System.setProperty("java.awt.headless", "true");
        onePagePDF = MDToPDF.mdToPDF("# One\n\nfirst page text with a few words to select").toByteArray();
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
        PDDocument doc = Loader.loadPDF(onePagePDF);
        onEDT(() -> {
            viewer.setDocument(doc, true);
            layoutTree(pane);
            pane.setEditable(true);
            pane.setActiveTool(PDFEditorPane.EditTool.SELECT); // what the Edit toggle does
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

    // ------------------------------------------------------------------ contextual toolbar

    @Test
    void stripAndSelectionGroupAppearOnlyWhenTheyApply() throws Exception {
        JComponent strip = pane.getStyleStrip(), selection = pane.getSelectionGroup();
        assertTrue(SwingUtilities.isDescendingFrom(strip, pane.getEditToolbar()));
        assertTrue(SwingUtilities.isDescendingFrom(selection, pane.getEditToolbar()));

        // Edit is on with the Select tool and nothing selected: no strip, no Delete / Properties
        assertEquals(PDFEditorPane.EditTool.SELECT, pane.getActiveTool());
        assertFalse(strip.isVisible(), "nothing styled is active or selected");
        assertFalse(selection.isVisible(), "nothing is selected");

        // a drawing tool shows colour, fill, opacity and width, not the text controls
        onEDT(() -> pane.setActiveTool(PDFEditorPane.EditTool.RECTANGLE));
        assertTrue(strip.isVisible());
        assertTrue(byTooltip(strip, "Colour").isVisible());
        assertTrue(byTooltip(strip, "Fill").isVisible());
        assertTrue(byTooltip(strip, "Opacity").isVisible());
        assertTrue(byTooltip(strip, "Stroke / border width").isVisible());
        assertFalse(byTooltip(strip, "Font size").isVisible());
        assertFalse(byTooltip(strip, "Bold text").isVisible());
        assertFalse(byTooltip(strip, "Text alignment").isVisible());

        // the text box tool adds the text controls
        onEDT(() -> pane.setActiveTool(PDFEditorPane.EditTool.TEXT_BOX));
        assertTrue(byTooltip(strip, "Font size").isVisible());
        assertTrue(byTooltip(strip, "Bold text").isVisible());
        assertTrue(byTooltip(strip, "Text alignment").isVisible());
        assertTrue(byTooltip(strip, "Font colour").isVisible(), "the colour swatch is the font colour");

        // the image tool keeps only the opacity
        onEDT(() -> pane.setActiveTool(PDFEditorPane.EditTool.IMAGE));
        assertTrue(strip.isVisible());
        assertTrue(byTooltip(strip, "Opacity").isVisible());
        assertFalse(byTooltip(strip, "Colour").isVisible());
        assertFalse(byTooltip(strip, "Fill").isVisible());
        assertFalse(byTooltip(strip, "Stroke / border width").isVisible());

        // selecting an annotation shows Delete / Properties and that annotation's strip
        PDAnnotation square = addSquare(new Rectangle2D.Float(100, 100, 80, 50));
        onEDT(() -> pane.selectAnnotation(0, square));
        assertTrue(selection.isVisible());
        assertTrue(byTooltip(selection, "Delete the selected").isVisible());
        assertTrue(byTooltip(selection, "Properties of the selected").isVisible());
        assertTrue(strip.isVisible());
        assertTrue(byTooltip(strip, "Fill").isVisible());
        assertFalse(byTooltip(strip, "Font size").isVisible());

        onEDT(() -> pane.clearAnnotationSelection());
        assertFalse(selection.isVisible());
        assertFalse(strip.isVisible(), "the Select tool with nothing selected has no style");

        // Edit off hides both
        onEDT(() -> pane.setActiveTool(PDFEditorPane.EditTool.TEXT_BOX));
        assertTrue(strip.isVisible());
        onEDT(() -> pane.setEditable(false));
        assertFalse(strip.isVisible());
        assertFalse(selection.isVisible());
    }

    // ------------------------------------------------------------------ status line

    @Test
    void statusLineFollowsToolAndSelection() throws Exception {
        assertTrue(SwingUtilities.isDescendingFrom(pane.getStatusBar(), pane));
        assertTrue(pane.getStatusHint().startsWith("Select:"), pane.getStatusHint());
        assertEquals("", pane.getStatusDetail());

        onEDT(() -> pane.setActiveTool(PDFEditorPane.EditTool.HIGHLIGHT));
        assertTrue(pane.getStatusHint().startsWith("Highlight:"), pane.getStatusHint());
        onEDT(() -> pane.setActiveTool(null));
        assertTrue(pane.getStatusHint().startsWith("Pan:"), pane.getStatusHint());
        onEDT(() -> pane.setEditable(false));
        assertTrue(pane.getStatusHint().startsWith("Viewing."), pane.getStatusHint());

        BufferedImage picture = new BufferedImage(40, 20, BufferedImage.TYPE_INT_RGB);
        PDAnnotation a = onEDT(() -> pane.addImage(0, new Rectangle2D.Float(100, 400, 120, 60), picture));
        assertTrue(pane.isEditable(), "an editing call turns editing on");
        onEDT(() -> pane.selectAnnotation(0, a));
        assertEquals("Selected: image 120 × 60 pt on page 1", pane.getStatusDetail());
        assertTrue(onEDT(() -> pane.rotateSelectedImage(90)));
        assertEquals("Selected: image 60 × 120 pt, turned 90° on page 1", pane.getStatusDetail());
        onEDT(() -> pane.clearAnnotationSelection());
        assertEquals("", pane.getStatusDetail());

        onEDT(() -> {
            viewer.close();
            return null;
        });
        assertTrue(pane.getStatusHint().startsWith("Open a PDF"), pane.getStatusHint());
    }

    // ------------------------------------------------------------------ tool keys

    @Test
    void oneLetterSelectsEachTool() throws Exception {
        assertEquals(PDFEditorPane.EditTool.values().length, PDFEditorPane.TOOL_KEYS.size(), "every tool has a key");
        assertEquals(PDFEditorPane.EditTool.values().length, new java.util.HashSet<>(PDFEditorPane.TOOL_KEYS.values()).size(), "no two tools share a key");
        for (PDFEditorPane.EditTool t : PDFEditorPane.EditTool.values()) {
            char key = PDFEditorPane.TOOL_KEYS.get(t);
            Object name = pane.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT).get(KeyStroke.getKeyStroke(key, 0));
            assertNotNull(name, "key " + key + " is bound");
            Action action = pane.getActionMap().get(name);
            assertNotNull(action);
            onEDT(() -> {
                action.actionPerformed(new ActionEvent(pane, ActionEvent.ACTION_PERFORMED, null));
                return null;
            });
            assertEquals(t, pane.getActiveTool(), "key " + key);
        }
        // the key is in the tooltip of the tool's button
        for (Component c : allOf(pane.getEditToolbar()))
            if (c instanceof javax.swing.JToggleButton && ((JComponent) c).getToolTipText() != null && ((JComponent) c).getToolTipText().startsWith("Text box:"))
                assertTrue(((JComponent) c).getToolTipText().endsWith("[T]"), ((JComponent) c).getToolTipText());
        // the letters work with Edit off too: they turn it on
        onEDT(() -> pane.setEditable(false));
        Action select = pane.getActionMap().get(pane.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT).get(KeyStroke.getKeyStroke('V', 0)));
        onEDT(() -> {
            select.actionPerformed(new ActionEvent(pane, ActionEvent.ACTION_PERFORMED, null));
            return null;
        });
        assertTrue(pane.isEditable());
        assertEquals(PDFEditorPane.EditTool.SELECT, pane.getActiveTool());
    }

    // ------------------------------------------------------------------ context menu

    @Test
    void rightClickMenuOffersWhatIsUnderThePointer() throws Exception {
        PDAnnotation square = addSquare(new Rectangle2D.Float(100, 100, 80, 50));
        onEDT(() -> pane.clearAnnotationSelection());
        Point onSquare = panelPoint(0, 140, 125), onEmpty = panelPoint(0, 400, 600);

        // over the square: it is selected and the menu names it
        JPopupMenu menu = onEDT(() -> viewer.buildContextMenu(mouse(onSquare)));
        List<String> items = labels(menu);
        assertSame(square.getCOSObject(), pane.getSelectedAnnotation().getCOSObject(), "the right click selects");
        assertTrue(items.contains("Properties of this rectangle..."), items.toString());
        assertTrue(items.contains("Delete this rectangle"), items.toString());
        assertFalse(items.stream().anyMatch(s -> s.startsWith("Edit the text")), "a rectangle has no text");
        assertFalse(items.stream().anyMatch(s -> s.startsWith("Rotate image")), "a rectangle is not a picture");
        assertTrue(items.contains("Copy"), "the viewer's own items follow");
        assertTrue(items.contains("Select all"));

        // over empty space without a text selection: Paste here (clipboard permitting) and the viewer's items
        onEDT(() -> pane.clearAnnotationSelection());
        items = labels(onEDT(() -> viewer.buildContextMenu(mouse(onEmpty))));
        assertEquals(java.util.Arrays.asList("Paste here", "Copy", "Select all", "Clear selection"), items);
        assertNull(pane.getSelectedAnnotation());

        // with page text selected: the markup and edit entries
        onEDT(() -> viewer.selectAll());
        assertTrue(viewer.hasSelection());
        items = labels(onEDT(() -> viewer.buildContextMenu(mouse(onEmpty))));
        assertTrue(items.contains("Highlight selected text"), items.toString());
        assertTrue(items.contains("Underline selected text"), items.toString());
        assertTrue(items.contains("Strike out selected text"), items.toString());
        assertTrue(items.contains("Edit selected text..."), items.toString());
        assertTrue(items.contains("Copy"));
        // the entries act: underline the selection
        JPopupMenu m = onEDT(() -> viewer.buildContextMenu(mouse(onEmpty)));
        int before = pane.getAnnotations(0).size();
        onEDT(() -> {
            itemNamed(m, "Underline selected text").doClick();
            return null;
        });
        assertEquals(before + 1, pane.getAnnotations(0).size());
        assertEquals("Underline", AnnotationFactory.subtype(pane.getAnnotations(0).get(before)));

        // a picture gets the rotate entries and Edit text, a note the Edit text entry
        BufferedImage picture = new BufferedImage(40, 20, BufferedImage.TYPE_INT_RGB);
        onEDT(() -> viewer.clearSelection());
        onEDT(() -> pane.addImage(0, new Rectangle2D.Float(300, 300, 120, 60), picture));
        Point onImage = panelPoint(0, 360, 330);
        items = labels(onEDT(() -> viewer.buildContextMenu(mouse(onImage))));
        assertTrue(items.contains("Rotate image clockwise"), items.toString());
        assertTrue(items.contains("Delete this image"), items.toString());
        PDAnnotation note = onEDT(() -> pane.addNote(0, new java.awt.geom.Point2D.Float(50, 500), "hello"));
        assertNotNull(note);
        Point onNote = panelPoint(0, 58, 508);
        items = labels(onEDT(() -> viewer.buildContextMenu(mouse(onNote))));
        assertTrue(items.contains("Edit the text of this note..."), items.toString());

        // editing off: only the viewer's items
        onEDT(() -> pane.setEditable(false));
        items = labels(onEDT(() -> viewer.buildContextMenu(mouse(onSquare))));
        assertEquals(java.util.Arrays.asList("Copy", "Select all", "Clear selection"), items);
    }

    // ------------------------------------------------------------------ nudge

    @Test
    void arrowKeysNudgeAndABurstIsOneUndoStep() throws Exception {
        PDAnnotation square = addSquare(new Rectangle2D.Float(100, 100, 80, 50));
        PageTransform t = transform(0);
        onEDT(() -> pane.selectAnnotation(0, square));
        Rectangle2D.Float start = t.toViewRect(square.getRectangle()); // the appearance pads the box by half the border
        int depth = pane.getEditModel().getUndoDepth();

        // three quick nudges: one undo step, moved by 3 pt right and 1 pt down (one with Shift: 10 pt)
        assertTrue(onEDT(() -> pane.nudgeSelectedAnnotation(1, 0)));
        assertTrue(onEDT(() -> pane.nudgeSelectedAnnotation(1, 0)));
        assertTrue(onEDT(() -> pane.nudgeSelectedAnnotation(1, 0)));
        assertTrue(onEDT(() -> pane.nudgeSelectedAnnotation(0, SelectAnnotationTool.NUDGE_BIG_PT)));
        assertEquals(depth + 1, pane.getEditModel().getUndoDepth(), "a burst is one undo step");
        assertEquals("Move rectangle", pane.getEditModel().peekUndo().name());
        Rectangle2D.Float moved = t.toViewRect(square.getRectangle());
        assertEquals(start.x + 3, moved.x, 0.01);
        assertEquals(start.y + 10, moved.y, 0.01);
        assertTrue(pane.isModified());

        // the keys themselves go through the Select tool and are consumed, so the view does not scroll
        SelectAnnotationTool select = (SelectAnnotationTool) pane.getTool(PDFEditorPane.EditTool.SELECT);
        KeyEvent left = new KeyEvent(pane, KeyEvent.KEY_PRESSED, System.currentTimeMillis(), 0, KeyEvent.VK_LEFT, KeyEvent.CHAR_UNDEFINED);
        onEDT(() -> {
            select.keyPressed(ctx(), left);
            return null;
        });
        assertTrue(left.isConsumed());
        assertEquals(start.x + 2, t.toViewRect(square.getRectangle()).x, 0.01);
        KeyEvent shiftUp = new KeyEvent(pane, KeyEvent.KEY_PRESSED, System.currentTimeMillis(), KeyEvent.SHIFT_DOWN_MASK, KeyEvent.VK_UP, KeyEvent.CHAR_UNDEFINED);
        onEDT(() -> {
            select.keyPressed(ctx(), shiftUp);
            return null;
        });
        assertEquals(start.y, t.toViewRect(square.getRectangle()).y, 0.01);
        assertEquals(depth + 1, pane.getEditModel().getUndoDepth(), "still the same burst");

        // one undo puts it all back
        onEDT(pane::undo);
        Rectangle2D.Float back = t.toViewRect(square.getRectangle());
        assertEquals(start.x, back.x, 0.01);
        assertEquals(start.y, back.y, 0.01);
        assertEquals(depth, pane.getEditModel().getUndoDepth());

        // after a pause the next nudge is a new step
        onEDT(() -> pane.selectAnnotation(0, square));
        assertTrue(onEDT(() -> pane.nudgeSelectedAnnotation(1, 0)));
        Thread.sleep(SelectAnnotationTool.NUDGE_BURST_MS + 100);
        assertTrue(onEDT(() -> pane.nudgeSelectedAnnotation(1, 0)));
        assertEquals(depth + 2, pane.getEditModel().getUndoDepth());

        // without a selection the arrows are left alone (they scroll)
        onEDT(() -> pane.clearAnnotationSelection());
        KeyEvent down = new KeyEvent(pane, KeyEvent.KEY_PRESSED, System.currentTimeMillis(), 0, KeyEvent.VK_DOWN, KeyEvent.CHAR_UNDEFINED);
        onEDT(() -> {
            select.keyPressed(ctx(), down);
            return null;
        });
        assertFalse(down.isConsumed());
        assertFalse(onEDT(() -> pane.nudgeSelectedAnnotation(1, 0)));
    }

    // ------------------------------------------------------------------ helpers

    private PDAnnotation addSquare(Rectangle2D viewRect) throws Exception {
        return onEDT(() -> {
            synchronized (viewer.getDocumentLock()) {
                PDDocument doc = viewer.getDocument();
                PDPage page = doc.getPage(0);
                PDAnnotation a = AnnotationFactory.shape(doc, page, PageTransform.of(page), false, viewRect, AnnotationStyle.DRAWING);
                assertTrue(pane.addAnnotation(0, a));
                return a;
            }
        });
    }

    private PageTransform transform(int page) throws Exception {
        return onEDT(() -> {
            synchronized (viewer.getDocumentLock()) {
                return PageTransform.of(viewer.getDocument().getPage(page));
            }
        });
    }

    private PDFToolContext ctx() {
        return viewer.getToolContext();
    }

    /** A pages-panel point for a view-space point (points, top-left origin) of a page. */
    private Point panelPoint(int page, float x, float y) throws Exception {
        return onEDT(() -> ctx().toPanelPoint(page, new java.awt.geom.Point2D.Float(x, y)));
    }

    private MouseEvent mouse(Point p) {
        return new MouseEvent(viewer, MouseEvent.MOUSE_RELEASED, System.currentTimeMillis(), 0, p.x, p.y, 1, true, MouseEvent.BUTTON3);
    }

    private static List<String> labels(JPopupMenu menu) {
        List<String> r = new ArrayList<>();
        for (Component c : menu.getComponents())
            if (c instanceof JMenuItem)
                r.add(((JMenuItem) c).getText());
        return r;
    }

    private static JMenuItem itemNamed(JPopupMenu menu, String text) {
        for (Component c : menu.getComponents())
            if (c instanceof JMenuItem && text.equals(((JMenuItem) c).getText()))
                return (JMenuItem) c;
        throw new AssertionError("no item " + text);
    }

    private static JComponent byTooltip(Container in, String prefix) {
        for (Component c : allOf(in))
            if (c instanceof JComponent && ((JComponent) c).getToolTipText() != null && ((JComponent) c).getToolTipText().startsWith(prefix))
                return (JComponent) c;
        throw new AssertionError("no control with tooltip " + prefix);
    }

    private static List<Component> allOf(Container c) {
        List<Component> r = new ArrayList<>();
        for (Component child : c.getComponents()) {
            r.add(child);
            if (child instanceof Container)
                r.addAll(allOf((Container) child));
        }
        return r;
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
}
