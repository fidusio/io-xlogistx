package io.xlogistx.editor.pdf;

import io.xlogistx.editor.pdf.EditorHost.StyleKey;
import io.xlogistx.editor.pdf.PDFEditorPane.EditTool;
import io.xlogistx.editor.pdf.tools.FreeTextTool;
import io.xlogistx.editor.pdf.tools.InPlaceTextEditor;
import io.xlogistx.editor.pdf.tools.SelectAnnotationTool;
import io.xlogistx.gui.pdf.PDFToolContext;
import io.xlogistx.gui.pdf.PDFViewerPanel;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotation;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationFreeText;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import java.awt.Component;
import java.awt.Container;
import java.awt.Point;
import java.awt.Rectangle;
import java.awt.event.MouseEvent;
import java.awt.geom.Rectangle2D;
import java.io.ByteArrayOutputStream;
import java.util.concurrent.Callable;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Headless tests of typing into text boxes on the page: a drag with the Text
 * box tool opens an editor over the box and the box is added on commit; blank
 * or cancelled edits add nothing, a tool switch commits; an existing box is
 * edited in place as one undo step; the editor follows the zoom; undo commits
 * the edit first.
 */
public class InPlaceTextTest {

    private static byte[] onePagePDF;
    private PDFEditorPane pane;
    private PDFViewerPanel viewer;
    private FreeTextTool textTool;
    private SelectAnnotationTool select;

    @BeforeAll
    static void headless() throws Exception {
        System.setProperty("java.awt.headless", "true");
        try (PDDocument doc = new PDDocument()) {
            doc.addPage(new PDPage(PDRectangle.A4));
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            doc.save(out);
            onePagePDF = out.toByteArray();
        }
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
            pane.setActiveTool(EditTool.SELECT);
            return null;
        });
        textTool = (FreeTextTool) pane.getTool(EditTool.TEXT_BOX);
        select = (SelectAnnotationTool) pane.getTool(EditTool.SELECT);
    }

    @AfterEach
    void tearDown() throws Exception {
        onEDT(() -> {
            viewer.close();
            return null;
        });
    }

    @Test
    void typingIntoANewBoxAddsItOnCommit() throws Exception {
        onEDT(() -> pane.setActiveTool(EditTool.TEXT_BOX));
        Point p1 = panelPoint(0, 100, 100), p2 = panelPoint(0, 260, 160);
        onEDT(() -> {
            textTool.pressed(ctx(), mouse(MouseEvent.MOUSE_PRESSED, p1));
            textTool.dragged(ctx(), mouse(MouseEvent.MOUSE_DRAGGED, p2));
            textTool.released(ctx(), mouse(MouseEvent.MOUSE_RELEASED, p2));
            return null;
        });
        InPlaceTextEditor editor = pane.getInPlaceEditor();
        assertNotNull(editor, "a drag opens the editor instead of a dialog");
        JTextArea area = editor.getTextArea();
        assertSame(area, ctx().overlay());
        assertTrue(SwingUtilities.isDescendingFrom(area, viewer), "hosted over the page");
        assertEquals(0, count(0), "nothing is added until the text is committed");
        float zoom = viewer.getZoom();
        Rectangle b = area.getBounds();
        assertEquals(Math.round(100 * zoom), b.x);
        assertEquals(Math.round(100 * zoom), b.y);
        assertEquals(Math.round(160 * zoom), b.width, 1);
        assertEquals(Math.round(60 * zoom), b.height, 1);
        assertEquals(pane.style(StyleKey.TEXT).getFontSize() * zoom, area.getFont().getSize2D(), 0.01, "the font follows the style and the zoom");
        assertEquals("", editor.getText());

        onEDT(() -> {
            area.setText("hello world");
            editor.commit();
            return null;
        });
        assertEquals(1, count(0));
        PDAnnotation a = pane.getAnnotations(0).get(0);
        assertEquals("FreeText", AnnotationFactory.subtype(a));
        assertEquals("hello world", a.getContents());
        Rectangle2D.Float r = transform(0).toViewRect(a.getRectangle());
        assertEquals(100, r.x, 0.6);
        assertEquals(160, r.width, 0.6);
        assertEquals("Add text box", pane.getEditModel().peekUndo().name());
        assertEquals(EditTool.SELECT, pane.getActiveTool(), "the new box is handed to the Select tool");
        assertSame(a.getCOSObject(), pane.getSelectedAnnotation().getCOSObject());
        assertNull(ctx().overlay());
        assertNull(pane.getInPlaceEditor());
        assertFalse(editor.isActive());
    }

    @Test
    void blankOrCancelledNewBoxAddsNothingAndAToolSwitchCommits() throws Exception {
        onEDT(() -> pane.setActiveTool(EditTool.TEXT_BOX));
        Rectangle2D.Float box = new Rectangle2D.Float(50, 50, 160, 40);

        InPlaceTextEditor blank = onEDT(() -> textTool.startTyping(ctx(), 0, box));
        onEDT(() -> {
            blank.getTextArea().setText("   ");
            blank.commit();
            return null;
        });
        assertEquals(0, count(0), "blank text adds no box");
        assertEquals(EditTool.TEXT_BOX, pane.getActiveTool());

        InPlaceTextEditor cancelled = onEDT(() -> textTool.startTyping(ctx(), 0, box));
        onEDT(() -> {
            cancelled.getTextArea().setText("typed");
            cancelled.cancel();
            return null;
        });
        assertEquals(0, count(0), "a cancelled box is dropped");

        InPlaceTextEditor escaped = onEDT(() -> textTool.startTyping(ctx(), 0, box));
        onEDT(() -> {
            escaped.getTextArea().setText("lost");
            textTool.cancel(ctx()); // what Esc does
            return null;
        });
        assertEquals(0, count(0));
        assertFalse(escaped.isActive());

        InPlaceTextEditor kept = onEDT(() -> textTool.startTyping(ctx(), 0, box));
        onEDT(() -> {
            kept.getTextArea().setText("kept");
            pane.setActiveTool(EditTool.RECTANGLE);
            return null;
        });
        assertEquals(1, count(0), "switching tools keeps what was typed");
        assertEquals("kept", pane.getAnnotations(0).get(0).getContents());
        assertEquals(EditTool.RECTANGLE, pane.getActiveTool(), "and does not steal the tool back");
        assertNull(pane.getInPlaceEditor());

        // a second box started while one is open commits the first
        onEDT(() -> pane.setActiveTool(EditTool.TEXT_BOX));
        InPlaceTextEditor first = onEDT(() -> textTool.startTyping(ctx(), 0, box));
        onEDT(() -> {
            first.getTextArea().setText("one");
            return null;
        });
        InPlaceTextEditor second = onEDT(() -> textTool.startTyping(ctx(), 0, new Rectangle2D.Float(50, 150, 160, 40)));
        assertFalse(first.isActive());
        assertEquals(2, count(0));
        assertTrue(second.isActive());
        onEDT(() -> {
            second.cancel();
            return null;
        });
    }

    @Test
    void anExistingBoxIsEditedInPlaceAsOneUndoStep() throws Exception {
        PDAnnotationFreeText box = onEDT(() -> textTool.addFreeText(ctx(), 0, new Rectangle2D.Float(100, 300, 200, 50), "first"));
        PDAnnotationFreeText other = onEDT(() -> textTool.addFreeText(ctx(), 0, new Rectangle2D.Float(100, 400, 200, 50), "other"));
        onEDT(() -> pane.selectAnnotation(0, box));
        int depth = pane.getEditModel().getUndoDepth();

        assertTrue(onEDT(() -> select.editText(ctx())), "a text box is edited on the page, not in a dialog");
        InPlaceTextEditor editor = pane.getInPlaceEditor();
        assertNotNull(editor);
        assertSame(box, editor.getBox());
        assertEquals("first", editor.getText());
        assertTrue(onEDT(() -> select.editText(ctx())), "asking again keeps the open editor");
        assertSame(editor, pane.getInPlaceEditor());
        onEDT(() -> {
            editor.getTextArea().setText("second");
            editor.commit();
            return null;
        });
        assertEquals("second", box.getContents());
        assertEquals(depth + 1, pane.getEditModel().getUndoDepth());
        assertEquals("Edit text", pane.getEditModel().peekUndo().name());
        assertSame(box.getCOSObject(), pane.getSelectedAnnotation().getCOSObject(), "still selected");
        assertNull(ctx().overlay());

        // the same text again: no edit
        assertTrue(onEDT(() -> select.editText(ctx())));
        onEDT(() -> {
            pane.getInPlaceEditor().commit();
            return null;
        });
        assertEquals(depth + 1, pane.getEditModel().getUndoDepth());

        // cancel keeps the text
        assertTrue(onEDT(() -> select.editText(ctx())));
        onEDT(() -> {
            pane.getInPlaceEditor().getTextArea().setText("zzz");
            select.cancel(ctx());
            return null;
        });
        assertEquals("second", box.getContents());
        assertEquals(depth + 1, pane.getEditModel().getUndoDepth());

        // selecting another annotation commits what was typed
        assertTrue(onEDT(() -> select.editText(ctx())));
        onEDT(() -> {
            pane.getInPlaceEditor().getTextArea().setText("third");
            pane.selectAnnotation(0, other);
            return null;
        });
        assertEquals("third", box.getContents());
        assertNull(pane.getInPlaceEditor());
        assertSame(other.getCOSObject(), pane.getSelectedAnnotation().getCOSObject());

        // undo walks back
        onEDT(pane::undo);
        assertEquals("second", box.getContents());
        onEDT(pane::undo);
        assertEquals("first", box.getContents());
    }

    @Test
    void theEditorFollowsTheZoomAndUndoCommitsFirst() throws Exception {
        PDAnnotationFreeText box = onEDT(() -> textTool.addFreeText(ctx(), 0, new Rectangle2D.Float(100, 100, 200, 60), "zoom me"));
        onEDT(() -> pane.selectAnnotation(0, box));
        assertTrue(onEDT(() -> select.editText(ctx())));
        JTextArea area = pane.getInPlaceEditor().getTextArea();
        float z1 = viewer.getZoom();
        Rectangle b1 = area.getBounds();
        float f1 = area.getFont().getSize2D();
        assertEquals(Math.round(100 * z1), b1.x);
        assertEquals(Math.round(200 * z1), b1.width, 1);

        onEDT(() -> viewer.setZoom(z1 * 2));
        onEDT(() -> null); // let the resize event through
        Rectangle b2 = area.getBounds();
        assertEquals(Math.round(200 * z1), b2.x, 1);
        assertEquals(b1.width * 2, b2.width, 2);
        assertEquals(f1 * 2, area.getFont().getSize2D(), 0.05, "the font scales with the zoom");

        onEDT(() -> {
            area.setText("changed");
            pane.undo();
            return null;
        });
        assertNull(pane.getInPlaceEditor(), "undo ends the edit");
        assertEquals("zoom me", box.getContents(), "the committed change is what was undone");
        assertTrue(pane.canRedo());
        onEDT(pane::redo);
        assertEquals("changed", box.getContents());
    }

    // ------------------------------------------------------------------ helpers

    private int count(int page) throws Exception {
        return onEDT(() -> pane.getAnnotations(page).size());
    }

    private io.xlogistx.gui.pdf.PageTransform transform(int page) throws Exception {
        return onEDT(() -> {
            synchronized (viewer.getDocumentLock()) {
                return io.xlogistx.gui.pdf.PageTransform.of(viewer.getDocument().getPage(page));
            }
        });
    }

    private PDFToolContext ctx() {
        return viewer.getToolContext();
    }

    private Point panelPoint(int page, float x, float y) throws Exception {
        return onEDT(() -> ctx().toPanelPoint(page, new java.awt.geom.Point2D.Float(x, y)));
    }

    private MouseEvent mouse(int id, Point p) {
        return new MouseEvent(viewer, id, System.currentTimeMillis(), id == MouseEvent.MOUSE_DRAGGED ? MouseEvent.BUTTON1_DOWN_MASK : 0,
                p.x, p.y, 1, false, MouseEvent.BUTTON1);
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
}
