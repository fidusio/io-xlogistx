package io.xlogistx.editor.pdf;

import io.xlogistx.editor.pdf.AnnotationFactory.MarkupKind;
import io.xlogistx.editor.pdf.tools.FreeTextTool;
import io.xlogistx.editor.pdf.tools.SelectAnnotationTool;
import io.xlogistx.editor.pdf.tools.ShapeTool;
import io.xlogistx.gui.MDToPDF;
import io.xlogistx.gui.PDFToolContext;
import io.xlogistx.gui.PDFViewerPanel;
import io.xlogistx.gui.pdf.PageTransform;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotation;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationFreeText;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationHighlight;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationPopup;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationSquare;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationText;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationTextMarkup;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.swing.*;
import java.awt.*;
import java.awt.geom.Point2D;
import java.awt.geom.Rectangle2D;
import java.awt.image.BufferedImage;
import java.io.File;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.function.BooleanSupplier;

import static org.junit.jupiter.api.Assertions.*;

/** Tiers 2 and 3: markup, notes, text boxes, shapes, selection edits, all undoable and rendered. */
public class AnnotationEditTest {

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
    void highlightingASelectionAcrossPagesIsOneUndoStep() throws Exception {
        onEDT(() -> viewer.select(0, 0, 1, 8));
        List<Rectangle2D.Float> rects0 = onEDT(() -> viewer.getSelectionRects(0));
        assertFalse(rects0.isEmpty());
        waitFor(() -> viewer.getPageImage(0) != null, 10000);
        BufferedImage before = onEDT(() -> viewer.getPageImage(0));

        assertEquals(2, (int) onEDT(() -> pane.markSelection(MarkupKind.HIGHLIGHT)));
        assertFalse(viewer.hasSelection(), "the selection is consumed");
        assertEquals(1, pane.getEditModel().getUndoDepth(), "one step for two pages");
        assertTrue(pane.getEditModel().peekUndo() instanceof CompoundEdit);

        List<PDAnnotation> a0 = onEDT(() -> pane.getAnnotations(0)), a1 = onEDT(() -> pane.getAnnotations(1));
        assertEquals(1, a0.size());
        assertEquals(1, a1.size());
        assertTrue(onEDT(() -> pane.getAnnotations(2)).isEmpty());
        PDAnnotationTextMarkup h = (PDAnnotationTextMarkup) a0.get(0);
        assertTrue(h instanceof PDAnnotationHighlight);
        assertNotNull(h.getAppearance(), "/AP built");
        assertEquals(rects0.size() * 8, h.getQuadPoints().length);
        PDRectangle box = onEDT(() -> {
            synchronized (viewer.getDocumentLock()) {
                return viewer.getDocument().getPage(0).getCropBox();
            }
        });
        float[] q = h.getQuadPoints();
        for (int i = 0; i < q.length; i += 2)
            assertTrue(q[i] >= box.getLowerLeftX() - 0.01 && q[i] <= box.getUpperRightX() + 0.01
                    && q[i + 1] >= box.getLowerLeftY() - 0.01 && q[i + 1] <= box.getUpperRightY() + 0.01, "quad inside the page box");
        PageTransform t = onEDT(() -> {
            synchronized (viewer.getDocumentLock()) {
                return PageTransform.of(viewer.getDocument().getPage(0));
            }
        });
        Rectangle2D.Float back = t.toViewRect(h.getRectangle());
        Rectangle2D.Float union = rects0.get(0);
        for (Rectangle2D.Float r : rects0)
            union = (Rectangle2D.Float) union.createUnion(r);
        // PDFBox's highlight handler grows Rect by a quarter line height per side for its curved ends
        assertTrue(back.x <= union.x + 0.05 && back.getMaxX() >= union.getMaxX() - 0.05
                && back.y <= union.y + 0.05 && back.getMaxY() >= union.getMaxY() - 0.05, "Rect encloses the quads: " + back + " vs " + union);
        assertTrue(back.width < union.width + 20 && back.height < union.height + 20, "but not by much");
        assertEquals(rects0, onEDT(() -> {
            viewer.select(0, 0, 1, 8);
            List<Rectangle2D.Float> again = viewer.getSelectionRects(0);
            viewer.clearSelection();
            return again;
        }), "the quads came from the selection rectangles");

        waitFor(() -> viewer.getPageImage(0) != null && viewer.getPageImage(0) != before, 10000);
        assertTrue(yellowish(onEDT(() -> viewer.getPageImage(0)), rects0.get(0), viewer.getZoom()), "a highlighted glyph renders yellow");

        onEDT(pane::undo);
        assertTrue(onEDT(() -> pane.getAnnotations(0)).isEmpty());
        assertTrue(onEDT(() -> pane.getAnnotations(1)).isEmpty());
        assertFalse(pane.isModified());
        onEDT(pane::redo);
        assertEquals(1, onEDT(() -> pane.getAnnotations(1)).size());

        File out = File.createTempFile("pdfeditor-annot", ".pdf");
        out.deleteOnExit();
        onEDT(() -> {
            viewer.save(out);
            return null;
        });
        waitFor(() -> !pane.isModified(), 15000);
        try (PDDocument saved = Loader.loadPDF(out)) {
            assertEquals("Highlight", saved.getPage(0).getAnnotations().get(0).getSubtype());
            assertEquals("Highlight", saved.getPage(1).getAnnotations().get(0).getSubtype());
        }
    }

    @Test
    void underlineAndStrikeoutUseTheirOwnSubtypes() throws Exception {
        onEDT(() -> viewer.select(0, 0, 0, 5));
        assertEquals(1, (int) onEDT(() -> pane.markSelection(MarkupKind.UNDERLINE)));
        onEDT(() -> viewer.select(0, 0, 0, 5));
        assertEquals(1, (int) onEDT(() -> pane.markSelection(MarkupKind.STRIKEOUT)));
        List<PDAnnotation> a = onEDT(() -> pane.getAnnotations(0));
        assertEquals("Underline", a.get(0).getSubtype());
        assertEquals("StrikeOut", a.get(1).getSubtype());
        assertEquals(0, (int) onEDT(() -> pane.markSelection(MarkupKind.HIGHLIGHT)), "nothing selected");
    }

    @Test
    void noteAndPopupAreLinkedAndRemovedTogether() throws Exception {
        PDAnnotation note = onEDT(() -> pane.addNote(0, new Point2D.Float(100, 100), "hello"));
        assertTrue(note instanceof PDAnnotationText);
        PDAnnotationPopup popup = ((PDAnnotationText) note).getPopup();
        assertNotNull(popup);
        assertSame(note.getCOSObject(), popup.getParent().getCOSObject(), "linked both ways");
        assertEquals("hello", note.getContents());
        List<PDAnnotation> all = pageAnnotations(0);
        assertEquals(2, all.size(), "note + popup on the page");
        assertEquals(1, onEDT(() -> pane.getAnnotations(0)).size(), "the popup is not editable");
        PageTransform t = transform(0);
        Rectangle2D.Float b = t.toViewRect(note.getRectangle());
        assertEquals(100, b.x, 0.01);
        assertEquals(100, b.y, 0.01);
        assertTrue(b.width >= 15 && b.width <= 25, "PDFBox's note handler fixes the icon size: " + b.width);

        assertTrue(onEDT(() -> pane.removeAnnotation(0, note)));
        assertTrue(pageAnnotations(0).isEmpty());
        onEDT(pane::undo);
        assertEquals(2, pageAnnotations(0).size());
        assertEquals("Text", pageAnnotations(0).get(0).getSubtype());
        assertEquals("Popup", pageAnnotations(0).get(1).getSubtype());
        onEDT(pane::undo);
        assertTrue(pageAnnotations(0).isEmpty(), "the add is undone too");
    }

    @Test
    void textBoxRendersWithEmbeddedFontAndNonLatinText() throws Exception {
        FreeTextTool tool = (FreeTextTool) pane.getTool(PDFEditorPane.EditTool.TEXT_BOX);
        waitFor(() -> viewer.getPageImage(0) != null, 10000);
        BufferedImage before = onEDT(() -> viewer.getPageImage(0));
        Rectangle2D.Float box = new Rectangle2D.Float(100, 400, 200, 60);
        PDAnnotationFreeText ft = onEDT(() -> tool.addFreeText(ctx(), 0, box, "Ünïcödé text\nsecond line"));
        assertNotNull(ft);
        assertNotNull(ft.getAppearance());
        assertTrue(ft.getDefaultAppearance().startsWith("/Helv 12"));
        assertEquals("Add text box", pane.getEditModel().peekUndo().name());
        waitFor(() -> viewer.getPageImage(0) != null && viewer.getPageImage(0) != before, 10000);
        assertTrue(darkInside(onEDT(() -> viewer.getPageImage(0)), box, viewer.getZoom()), "text pixels inside the box");

        PDAnnotationFreeText cjk = onEDT(() -> tool.addFreeText(ctx(), 0, new Rectangle2D.Float(100, 500, 200, 40), "漢字 and more"));
        assertNotNull(cjk, "glyphs the font lacks become '?' instead of failing");
        assertNotNull(cjk.getAppearance());
    }

    @Test
    void shapesOnARotatedPageRoundTripAndMoveExactly() throws Exception {
        onEDT(() -> pane.rotatePages(new int[]{1}, 90));
        ShapeTool rect = (ShapeTool) pane.getTool(PDFEditorPane.EditTool.RECTANGLE);
        Rectangle2D.Float view = new Rectangle2D.Float(20, 30, 100, 50);
        PDAnnotation square = onEDT(() -> rect.addShape(ctx(), 1, view));
        assertTrue(square instanceof PDAnnotationSquare);
        PageTransform t = transform(1);
        Rectangle2D.Float back = t.toViewRect(square.getRectangle());
        // PDFBox's square handler grows the rectangle by half the 2 pt border on every side
        assertEquals(view.x, back.x, 1.01);
        assertEquals(view.y, back.y, 1.01);
        assertEquals(view.width, back.width, 2.01);
        assertEquals(view.height, back.height, 2.01);
        assertEquals(view.getCenterX(), back.getCenterX(), 0.01);
        assertEquals(view.getCenterY(), back.getCenterY(), 0.01);

        // select, move by (10, 20) pt in view space, resize, restyle, delete: each one undo step
        onEDT(() -> pane.selectAnnotation(1, square));
        assertEquals(PDFEditorPane.EditTool.SELECT, pane.getActiveTool());
        assertSame(square.getCOSObject(), pane.getSelectedAnnotation().getCOSObject());
        SelectAnnotationTool select = (SelectAnnotationTool) pane.getTool(PDFEditorPane.EditTool.SELECT);
        PDRectangle r0 = AnnotationFactory.copy(square.getRectangle());
        assertTrue(onEDT(() -> select.moveSelected(ctx(), 10, 20)));
        Rectangle2D.Float moved = t.toViewRect(square.getRectangle());
        assertEquals(back.x + 10, moved.x, 0.01);
        assertEquals(back.y + 20, moved.y, 0.01);
        assertEquals("Move rectangle", pane.getEditModel().peekUndo().name());
        onEDT(pane::undo);
        assertEquals(r0.getLowerLeftX(), square.getRectangle().getLowerLeftX(), 0.001);
        assertEquals(r0.getLowerLeftY(), square.getRectangle().getLowerLeftY(), 0.001);
        onEDT(pane::redo);

        onEDT(() -> pane.selectAnnotation(1, square));
        assertTrue(onEDT(() -> select.resizeSelected(ctx(), new Rectangle2D.Float(30, 50, 60, 20))));
        Rectangle2D.Float resized = t.toViewRect(square.getRectangle());
        assertEquals(60, resized.getCenterX() - 30 + 30, 2.01); // centre stays, size within the border growth
        assertEquals(60, resized.width, 2.01);
        assertEquals(20, resized.height, 2.01);

        AnnotationStyle blue = new AnnotationStyle(Color.BLUE, Color.YELLOW, 0.5f, 3f, 12f, null);
        assertTrue(onEDT(() -> pane.applyStyleToSelection(blue)));
        assertEquals(Color.BLUE, AnnotationFactory.awtColor(square.getColor()));
        assertEquals(Color.YELLOW, AnnotationFactory.awtColor(((PDAnnotationSquare) square).getInteriorColor()));
        assertEquals(0.5f, ((PDAnnotationSquare) square).getConstantOpacity(), 0.001);
        assertEquals(3f, ((PDAnnotationSquare) square).getBorderStyle().getWidth(), 0.001);
        assertEquals("Change properties", pane.getEditModel().peekUndo().name());
        onEDT(pane::undo);
        assertEquals(Color.RED.getRed(), AnnotationFactory.awtColor(square.getColor()).getRed(), 40);
        assertNull(square.getCOSObject().getDictionaryObject(COSName.IC), "fill removed again");
        assertEquals(2f, ((PDAnnotationSquare) square).getBorderStyle().getWidth(), 0.001);

        onEDT(() -> pane.selectAnnotation(1, square));
        assertTrue(onEDT(pane::deleteSelectedAnnotation));
        assertNull(pane.getSelectedAnnotation());
        assertTrue(onEDT(() -> pane.getAnnotations(1)).isEmpty());
        onEDT(pane::undo);
        assertEquals(1, onEDT(() -> pane.getAnnotations(1)).size());
    }

    @Test
    void selectionToolHitTestsTopmostAndDeselectsOnEmptySpace() throws Exception {
        ShapeTool rect = (ShapeTool) pane.getTool(PDFEditorPane.EditTool.RECTANGLE);
        PDAnnotation a = onEDT(() -> rect.addShape(ctx(), 0, new Rectangle2D.Float(50, 50, 100, 100)));
        PDAnnotation b = onEDT(() -> rect.addShape(ctx(), 0, new Rectangle2D.Float(100, 100, 100, 100)));
        PageTransform t = transform(0);
        List<PDAnnotation> all = onEDT(() -> pane.getAnnotations(0));
        assertSame(b.getCOSObject(), AnnotationGeometry.hitTest(all, t, new Point2D.Float(120, 120), 4).getCOSObject(), "topmost wins where they overlap");
        assertSame(a.getCOSObject(), AnnotationGeometry.hitTest(all, t, new Point2D.Float(60, 60), 4).getCOSObject());
        assertNull(AnnotationGeometry.hitTest(all, t, new Point2D.Float(400, 400), 4));
        assertEquals(AnnotationGeometry.Kind.BOX, AnnotationGeometry.kind(a));
        onEDT(() -> pane.selectAnnotation(0, a));
        onEDT(() -> pane.setActiveTool(null));
        assertNull(pane.getSelectedAnnotation(), "switching tools clears the selection");
        assertNull(pane.getActiveTool());
        assertEquals(PDFViewerPanel.Tool.PAN, viewer.getTool());
    }

    @Test
    void stylesAreRememberedPerKind() throws Exception {
        AnnotationStyle s = AnnotationStyle.DRAWING.withStrokeColor(Color.GREEN).withStrokeWidth(5f);
        onEDT(() -> pane.setStyle(EditorHost.StyleKey.DRAWING, s));
        assertEquals(s, pane.getStyle(EditorHost.StyleKey.DRAWING));
        ShapeTool ell = (ShapeTool) pane.getTool(PDFEditorPane.EditTool.ELLIPSE);
        PDAnnotation c = onEDT(() -> ell.addShape(ctx(), 0, new Rectangle2D.Float(10, 10, 40, 40)));
        assertEquals("Circle", c.getSubtype());
        assertEquals(Color.GREEN, AnnotationFactory.awtColor(c.getColor()));
        assertEquals(5f, ((org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationCircle) c).getBorderStyle().getWidth(), 0.001);
        assertEquals(AnnotationStyle.HIGHLIGHT, pane.getStyle(EditorHost.StyleKey.HIGHLIGHT));
    }

    // ---------------------------------------------------------------- helpers

    private PDFToolContext ctx() {
        return viewer.getToolContext();
    }

    private PageTransform transform(int page) throws Exception {
        return onEDT(() -> {
            synchronized (viewer.getDocumentLock()) {
                return PageTransform.of(viewer.getDocument().getPage(page));
            }
        });
    }

    private List<PDAnnotation> pageAnnotations(int page) throws Exception {
        return onEDT(() -> {
            synchronized (viewer.getDocumentLock()) {
                return new java.util.ArrayList<>(viewer.getDocument().getPage(page).getAnnotations());
            }
        });
    }

    private static boolean yellowish(BufferedImage img, Rectangle2D.Float viewRect, float zoom) {
        int x1 = Math.round(viewRect.x * zoom), x2 = Math.round((viewRect.x + viewRect.width) * zoom);
        int y1 = Math.round(viewRect.y * zoom), y2 = Math.round((viewRect.y + viewRect.height) * zoom);
        for (int y = Math.max(0, y1); y < Math.min(img.getHeight(), y2); y++)
            for (int x = Math.max(0, x1); x < Math.min(img.getWidth(), x2); x++) {
                int rgb = img.getRGB(x, y);
                int r = (rgb >> 16) & 0xff, b = rgb & 0xff;
                if (r > 200 && b < 120)
                    return true;
            }
        return false;
    }

    private static boolean darkInside(BufferedImage img, Rectangle2D.Float viewRect, float zoom) {
        int x1 = Math.round(viewRect.x * zoom) + 2, x2 = Math.round((viewRect.x + viewRect.width) * zoom) - 2;
        int y1 = Math.round(viewRect.y * zoom) + 2, y2 = Math.round((viewRect.y + viewRect.height) * zoom) - 2;
        for (int y = Math.max(0, y1); y < Math.min(img.getHeight(), y2); y++)
            for (int x = Math.max(0, x1); x < Math.min(img.getWidth(), x2); x++)
                if ((img.getRGB(x, y) & 0xff) < 100)
                    return true;
        return false;
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
