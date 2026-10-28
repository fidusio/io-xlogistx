package io.xlogistx.editor.pdf;

import io.xlogistx.editor.pdf.tools.ImageTool;
import io.xlogistx.editor.pdf.tools.SelectAnnotationTool;
import io.xlogistx.gui.MDToPDF;
import io.xlogistx.gui.pdf.PDFToolContext;
import io.xlogistx.gui.pdf.PDFViewerPanel;
import io.xlogistx.gui.pdf.PageTransform;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotation;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationRubberStamp;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.imageio.ImageIO;
import io.xlogistx.gui.IconUtil;
import javax.swing.Icon;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.SwingUtilities;
import java.awt.Color;
import java.awt.Component;
import java.awt.Container;
import java.awt.Cursor;
import java.awt.Graphics2D;
import java.awt.Point;
import java.awt.event.InputEvent;
import java.awt.event.MouseEvent;
import java.awt.geom.Point2D;
import java.awt.geom.Rectangle2D;
import java.awt.image.BufferedImage;
import java.io.File;
import java.nio.file.Files;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.function.BooleanSupplier;

import static org.junit.jupiter.api.Assertions.*;

/** Image stamps: a picture placed as a Stamp annotation, fitted, rendered, resized, restyled, undone, saved. */
public class ImageStampTest {

    private static final String PAGE_BREAK = "\n\n<div style=\"page-break-before: always\"></div>\n\n";
    private static byte[] twoPagePDF;
    private PDFEditorPane pane;
    private PDFViewerPanel viewer;

    @BeforeAll
    static void headless() throws Exception {
        System.setProperty("java.awt.headless", "true");
        twoPagePDF = MDToPDF.mdToPDF("# One\n\nfirst page text" + PAGE_BREAK + "# Two\n\nsecond page text").toByteArray();
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
        PDDocument doc = Loader.loadPDF(twoPagePDF);
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
    void pictureIsFittedRenderedResizedAndUndone() throws Exception {
        waitFor(() -> viewer.getPageImage(0) != null, 10000);
        BufferedImage picture = solid(40, 20, Color.RED);
        Rectangle2D.Float box = new Rectangle2D.Float(100, 400, 120, 90);
        PDAnnotation a = onEDT(() -> pane.addImage(0, box, picture));
        assertTrue(a instanceof PDAnnotationRubberStamp);
        assertTrue(ImageStamp.isImage(a));
        assertEquals("Stamp", a.getSubtype());
        assertEquals(ImageStamp.NAME, ((PDAnnotationRubberStamp) a).getName());
        assertTrue(a.isPrinted());
        assertEquals("Add image", pane.getEditModel().peekUndo().name());
        PageTransform t = transform(0);
        Rectangle2D.Float bounds = t.toViewRect(a.getRectangle());
        assertEquals(100, bounds.x, 0.01);
        assertEquals(400, bounds.y, 0.01);
        assertEquals(120, bounds.width, 0.01, "the box's width is kept");
        assertEquals(60, bounds.height, 0.01, "the height follows the picture's 2:1 aspect");
        assertEquals(2f, ImageStamp.aspect(a), 0.001);
        PDImageXObject embedded = ImageStamp.imageOf(a);
        assertEquals(40, embedded.getWidth());
        assertEquals(20, embedded.getHeight());

        waitFor(() -> reddish(viewer.getPageImage(0), bounds, viewer.getZoom()), 10000);
        assertFalse(reddish(onEDT(() -> viewer.getPageImage(0)), new Rectangle2D.Float(100, 470, 120, 30), viewer.getZoom()),
                "nothing drawn below the fitted box");

        // resize with the selection tool: same picture, new rectangle, re-rendered
        onEDT(() -> pane.selectAnnotation(0, a));
        SelectAnnotationTool select = (SelectAnnotationTool) pane.getTool(PDFEditorPane.EditTool.SELECT);
        assertTrue(onEDT(() -> select.resizeSelected(ctx(), new Rectangle2D.Float(100, 400, 240, 120))));
        assertEquals("Resize image", pane.getEditModel().peekUndo().name());
        Rectangle2D.Float grown = t.toViewRect(a.getRectangle());
        assertEquals(240, grown.width, 0.01);
        assertEquals(120, grown.height, 0.01);
        assertSame(embedded.getCOSObject(), ImageStamp.imageOf(a).getCOSObject(), "resize reuses the embedded picture");
        Rectangle2D.Float rightHalf = new Rectangle2D.Float(230, 400, 110, 120);
        waitFor(() -> reddish(viewer.getPageImage(0), rightHalf, viewer.getZoom()), 10000);

        onEDT(pane::undo);
        Rectangle2D.Float back = t.toViewRect(a.getRectangle());
        assertEquals(120, back.width, 0.01);
        assertEquals(60, back.height, 0.01);
        waitFor(() -> !reddish(viewer.getPageImage(0), rightHalf, viewer.getZoom()), 10000);

        // opacity is the stamp's only style; colours are not written
        onEDT(() -> pane.selectAnnotation(0, a));
        assertTrue(onEDT(() -> pane.applyStyleToSelection(AnnotationStyle.IMAGE.withOpacity(0.4f).withStrokeColor(Color.GREEN))));
        assertEquals(0.4f, ((PDAnnotationRubberStamp) a).getConstantOpacity(), 0.001);
        assertNull(a.getColor(), "no colour on an image stamp");
        assertNull(((PDAnnotationRubberStamp) a).getBorderStyle(), "no border on an image stamp");
        waitFor(() -> {
            BufferedImage img = viewer.getPageImage(0);
            return img != null && pinkish(img, bounds, viewer.getZoom());
        }, 10000);
        onEDT(pane::undo);
        assertEquals(1f, ((PDAnnotationRubberStamp) a).getConstantOpacity(), 0.001);

        onEDT(() -> pane.selectAnnotation(0, a));
        assertTrue(onEDT(pane::deleteSelectedAnnotation));
        assertTrue(onEDT(() -> pane.getAnnotations(0)).isEmpty());
        onEDT(pane::undo);
        assertEquals(1, onEDT(() -> pane.getAnnotations(0)).size());
    }

    @Test
    void imageFileAtItsOwnSizeSurvivesSaveAndReload() throws Exception {
        File png = Files.createTempFile("stamp", ".png").toFile();
        png.deleteOnExit();
        assertTrue(ImageIO.write(solid(40, 20, Color.BLUE), "png", png));
        PDAnnotation a = onEDT(() -> pane.addImage(1, null, png));
        assertNotNull(a);
        PageTransform t = transform(1);
        Rectangle2D.Float bounds = t.toViewRect(a.getRectangle());
        assertEquals(ImageTool.MARGIN_PT, bounds.x, 0.01);
        assertEquals(ImageTool.MARGIN_PT, bounds.y, 0.01);
        assertEquals(40, bounds.width, 0.01, "pixels become points");
        assertEquals(20, bounds.height, 0.01);

        File out = Files.createTempFile("stamped", ".pdf").toFile();
        out.deleteOnExit();
        onEDT(() -> {
            viewer.save(out);
            return null;
        });
        waitFor(() -> !pane.getEditModel().isModified(), 10000);
        try (PDDocument saved = Loader.loadPDF(out)) {
            List<PDAnnotation> annots = saved.getPage(1).getAnnotations();
            assertEquals(1, annots.size());
            PDAnnotation s = annots.get(0);
            assertTrue(s instanceof PDAnnotationRubberStamp, s.getClass().getName());
            assertTrue(ImageStamp.isImage(s), "the picture travels in the appearance");
            assertEquals(40, ImageStamp.imageOf(s).getWidth());
            assertEquals(2f, ImageStamp.aspect(s), 0.001);
            assertTrue(saved.getPage(0).getAnnotations().isEmpty());
        }
    }

    @Test
    void mouseGrabsAPictureWithEitherToolAndPansOnEmptySpace() throws Exception {
        PDAnnotation a = onEDT(() -> pane.addImage(0, new Rectangle2D.Float(100, 100, 120, 60), solid(40, 20, Color.RED)));
        PageTransform t = transform(0);
        JComponent pages = onEDT(() -> viewer.getToolContext().owner());
        Point inside = onEDT(() -> viewer.getToolContext().toPanelPoint(0, new Point2D.Float(150, 130)));

        // the Image tool is still active after an insert: a press on the picture hands over to Select and the drag moves it
        onEDT(() -> pane.setActiveTool(PDFEditorPane.EditTool.IMAGE));
        Rectangle2D.Float before = t.toViewRect(a.getRectangle());
        mouse(pages, MouseEvent.MOUSE_PRESSED, inside.x, inside.y, 0);
        assertEquals(PDFEditorPane.EditTool.SELECT, pane.getActiveTool(), "the Image tool handed over");
        assertSame(a.getCOSObject(), pane.getSelectedAnnotation().getCOSObject());
        mouse(pages, MouseEvent.MOUSE_DRAGGED, inside.x + 20, inside.y + 30, 0);
        mouse(pages, MouseEvent.MOUSE_DRAGGED, inside.x + 40, inside.y + 60, 0);
        mouse(pages, MouseEvent.MOUSE_RELEASED, inside.x + 40, inside.y + 60, 0);
        Rectangle2D.Float moved = t.toViewRect(a.getRectangle());
        float z = viewer.getZoom();
        assertEquals(before.x + 40 / z, moved.x, 0.5);
        assertEquals(before.y + 60 / z, moved.y, 0.5);
        assertEquals("Move image", pane.getEditModel().peekUndo().name());

        // hover: move cursor over the picture, a resize cursor over its SE handle, default elsewhere
        Point corner = onEDT(() -> viewer.getToolContext().toPanelPoint(0, new Point2D.Float(moved.x + moved.width, moved.y + moved.height)));
        mouse(pages, MouseEvent.MOUSE_MOVED, corner.x, corner.y, 0);
        assertEquals(Cursor.SE_RESIZE_CURSOR, onEDT(pages::getCursor).getType());
        Point centre = onEDT(() -> viewer.getToolContext().toPanelPoint(0, new Point2D.Float((float) moved.getCenterX(), (float) moved.getCenterY())));
        mouse(pages, MouseEvent.MOUSE_MOVED, centre.x, centre.y, 0);
        assertEquals(Cursor.MOVE_CURSOR, onEDT(pages::getCursor).getType());
        Point empty = onEDT(() -> viewer.getToolContext().toPanelPoint(0, new Point2D.Float(300, 700)));
        mouse(pages, MouseEvent.MOUSE_MOVED, empty.x, empty.y, 0);
        assertEquals(Cursor.DEFAULT_CURSOR, onEDT(pages::getCursor).getType());

        // a corner drag keeps the 2:1 aspect; with Shift it stretches freely
        mouse(pages, MouseEvent.MOUSE_PRESSED, corner.x, corner.y, 0);
        mouse(pages, MouseEvent.MOUSE_DRAGGED, corner.x + 60, corner.y, 0);
        mouse(pages, MouseEvent.MOUSE_RELEASED, corner.x + 60, corner.y, 0);
        Rectangle2D.Float grown = t.toViewRect(a.getRectangle());
        assertEquals("Resize image", pane.getEditModel().peekUndo().name());
        assertEquals(moved.width + 60 / z, grown.width, 0.5);
        assertEquals(grown.width / 2, grown.height, 0.5, "aspect kept");
        assertEquals(moved.x, grown.x, 0.01, "NW corner fixed");
        Point corner2 = onEDT(() -> viewer.getToolContext().toPanelPoint(0, new Point2D.Float(grown.x + grown.width, grown.y + grown.height)));
        mouse(pages, MouseEvent.MOUSE_PRESSED, corner2.x, corner2.y, 0); // Shift+press is the viewer's zoom marquee: Shift goes down during the drag
        mouse(pages, MouseEvent.MOUSE_DRAGGED, corner2.x, corner2.y + 40, InputEvent.SHIFT_DOWN_MASK);
        mouse(pages, MouseEvent.MOUSE_RELEASED, corner2.x, corner2.y + 40, InputEvent.SHIFT_DOWN_MASK);
        Rectangle2D.Float stretched = t.toViewRect(a.getRectangle());
        assertEquals(grown.width, stretched.width, 0.5);
        assertEquals(grown.height + 40 / z, stretched.height, 0.5, "Shift stretches");

        // a drag on empty space pans instead of deselecting and doing nothing
        int y0 = onEDT(() -> viewer.getToolContext().viewport().getViewPosition().y);
        mouse(pages, MouseEvent.MOUSE_PRESSED, empty.x, empty.y, 0);
        mouse(pages, MouseEvent.MOUSE_DRAGGED, empty.x, empty.y - 100, 0);
        mouse(pages, MouseEvent.MOUSE_RELEASED, empty.x, empty.y - 100, 0);
        assertNull(pane.getSelectedAnnotation(), "empty space deselects");
        assertEquals(y0 + 100, onEDT(() -> viewer.getToolContext().viewport().getViewPosition().y), "panned up by the drag");
        assertEquals("Resize image", pane.getEditModel().peekUndo().name(), "no edit recorded by the pan");
    }

    @Test
    void placementKeepsTheAspectAndStaysOnThePage() {
        // a box: fitted by width, then by height when the box is too flat
        Rectangle2D.Float r = ImageTool.placement(400, 200, new Rectangle2D.Float(10, 20, 100, 100), 595, 842);
        assertEquals(new Rectangle2D.Float(10, 20, 100, 50), r);
        r = ImageTool.placement(400, 200, new Rectangle2D.Float(10, 20, 100, 30), 595, 842);
        assertEquals(new Rectangle2D.Float(10, 20, 60, 30), r);
        // a click: pixel size, capped to half the page, shifted to stay inside
        r = ImageTool.placement(40, 20, new Rectangle2D.Float(500, 800, 0, 0), 595, 842);
        assertEquals(new Rectangle2D.Float(500, 800, 40, 20), r, "fits, so the corner is kept");
        r = ImageTool.placement(40, 20, new Rectangle2D.Float(580, 830, 0, 0), 595, 842);
        assertEquals(40, r.width, 0.001);
        assertEquals(20, r.height, 0.001);
        assertEquals(595 - ImageTool.MARGIN_PT - 40, r.x, 0.001);
        assertEquals(842 - ImageTool.MARGIN_PT - 20, r.y, 0.001);
        r = ImageTool.placement(2000, 1000, new Rectangle2D.Float(0, 0, 0, 0), 595, 842);
        assertEquals(297.5f, r.width, 0.001);
        assertEquals(148.75f, r.height, 0.001);
        r = ImageTool.placement(1000, 2000, null, 595, 842);
        assertEquals(421, r.height, 0.001);
        assertEquals(210.5f, r.width, 0.001);
        assertEquals(ImageTool.MARGIN_PT, r.x, 0.001);
    }

    @Test
    void cornerHandlesKeepTheAspectRatio() throws Exception {
        java.lang.reflect.Method m = SelectAnnotationTool.class.getDeclaredMethod("resizedKeepingAspect", Rectangle2D.Float.class, int.class, float.class, float.class);
        m.setAccessible(true);
        Rectangle2D.Float base = new Rectangle2D.Float(100, 100, 200, 100);
        // SE handle dragged right: width grows, height follows, NW corner fixed
        Rectangle2D.Float se = (Rectangle2D.Float) m.invoke(null, base, 3, 100f, 0f);
        assertEquals(new Rectangle2D.Float(100, 100, 300, 150), se);
        // NW handle dragged up/left: SE corner stays at (300, 200)
        Rectangle2D.Float nw = (Rectangle2D.Float) m.invoke(null, base, 0, -50f, -100f);
        assertEquals(300, nw.x + nw.width, 0.001);
        assertEquals(200, nw.y + nw.height, 0.001);
        assertEquals(2f, nw.width / nw.height, 0.001);
        assertEquals(400, nw.width, 0.001, "the larger of the two drags wins");
        // shrinking past zero is clamped
        Rectangle2D.Float tiny = (Rectangle2D.Float) m.invoke(null, base, 3, -500f, -500f);
        assertTrue(tiny.width >= 1 && tiny.height >= 0.5f);
    }

    @Test
    void quarterTurnsTurnThePictureSwapTheBoxAndUndo() throws Exception {
        waitFor(() -> viewer.getPageImage(0) != null, 10000);
        // left half red, right half blue: after a clockwise quarter turn red is on top
        BufferedImage picture = new BufferedImage(40, 20, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = picture.createGraphics();
        g.setColor(Color.RED);
        g.fillRect(0, 0, 20, 20);
        g.setColor(Color.BLUE);
        g.fillRect(20, 0, 20, 20);
        g.dispose();
        PDAnnotation a = onEDT(() -> pane.addImage(0, new Rectangle2D.Float(100, 400, 120, 60), picture));
        assertEquals(0, ImageStamp.rotationOf(a));
        PageTransform t = transform(0);
        Rectangle2D.Float leftHalf = new Rectangle2D.Float(100, 400, 60, 60);
        waitFor(() -> reddish(viewer.getPageImage(0), leftHalf, viewer.getZoom()), 10000);

        onEDT(() -> pane.selectAnnotation(0, a));
        assertTrue(onEDT(() -> pane.rotateSelectedImage(90)));
        assertEquals("Rotate image right", pane.getEditModel().peekUndo().name());
        assertEquals(90, ImageStamp.rotationOf(a));
        Rectangle2D.Float turned = t.toViewRect(a.getRectangle());
        assertEquals(130, turned.x, 0.01, "the box turns about its centre");
        assertEquals(370, turned.y, 0.01);
        assertEquals(60, turned.width, 0.01, "width and height are swapped");
        assertEquals(120, turned.height, 0.01);
        assertEquals(0.5f, ImageStamp.aspect(a), 0.001, "the shown aspect is inverted");
        Rectangle2D.Float top = new Rectangle2D.Float(130, 370, 60, 60), bottom = new Rectangle2D.Float(130, 430, 60, 60);
        waitFor(() -> reddish(viewer.getPageImage(0), top, viewer.getZoom()) && bluish(viewer.getPageImage(0), bottom, viewer.getZoom()), 10000);

        onEDT(pane::undo);
        assertEquals(0, ImageStamp.rotationOf(a));
        Rectangle2D.Float back = t.toViewRect(a.getRectangle());
        assertEquals(new Rectangle2D.Float(100, 400, 120, 60), back);
        waitFor(() -> reddish(viewer.getPageImage(0), leftHalf, viewer.getZoom()), 10000);

        // counter-clockwise: red goes to the bottom; a second turn gives 180 with red on the right
        onEDT(() -> pane.selectAnnotation(0, a));
        assertTrue(onEDT(() -> pane.rotateSelectedImage(-90)));
        assertEquals("Rotate image left", pane.getEditModel().peekUndo().name());
        assertEquals(270, ImageStamp.rotationOf(a));
        waitFor(() -> bluish(viewer.getPageImage(0), top, viewer.getZoom()) && reddish(viewer.getPageImage(0), bottom, viewer.getZoom()), 10000);
        assertTrue(onEDT(() -> pane.rotateSelectedImage(-90)));
        assertEquals(180, ImageStamp.rotationOf(a));
        assertEquals(new Rectangle2D.Float(100, 400, 120, 60), t.toViewRect(a.getRectangle()));
        Rectangle2D.Float rightHalf = new Rectangle2D.Float(160, 400, 60, 60);
        waitFor(() -> reddish(viewer.getPageImage(0), rightHalf, viewer.getZoom()) && bluish(viewer.getPageImage(0), leftHalf, viewer.getZoom()), 10000);

        // the rotation survives save and reload, and the picture is still an image stamp
        File out = Files.createTempFile("rotated", ".pdf").toFile();
        out.deleteOnExit();
        onEDT(() -> {
            viewer.save(out);
            return null;
        });
        waitFor(() -> !pane.getEditModel().isModified(), 10000);
        try (PDDocument doc = Loader.loadPDF(out)) {
            List<PDAnnotation> annots = doc.getPage(0).getAnnotations();
            assertEquals(1, annots.size());
            assertTrue(ImageStamp.isImage(annots.get(0)));
            assertEquals(180, ImageStamp.rotationOf(annots.get(0)));
        }

        // a box too close to the edge is pushed back onto the page by a quarter turn
        PDAnnotation edge = onEDT(() -> pane.addImage(0, new Rectangle2D.Float(100, t.heightPt() - 70, 120, 60), picture));
        onEDT(() -> pane.selectAnnotation(0, edge));
        assertTrue(onEDT(() -> pane.rotateSelectedImage(90)));
        Rectangle2D.Float moved = t.toViewRect(edge.getRectangle());
        assertEquals(60, moved.width, 0.01);
        assertEquals(120, moved.height, 0.01);
        assertEquals(130, moved.x, 0.01, "the centre is kept where the box fits");
        assertEquals(t.heightPt() - 120, moved.y, 0.01, "pushed up onto the page");

        // not an image: nothing happens
        PDAnnotation note = onEDT(() -> pane.addNote(0, new Point2D.Float(50, 50), "hi"));
        onEDT(() -> pane.selectAnnotation(0, note));
        assertFalse(onEDT(() -> pane.rotateSelectedImage(90)));
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

    /** Sends a mouse event to the pages panel on the EDT, as the real dispatcher does (Shift+press is a marquee, so Shift is only set on drags here via the modifiers given). */
    private static void mouse(JComponent target, int id, int x, int y, int modifiers) throws Exception {
        onEDT(() -> {
            int mods = modifiers | (id == MouseEvent.MOUSE_RELEASED || id == MouseEvent.MOUSE_MOVED ? 0 : InputEvent.BUTTON1_DOWN_MASK);
            target.dispatchEvent(new MouseEvent(target, id, System.currentTimeMillis(), mods, x, y, 1, false, MouseEvent.BUTTON1));
            return null;
        });
    }

    private static BufferedImage solid(int w, int h, Color c) {
        BufferedImage img = new BufferedImage(w, h, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = img.createGraphics();
        g.setColor(c);
        g.fillRect(0, 0, w, h);
        g.dispose();
        return img;
    }

    /** True when every sampled pixel inside the rectangle (inset 2 px) is strong red. */
    private static boolean reddish(BufferedImage img, Rectangle2D.Float viewRect, float zoom) {
        return allPixels(img, viewRect, zoom, true);
    }

    /** True when every sampled pixel inside the rectangle (inset 2 px) is strong blue. */
    private static boolean bluish(BufferedImage img, Rectangle2D.Float viewRect, float zoom) {
        return allPixels(img, viewRect, zoom, false);
    }

    private static boolean allPixels(BufferedImage img, Rectangle2D.Float viewRect, float zoom, boolean red) {
        if (img == null)
            return false;
        int x1 = Math.round(viewRect.x * zoom) + 2, x2 = Math.round((viewRect.x + viewRect.width) * zoom) - 2;
        int y1 = Math.round(viewRect.y * zoom) + 2, y2 = Math.round((viewRect.y + viewRect.height) * zoom) - 2;
        int hits = 0, samples = 0;
        for (int y = Math.max(0, y1); y < Math.min(img.getHeight(), y2); y += 3)
            for (int x = Math.max(0, x1); x < Math.min(img.getWidth(), x2); x += 3) {
                int rgb = img.getRGB(x, y);
                int r = (rgb >> 16) & 0xff, g = (rgb >> 8) & 0xff, b = rgb & 0xff;
                samples++;
                if (red ? r > 200 && g < 60 && b < 60 : b > 200 && g < 60 && r < 60)
                    hits++;
            }
        return samples > 0 && hits == samples;
    }

    /** True when the rectangle is red blended with the white page (40 % opacity): red high, green and blue mid. */
    private static boolean pinkish(BufferedImage img, Rectangle2D.Float viewRect, float zoom) {
        int x = Math.round((viewRect.x + viewRect.width / 2) * zoom), y = Math.round((viewRect.y + viewRect.height / 2) * zoom);
        if (x < 0 || y < 0 || x >= img.getWidth() || y >= img.getHeight())
            return false;
        int rgb = img.getRGB(x, y);
        int r = (rgb >> 16) & 0xff, g = (rgb >> 8) & 0xff, b = rgb & 0xff;
        return r > 200 && g > 100 && g < 200 && b > 100 && b < 200;
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

    @Test
    void toolbarRotateButtonsFollowTheSelection() throws Exception {
        JButton left = toolbarButton("Rotate the current page counter-clockwise"), right = toolbarButton("Rotate the current page clockwise");
        assertNotSame(left, right);
        assertTrue(left.getToolTipText().contains("current page"), "no selection: the buttons rotate the page");
        Icon pageLeft = left.getIcon(), pageRight = right.getIcon();
        assertTrue(pageLeft instanceof IconUtil.RotateLeftIcon);
        assertTrue(pageRight instanceof IconUtil.RotateRightIcon);

        BufferedImage picture = new BufferedImage(40, 20, BufferedImage.TYPE_INT_RGB);
        PDAnnotation a = onEDT(() -> pane.addImage(0, new Rectangle2D.Float(100, 400, 120, 60), picture));
        onEDT(() -> pane.selectAnnotation(0, a));
        assertTrue(left.getToolTipText().contains("selected image"), "image selected: the same buttons rotate the image");
        assertTrue(left.getIcon() instanceof IconUtil.RotateImageLeftIcon);
        assertTrue(right.getIcon() instanceof IconUtil.RotateImageRightIcon);
        onEDT(() -> { right.doClick(); return null; });
        assertEquals(90, ImageStamp.rotationOf(a));
        assertEquals("Rotate image right", pane.getEditModel().peekUndo().name());
        assertEquals(0, viewer.getDocument().getPage(0).getRotation(), "the page is untouched");

        onEDT(() -> pane.clearAnnotationSelection());
        assertNull(pane.getSelectedAnnotation());
        assertSame(pageLeft, left.getIcon(), "selection cleared: back to the page icons");
        assertSame(pageRight, right.getIcon());
        assertTrue(right.getToolTipText().contains("current page"));
        onEDT(() -> { left.doClick(); return null; });
        assertEquals(270, viewer.getDocument().getPage(0).getRotation());
        assertEquals(90, ImageStamp.rotationOf(a), "the image is untouched");
    }

    /** The edit toolbar button with exactly this tooltip. */
    private JButton toolbarButton(String tooltip) throws Exception {
        return onEDT(() -> {
            for (Component c : pane.getEditToolbar().getComponents())
                if (c instanceof JButton && tooltip.equals(((JButton) c).getToolTipText()))
                    return (JButton) c;
            throw new AssertionError("no toolbar button with tooltip " + tooltip);
        });
    }
}
