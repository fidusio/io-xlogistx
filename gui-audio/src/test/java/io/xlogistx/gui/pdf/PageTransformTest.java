package io.xlogistx.gui.pdf;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.rendering.ImageType;
import org.apache.pdfbox.rendering.PDFRenderer;
import org.junit.jupiter.api.Test;

import java.awt.geom.Point2D;
import java.awt.geom.Rectangle2D;
import java.awt.image.BufferedImage;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link PageTransform} against hand-computed corners and against what PDFBox
 * actually renders.
 */
public class PageTransformTest {

    private static final float EPS = 1e-3f;
    /** A landscape 200 x 100 pt box at the origin. */
    private static final PDRectangle BOX = new PDRectangle(0, 0, 200, 100);

    @Test
    void displayedSizeFollowsRotation() {
        assertEquals(200, new PageTransform(BOX, 0).widthPt(), EPS);
        assertEquals(100, new PageTransform(BOX, 0).heightPt(), EPS);
        assertEquals(100, new PageTransform(BOX, 90).widthPt(), EPS);
        assertEquals(200, new PageTransform(BOX, 90).heightPt(), EPS);
        assertEquals(200, new PageTransform(BOX, 180).widthPt(), EPS);
        assertEquals(100, new PageTransform(BOX, 270).widthPt(), EPS);
        assertEquals(90, new PageTransform(BOX, 450).rotation(), "rotation is normalized");
        assertEquals(270, new PageTransform(BOX, -90).rotation());
    }

    @Test
    void cornersLandWhereTheRotatedPageShowsThem() {
        // the unrotated page's bottom-left corner (PDF origin) and top-right corner
        Point2D.Float origin = new Point2D.Float(0, 0), topRight = new Point2D.Float(200, 100);

        PageTransform r0 = new PageTransform(BOX, 0);
        assertPoint(0, 100, r0.toView(origin));
        assertPoint(200, 0, r0.toView(topRight));

        PageTransform r90 = new PageTransform(BOX, 90);   // clockwise: the old left edge is now the top
        assertPoint(0, 0, r90.toView(origin));
        assertPoint(100, 200, r90.toView(topRight));

        PageTransform r180 = new PageTransform(BOX, 180);
        assertPoint(200, 0, r180.toView(origin));
        assertPoint(0, 100, r180.toView(topRight));

        PageTransform r270 = new PageTransform(BOX, 270);
        assertPoint(100, 200, r270.toView(origin));
        assertPoint(0, 0, r270.toView(topRight));
    }

    @Test
    void cropBoxOriginIsSubtracted() {
        PDRectangle offset = new PDRectangle(50, 20, 200, 100);
        PageTransform t = new PageTransform(offset, 0);
        assertPoint(0, 100, t.toView(new Point2D.Float(50, 20)));
        assertPoint(200, 0, t.toView(new Point2D.Float(250, 120)));
        PageTransform t90 = new PageTransform(offset, 90);
        assertPoint(0, 0, t90.toView(new Point2D.Float(50, 20)));
        assertPoint(100, 200, t90.toView(new Point2D.Float(250, 120)));
    }

    @Test
    void roundTripsPointsAndRectangles() {
        PDRectangle offset = new PDRectangle(50, 20, 200, 100);
        for (int rotation : new int[]{0, 90, 180, 270}) {
            PageTransform t = new PageTransform(offset, rotation);
            for (Point2D.Float p : new Point2D.Float[]{new Point2D.Float(50, 20), new Point2D.Float(123.5f, 77.25f), new Point2D.Float(250, 120)}) {
                Point2D.Float back = t.toPdf(t.toView(p));
                assertEquals(p.x, back.x, EPS, "rotation " + rotation);
                assertEquals(p.y, back.y, EPS, "rotation " + rotation);
            }
            PDRectangle r = new PDRectangle(60, 30, 40, 20);
            Rectangle2D.Float view = t.toViewRect(r);
            PDRectangle back = t.toPdfRect(view);
            assertEquals(r.getLowerLeftX(), back.getLowerLeftX(), EPS);
            assertEquals(r.getLowerLeftY(), back.getLowerLeftY(), EPS);
            assertEquals(r.getUpperRightX(), back.getUpperRightX(), EPS);
            assertEquals(r.getUpperRightY(), back.getUpperRightY(), EPS);
            assertTrue(view.width > 0 && view.height > 0);
            assertTrue(view.x >= -EPS && view.y >= -EPS && view.getMaxX() <= t.widthPt() + EPS && view.getMaxY() <= t.heightPt() + EPS,
                    "inside the displayed page at rotation " + rotation + ": " + view);
        }
    }

    @Test
    void rectanglesMatchTheViewersLegacyFormula() {
        // the formula PDFViewerPanel used for link rectangles before PageTransform existed
        PDRectangle r = new PDRectangle(10, 20, 20, 30); // llx 10, lly 20, urx 30, ury 50
        assertRect(10, 50, 20, 30, new PageTransform(BOX, 0).toViewRect(r));
        assertRect(20, 10, 30, 20, new PageTransform(BOX, 90).toViewRect(r));
        assertRect(170, 20, 20, 30, new PageTransform(BOX, 180).toViewRect(r));
        assertRect(50, 170, 30, 20, new PageTransform(BOX, 270).toViewRect(r));
    }

    @Test
    void quadPointsAreUpperLeftUpperRightLowerLeftLowerRight() {
        PageTransform t = new PageTransform(BOX, 0);
        float[] q = t.toQuadPoints(Arrays.asList(new Rectangle2D.Float(10, 10, 20, 5)));
        assertArrayEquals(new float[]{10, 90, 30, 90, 10, 85, 30, 85}, q, EPS);
        float[] q90 = new PageTransform(BOX, 90).toQuadPoints(Arrays.asList(new Rectangle2D.Float(0, 0, 100, 200)));
        // the displayed top-left is the PDF origin, the displayed top-right is the PDF top-left corner
        assertArrayEquals(new float[]{0, 0, 0, 100, 200, 0, 200, 100}, q90, EPS);
        assertEquals(16, t.toQuadPoints(Arrays.asList(new Rectangle2D.Float(0, 0, 1, 1), new Rectangle2D.Float(1, 1, 1, 1))).length);
    }

    @Test
    void agreesWithPDFBoxRendering() throws Exception {
        for (int rotation : new int[]{0, 90, 180, 270}) {
            try (PDDocument doc = new PDDocument()) {
                PDPage page = new PDPage(new PDRectangle(0, 0, 200, 100));
                page.setRotation(rotation);
                doc.addPage(page);
                try (PDPageContentStream cs = new PDPageContentStream(doc, page)) {
                    cs.setNonStrokingColor(0f, 0f, 0f);
                    cs.addRect(20, 10, 40, 20); // llx 20, lly 10, w 40, h 20 in PDF user space
                    cs.fill();
                }
                BufferedImage img = new PDFRenderer(doc).renderImageWithDPI(0, 72, ImageType.RGB);
                PageTransform t = PageTransform.of(page);
                assertEquals(Math.round(t.widthPt()), img.getWidth(), "rotation " + rotation);
                assertEquals(Math.round(t.heightPt()), img.getHeight(), "rotation " + rotation);
                Point2D.Float center = t.toView(new Point2D.Float(40, 20));
                assertTrue(dark(img, center), "rect center is painted at rotation " + rotation + ": " + center);
                Point2D.Float outside = t.toView(new Point2D.Float(150, 80));
                assertFalse(dark(img, outside), "far corner is blank at rotation " + rotation + ": " + outside);
                Rectangle2D.Float view = t.toViewRect(new PDRectangle(20, 10, 40, 20));
                assertTrue(dark(img, new Point2D.Float((float) view.getCenterX(), (float) view.getCenterY())));
                assertFalse(dark(img, new Point2D.Float(view.x - 3, view.y - 3)));
            }
        }
    }

    @Test
    void rejectsNulls() {
        assertThrows(NullPointerException.class, () -> new PageTransform(null, 0));
        assertThrows(NullPointerException.class, () -> PageTransform.of(null));
        assertThrows(NullPointerException.class, () -> new PageTransform(BOX, 0).toViewRect(null));
    }

    private static boolean dark(BufferedImage img, Point2D.Float p) {
        int x = Math.round(p.x), y = Math.round(p.y);
        x = Math.max(0, Math.min(img.getWidth() - 1, x));
        y = Math.max(0, Math.min(img.getHeight() - 1, y));
        return (img.getRGB(x, y) & 0xff) < 128;
    }

    private static void assertPoint(float x, float y, Point2D.Float p) {
        assertEquals(x, p.x, EPS, "x of " + p);
        assertEquals(y, p.y, EPS, "y of " + p);
    }

    private static void assertRect(float x, float y, float w, float h, Rectangle2D.Float r) {
        assertEquals(x, r.x, EPS, "x of " + r);
        assertEquals(y, r.y, EPS, "y of " + r);
        assertEquals(w, r.width, EPS, "width of " + r);
        assertEquals(h, r.height, EPS, "height of " + r);
    }
}
