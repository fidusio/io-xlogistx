package io.xlogistx.gui.pdf;

import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.zoxweb.shared.util.SUS;

import java.awt.geom.AffineTransform;
import java.awt.geom.NoninvertibleTransformException;
import java.awt.geom.Point2D;
import java.awt.geom.Rectangle2D;
import java.util.List;

/**
 * The single source of truth for converting between PDF user space and
 * <em>view space</em>: PDF points with the origin at the top-left corner of
 * the page as it is displayed (crop box applied, page rotation applied). View
 * space is what the viewer's text positions, search matches and links use;
 * multiplying by the zoom factor gives pixels.
 * <p>
 * The derivation mirrors PDFBox's renderer: translate by the crop box origin,
 * flip Y over the crop box height, then rotate by the page rotation about the
 * box. Pure Java, no Swing, so it can be unit tested headless.
 */
public final class PageTransform {

    private final PDRectangle box;
    private final int rotation;
    private final float widthPt;
    private final float heightPt;
    private final AffineTransform pdfToView;
    private final AffineTransform viewToPdf;

    /**
     * @param box      the displayed page box (crop box, or media box when none), never null
     * @param rotation the page rotation in degrees, any multiple of 90 (normalized)
     */
    public PageTransform(PDRectangle box, int rotation) {
        SUS.checkIfNull("box null", box);
        this.box = box;
        this.rotation = ((rotation % 360) + 360) % 360;
        float w = box.getWidth(), h = box.getHeight();
        boolean rotated = this.rotation == 90 || this.rotation == 270;
        widthPt = rotated ? h : w;
        heightPt = rotated ? w : h;

        AffineTransform at = new AffineTransform();
        switch (this.rotation) {
            case 90:
                at.translate(h, 0);
                break;
            case 180:
                at.translate(w, h);
                break;
            case 270:
                at.translate(0, w);
                break;
            default:
                break;
        }
        at.rotate(Math.toRadians(this.rotation));
        at.translate(0, h);
        at.scale(1, -1);
        at.translate(-box.getLowerLeftX(), -box.getLowerLeftY());
        pdfToView = at;
        try {
            viewToPdf = at.createInverse();
        } catch (NoninvertibleTransformException e) {
            throw new IllegalStateException(e); // rotations and translations are always invertible
        }
    }

    /**
     * @param page the page, never null
     * @return the transform of the page's crop box (media box when it has none) and rotation
     */
    public static PageTransform of(PDPage page) {
        SUS.checkIfNull("page null", page);
        PDRectangle box = page.getCropBox() != null ? page.getCropBox() : page.getMediaBox();
        return new PageTransform(box, page.getRotation());
    }

    /** @return the displayed page box in PDF user space */
    public PDRectangle box() {
        return box;
    }

    /** @return the normalized page rotation: 0, 90, 180 or 270 */
    public int rotation() {
        return rotation;
    }

    /** @return the displayed width in points (rotation applied) */
    public float widthPt() {
        return widthPt;
    }

    /** @return the displayed height in points (rotation applied) */
    public float heightPt() {
        return heightPt;
    }

    /** @return a copy of the transform from PDF user space to view space */
    public AffineTransform pdfToView() {
        return new AffineTransform(pdfToView);
    }

    /** @return a copy of the transform from view space to PDF user space */
    public AffineTransform viewToPdf() {
        return new AffineTransform(viewToPdf);
    }

    /**
     * @param pdf a point in PDF user space, never null
     * @return the same point in view space
     */
    public Point2D.Float toView(Point2D pdf) {
        Point2D p = pdfToView.transform(pdf, null);
        return new Point2D.Float((float) p.getX(), (float) p.getY());
    }

    /**
     * @param view a point in view space, never null
     * @return the same point in PDF user space
     */
    public Point2D.Float toPdf(Point2D view) {
        Point2D p = viewToPdf.transform(view, null);
        return new Point2D.Float((float) p.getX(), (float) p.getY());
    }

    /**
     * @param r a rectangle in PDF user space, never null
     * @return its bounds in view space
     */
    public Rectangle2D.Float toViewRect(PDRectangle r) {
        SUS.checkIfNull("rect null", r);
        return bounds(pdfToView, r.getLowerLeftX(), r.getLowerLeftY(), r.getUpperRightX(), r.getUpperRightY());
    }

    /**
     * @param r a rectangle in view space, never null
     * @return its bounds in PDF user space as a normalized {@link PDRectangle}
     */
    public PDRectangle toPdfRect(Rectangle2D r) {
        SUS.checkIfNull("rect null", r);
        Rectangle2D.Float b = bounds(viewToPdf, (float) r.getMinX(), (float) r.getMinY(), (float) r.getMaxX(), (float) r.getMaxY());
        return new PDRectangle(b.x, b.y, b.width, b.height);
    }

    /**
     * Builds text-markup QuadPoints for view-space rectangles: per rectangle
     * {@code x1 y1} upper-left, {@code x2 y2} upper-right, {@code x3 y3}
     * lower-left, {@code x4 y4} lower-right, "upper" and "left" as displayed,
     * all in PDF user space.
     *
     * @param viewRects the rectangles, never null
     * @return 8 floats per rectangle
     */
    public float[] toQuadPoints(List<? extends Rectangle2D> viewRects) {
        SUS.checkIfNull("rects null", viewRects);
        float[] quads = new float[viewRects.size() * 8];
        int i = 0;
        for (Rectangle2D r : viewRects) {
            Point2D.Float ul = toPdf(new Point2D.Float((float) r.getMinX(), (float) r.getMinY()));
            Point2D.Float ur = toPdf(new Point2D.Float((float) r.getMaxX(), (float) r.getMinY()));
            Point2D.Float ll = toPdf(new Point2D.Float((float) r.getMinX(), (float) r.getMaxY()));
            Point2D.Float lr = toPdf(new Point2D.Float((float) r.getMaxX(), (float) r.getMaxY()));
            quads[i++] = ul.x;
            quads[i++] = ul.y;
            quads[i++] = ur.x;
            quads[i++] = ur.y;
            quads[i++] = ll.x;
            quads[i++] = ll.y;
            quads[i++] = lr.x;
            quads[i++] = lr.y;
        }
        return quads;
    }

    /** Transforms the four corners of a box and returns their bounds. */
    private static Rectangle2D.Float bounds(AffineTransform at, float x1, float y1, float x2, float y2) {
        float[] pts = {x1, y1, x2, y1, x1, y2, x2, y2};
        at.transform(pts, 0, pts, 0, 4);
        float minX = pts[0], maxX = pts[0], minY = pts[1], maxY = pts[1];
        for (int i = 2; i < pts.length; i += 2) {
            minX = Math.min(minX, pts[i]);
            maxX = Math.max(maxX, pts[i]);
            minY = Math.min(minY, pts[i + 1]);
            maxY = Math.max(maxY, pts[i + 1]);
        }
        return new Rectangle2D.Float(minX, minY, maxX - minX, maxY - minY);
    }

    @Override
    public String toString() {
        return "PageTransform{box=" + box + ", rotation=" + rotation + ", " + widthPt + "x" + heightPt + "pt}";
    }
}
