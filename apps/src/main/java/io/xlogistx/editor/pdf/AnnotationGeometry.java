package io.xlogistx.editor.pdf;

import io.xlogistx.gui.pdf.PageTransform;
import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSNumber;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotation;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationInk;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationLine;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationLink;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationMarkup;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationPopup;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationRubberStamp;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationSquareCircle;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationText;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationTextMarkup;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationFreeText;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationWidget;

import java.awt.geom.Line2D;
import java.awt.geom.Point2D;
import java.awt.geom.Rectangle2D;
import java.util.List;

/**
 * Hit testing and geometry edits for annotations, in PDF user space unless a
 * name says view space. Pure PDFBox, no Swing.
 */
public final class AnnotationGeometry {

    /** How an annotation may be reshaped with the selection tool. */
    public enum Kind {
        /** Move only: text markup (quads belong to glyphs), ink, notes. */
        MOVE_ONLY,
        /** Move and resize by its rectangle: squares, circles, text boxes, image stamps. */
        BOX,
        /** Move, or drag either endpoint. */
        LINE
    }

    private AnnotationGeometry() {
    }

    /** @return false for popups, links and form widgets, which the selection tool never picks */
    public static boolean isEditable(PDAnnotation a) {
        return !(a instanceof PDAnnotationPopup || a instanceof PDAnnotationLink || a instanceof PDAnnotationWidget)
                && a.getRectangle() != null;
    }

    /** @return how the annotation can be reshaped */
    public static Kind kind(PDAnnotation a) {
        if (a instanceof PDAnnotationLine)
            return Kind.LINE;
        if (a instanceof PDAnnotationSquareCircle || a instanceof PDAnnotationFreeText || a instanceof PDAnnotationRubberStamp)
            return Kind.BOX;
        return Kind.MOVE_ONLY;
    }

    /** @return the annotation's rectangle in view space */
    public static Rectangle2D.Float bounds(PDAnnotation a, PageTransform t) {
        return t.toViewRect(a.getRectangle());
    }

    /**
     * The topmost editable annotation under a point.
     *
     * @param annotations the page's annotations in drawing order
     * @param t           the page transform
     * @param viewPt      the point in view space
     * @param tolerancePt how far from a line or ink stroke still counts, in points
     * @return the annotation, null when none
     */
    public static PDAnnotation hitTest(List<PDAnnotation> annotations, PageTransform t, Point2D viewPt, float tolerancePt) {
        Point2D.Float pdf = t.toPdf(viewPt);
        for (int i = annotations.size() - 1; i >= 0; i--) {
            PDAnnotation a = annotations.get(i);
            if (!isEditable(a))
                continue;
            if (a instanceof PDAnnotationLine) {
                float[] l = ((PDAnnotationLine) a).getLine();
                if (l != null && l.length >= 4 && Line2D.ptSegDist(l[0], l[1], l[2], l[3], pdf.x, pdf.y) <= tolerancePt)
                    return a;
                continue;
            }
            if (a instanceof PDAnnotationInk) {
                float[][] strokes = ((PDAnnotationInk) a).getInkList();
                if (strokes != null)
                    for (float[] s : strokes) {
                        if (s.length == 2 && pdf.distance(s[0], s[1]) <= tolerancePt)
                            return a;
                        for (int k = 0; k + 3 < s.length; k += 2)
                            if (Line2D.ptSegDist(s[k], s[k + 1], s[k + 2], s[k + 3], pdf.x, pdf.y) <= tolerancePt)
                                return a;
                    }
                continue;
            }
            PDRectangle r = a.getRectangle();
            if (pdf.x >= r.getLowerLeftX() - tolerancePt && pdf.x <= r.getUpperRightX() + tolerancePt
                    && pdf.y >= r.getLowerLeftY() - tolerancePt && pdf.y <= r.getUpperRightY() + tolerancePt)
                return a;
        }
        return null;
    }

    /**
     * Shifts every geometric entry of the annotation (rectangle, quads, ink,
     * line, vertices, and its popup) by a PDF-space delta.
     */
    public static void translate(PDAnnotation a, float dx, float dy) {
        PDRectangle r = a.getRectangle();
        if (r != null)
            a.setRectangle(new PDRectangle(r.getLowerLeftX() + dx, r.getLowerLeftY() + dy, r.getWidth(), r.getHeight()));
        if (a instanceof PDAnnotationTextMarkup) {
            PDAnnotationTextMarkup m = (PDAnnotationTextMarkup) a;
            float[] q = m.getQuadPoints();
            if (q != null)
                m.setQuadPoints(shift(q, dx, dy));
        }
        if (a instanceof PDAnnotationInk) {
            PDAnnotationInk ink = (PDAnnotationInk) a;
            float[][] strokes = ink.getInkList();
            if (strokes != null) {
                float[][] moved = new float[strokes.length][];
                for (int i = 0; i < strokes.length; i++)
                    moved[i] = shift(strokes[i], dx, dy);
                ink.setInkList(moved);
            }
        }
        if (a instanceof PDAnnotationLine) {
            PDAnnotationLine line = (PDAnnotationLine) a;
            float[] l = line.getLine();
            if (l != null)
                line.setLine(shift(l, dx, dy));
        }
        COSBase vertices = a.getCOSObject().getDictionaryObject(COSName.VERTICES);
        if (vertices instanceof COSArray)
            a.getCOSObject().setItem(COSName.VERTICES, shifted((COSArray) vertices, dx, dy));
        if (a instanceof PDAnnotationMarkup) {
            PDAnnotationPopup popup = ((PDAnnotationMarkup) a).getPopup();
            if (popup != null && popup.getRectangle() != null) {
                PDRectangle p = popup.getRectangle();
                popup.setRectangle(new PDRectangle(p.getLowerLeftX() + dx, p.getLowerLeftY() + dy, p.getWidth(), p.getHeight()));
            }
        }
    }

    /**
     * Sets the rectangle of a {@link Kind#BOX} annotation (and re-fits a text box).
     *
     * @param r the new rectangle in PDF space, normalized
     */
    public static void setBounds(PDAnnotation a, PDRectangle r) {
        a.setRectangle(new PDRectangle(Math.min(r.getLowerLeftX(), r.getUpperRightX()), Math.min(r.getLowerLeftY(), r.getUpperRightY()),
                Math.abs(r.getWidth()), Math.abs(r.getHeight())));
    }

    /**
     * Sets a line's endpoints (PDF space) and grows its rectangle to hold them.
     */
    public static void setLine(PDAnnotationLine a, float x1, float y1, float x2, float y2, float room) {
        a.setLine(new float[]{x1, y1, x2, y2});
        float minX = Math.min(x1, x2) - room, minY = Math.min(y1, y2) - room;
        float maxX = Math.max(x1, x2) + room, maxY = Math.max(y1, y2) + room;
        a.setRectangle(new PDRectangle(minX, minY, maxX - minX, maxY - minY));
    }

    /** @return the note annotation whose popup this is, or null */
    public static PDAnnotationText noteOf(PDAnnotation a) {
        return a instanceof PDAnnotationText ? (PDAnnotationText) a : null;
    }

    private static float[] shift(float[] v, float dx, float dy) {
        float[] out = v.clone();
        for (int i = 0; i + 1 < out.length; i += 2) {
            out[i] += dx;
            out[i + 1] += dy;
        }
        return out;
    }

    private static COSArray shifted(COSArray in, float dx, float dy) {
        COSArray out = new COSArray();
        for (int i = 0; i < in.size(); i++) {
            COSBase b = in.getObject(i);
            float v = b instanceof COSNumber ? ((COSNumber) b).floatValue() : 0f;
            out.add(new org.apache.pdfbox.cos.COSFloat(v + (i % 2 == 0 ? dx : dy)));
        }
        return out;
    }
}
