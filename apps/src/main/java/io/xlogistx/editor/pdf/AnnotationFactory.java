package io.xlogistx.editor.pdf;

import io.xlogistx.gui.pdf.PageTransform;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.graphics.color.PDColor;
import org.apache.pdfbox.pdmodel.graphics.color.PDDeviceRGB;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotation;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationCircle;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationFreeText;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationHighlight;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationInk;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationLine;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationMarkup;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationPopup;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationRubberStamp;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationSquare;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationSquareCircle;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationStrikeout;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationText;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationTextMarkup;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationUnderline;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDBorderStyleDictionary;
import org.zoxweb.shared.util.SUS;

import java.awt.Color;
import java.awt.geom.Point2D;
import java.awt.geom.Rectangle2D;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.Calendar;
import java.util.List;
import java.util.Locale;

/**
 * Builds standard PDF annotations from view-space geometry (points, top-left
 * origin of the displayed page, see {@link PageTransform}) and an
 * {@link AnnotationStyle}, with appearance streams so every viewer shows them.
 * Pure PDFBox, no Swing. The caller adds the result to the page (see
 * {@link AddAnnotationEdit}); a note's popup is reachable through
 * {@link PDAnnotationMarkup#getPopup()} and must be added too.
 */
public final class AnnotationFactory {

    /** Text markup kinds. */
    public enum MarkupKind {
        HIGHLIGHT, UNDERLINE, STRIKEOUT
    }

    /** Side of a sticky note icon, in points. */
    public static final float NOTE_SIZE = 20f;
    /** Size of the popup window opened from a note, in points. */
    public static final float POPUP_WIDTH = 180f, POPUP_HEIGHT = 120f;
    /** Room added around a line's end for its arrow head, in points. */
    private static final float ARROW_ROOM = 10f;

    private AnnotationFactory() {
    }

    /**
     * Text markup over the given line rectangles.
     *
     * @param doc       the document, never null
     * @param page      the page the markup belongs to, never null
     * @param t         the page's transform, never null
     * @param viewRects one rectangle per text line, in view space; never null or empty
     * @param style     the style, never null; stroke colour = markup colour
     * @return the annotation, with appearance
     */
    public static PDAnnotationTextMarkup textMarkup(PDDocument doc, PDPage page, PageTransform t, MarkupKind kind,
                                                    List<Rectangle2D.Float> viewRects, AnnotationStyle style) {
        SUS.checkIfNull("kind null", kind);
        SUS.checkIfNull("rects null", viewRects);
        if (viewRects.isEmpty())
            throw new IllegalArgumentException("no rectangles to mark");
        PDAnnotationTextMarkup a;
        switch (kind) {
            case UNDERLINE:
                a = new PDAnnotationUnderline();
                break;
            case STRIKEOUT:
                a = new PDAnnotationStrikeout();
                break;
            default:
                a = new PDAnnotationHighlight();
        }
        common(a, page, style);
        a.setColor(pdColor(style.getStrokeColor()));
        a.setQuadPoints(t.toQuadPoints(viewRects));
        a.setRectangle(t.toPdfRect(union(viewRects)));
        a.constructAppearances(doc);
        return a;
    }

    /**
     * A sticky note (comment icon) with its closed popup window.
     *
     * @param doc      the document, never null
     * @param page     the page, never null
     * @param t        the page's transform, never null
     * @param viewPt   top-left corner of the icon, in view space; never null
     * @param contents the note text, may be empty
     * @param style    the style, never null; stroke colour = icon colour
     * @return the note; its popup is {@code getPopup()}
     */
    public static PDAnnotationText note(PDDocument doc, PDPage page, PageTransform t, Point2D viewPt, String contents, AnnotationStyle style) {
        SUS.checkIfNull("point null", viewPt);
        PDAnnotationText a = new PDAnnotationText();
        common(a, page, style);
        a.setName(PDAnnotationText.NAME_COMMENT);
        a.setContents(contents == null ? "" : contents);
        a.setColor(pdColor(style.getStrokeColor()));
        a.setOpen(false);
        float x = (float) viewPt.getX(), y = (float) viewPt.getY();
        a.setRectangle(t.toPdfRect(new Rectangle2D.Float(x, y, NOTE_SIZE, NOTE_SIZE)));
        a.setPopup(popupFor(a, page));
        a.constructAppearances(doc);
        return a;
    }

    /**
     * A closed popup for a note (or any markup annotation): {@link #POPUP_WIDTH}
     * x {@link #POPUP_HEIGHT} points, just right of the annotation's box and
     * top-aligned with it.
     *
     * @param owner the annotation, with a rectangle; never null
     * @param page  the page, never null
     * @return the popup, parented to the owner (the caller sets it on the owner)
     */
    public static PDAnnotationPopup popupFor(PDAnnotationMarkup owner, PDPage page) {
        SUS.checkIfNull("owner null", owner);
        SUS.checkIfNull("page null", page);
        PDRectangle r = owner.getRectangle();
        if (r == null)
            r = new PDRectangle();
        PDAnnotationPopup popup = new PDAnnotationPopup();
        popup.setParent(owner);
        popup.setOpen(false);
        popup.setPage(page);
        popup.setRectangle(new PDRectangle(r.getUpperRightX() + 4, r.getUpperRightY() - POPUP_HEIGHT, POPUP_WIDTH, POPUP_HEIGHT));
        return popup;
    }

    /**
     * Freehand ink.
     *
     * @param viewStrokes one list of points per stroke, in view space; never null or empty
     */
    public static PDAnnotationInk ink(PDDocument doc, PDPage page, PageTransform t, List<? extends List<? extends Point2D>> viewStrokes, AnnotationStyle style) {
        SUS.checkIfNull("strokes null", viewStrokes);
        if (viewStrokes.isEmpty())
            throw new IllegalArgumentException("no strokes");
        float[][] inkList = new float[viewStrokes.size()][];
        Rectangle2D.Float bounds = null;
        for (int s = 0; s < viewStrokes.size(); s++) {
            List<? extends Point2D> stroke = viewStrokes.get(s);
            float[] pts = new float[stroke.size() * 2];
            for (int i = 0; i < stroke.size(); i++) {
                Point2D p = stroke.get(i);
                Point2D.Float pdf = t.toPdf(p);
                pts[2 * i] = pdf.x;
                pts[2 * i + 1] = pdf.y;
                Rectangle2D.Float dot = new Rectangle2D.Float((float) p.getX(), (float) p.getY(), 0, 0);
                bounds = bounds == null ? dot : (Rectangle2D.Float) bounds.createUnion(dot);
            }
            inkList[s] = pts;
        }
        PDAnnotationInk a = new PDAnnotationInk();
        common(a, page, style);
        a.setColor(pdColor(style.getStrokeColor()));
        a.setBorderStyle(border(style.getStrokeWidth()));
        a.setInkList(inkList);
        a.setRectangle(t.toPdfRect(grow(bounds, style.getStrokeWidth())));
        a.constructAppearances(doc);
        return a;
    }

    /**
     * A rectangle or an ellipse.
     *
     * @param circle   true for an ellipse, false for a rectangle
     * @param viewRect the bounds in view space, never null
     */
    public static PDAnnotationSquareCircle shape(PDDocument doc, PDPage page, PageTransform t, boolean circle, Rectangle2D viewRect, AnnotationStyle style) {
        SUS.checkIfNull("rect null", viewRect);
        PDAnnotationSquareCircle a = circle ? new PDAnnotationCircle() : new PDAnnotationSquare();
        common(a, page, style);
        a.setColor(pdColor(style.getStrokeColor()));
        if (style.getFillColor() != null)
            a.setInteriorColor(pdColor(style.getFillColor()));
        a.setBorderStyle(border(style.getStrokeWidth()));
        a.setRectangle(t.toPdfRect(viewRect));
        a.constructAppearances(doc);
        return a;
    }

    /**
     * A straight line, optionally with an open arrow head at its end.
     *
     * @param p1 start, in view space; never null
     * @param p2 end, in view space; never null
     */
    public static PDAnnotationLine line(PDDocument doc, PDPage page, PageTransform t, Point2D p1, Point2D p2, boolean arrow, AnnotationStyle style) {
        SUS.checkIfNull("p1 null", p1);
        SUS.checkIfNull("p2 null", p2);
        PDAnnotationLine a = new PDAnnotationLine();
        common(a, page, style);
        a.setColor(pdColor(style.getStrokeColor()));
        if (style.getFillColor() != null)
            a.setInteriorColor(pdColor(style.getFillColor()));
        a.setBorderStyle(border(style.getStrokeWidth()));
        Point2D.Float a1 = t.toPdf(p1), a2 = t.toPdf(p2);
        a.setLine(new float[]{a1.x, a1.y, a2.x, a2.y});
        a.setStartPointEndingStyle(PDAnnotationLine.LE_NONE);
        a.setEndPointEndingStyle(arrow ? PDAnnotationLine.LE_OPEN_ARROW : PDAnnotationLine.LE_NONE);
        Rectangle2D.Float bounds = new Rectangle2D.Float((float) p1.getX(), (float) p1.getY(), 0, 0);
        bounds.add(p2);
        a.setRectangle(t.toPdfRect(grow(bounds, style.getStrokeWidth() + (arrow ? ARROW_ROOM : 0))));
        a.constructAppearances(doc);
        return a;
    }

    /**
     * A text box (free text annotation) with an appearance drawn by
     * {@link FreeTextAppearance} (embedded Roboto, so non-Latin-1 text shows).
     *
     * @param viewRect the box in view space, never null
     * @param text     the text, may contain newlines
     * @param style    stroke colour = text colour, fill = background (null = none),
     *                 stroke width = border (0 = none), font size
     */
    public static PDAnnotationFreeText freeText(PDDocument doc, PDPage page, PageTransform t, Rectangle2D viewRect, String text, AnnotationStyle style) {
        SUS.checkIfNull("rect null", viewRect);
        PDAnnotationFreeText a = new PDAnnotationFreeText();
        common(a, page, style);
        a.setContents(text == null ? "" : text);
        a.setDefaultAppearance(defaultAppearance(style.getStrokeColor(), style.getFontSize()));
        a.setDefaultStyleString(FreeTextAppearance.defaultStyle(style));
        a.setQ(FreeTextAppearance.q(style.getAlignment()));
        if (style.getFillColor() != null)
            a.setColor(pdColor(style.getFillColor()));
        a.setBorderStyle(border(style.getStrokeWidth()));
        a.setRectangle(t.toPdfRect(viewRect));
        FreeTextAppearance.build(doc, a);
        return a;
    }

    /**
     * A picture placed over the page as an image stamp (see {@link ImageStamp}).
     *
     * @param viewRect the box in view space, never null (the caller fits the picture's aspect)
     * @param image    the picture, already created in {@code doc}
     * @param style    opacity applies; colours and width are ignored
     * @return the stamp, with its appearance drawn
     * @throws IOException when the appearance stream cannot be written
     */
    public static PDAnnotationRubberStamp image(PDDocument doc, PDPage page, PageTransform t, Rectangle2D viewRect, PDImageXObject image, AnnotationStyle style) throws IOException {
        SUS.checkIfNull("rect null", viewRect);
        SUS.checkIfNull("image null", image);
        PDAnnotationRubberStamp a = new PDAnnotationRubberStamp();
        common(a, page, style);
        a.setName(ImageStamp.NAME);
        a.setRectangle(t.toPdfRect(viewRect));
        ImageStamp.build(doc, a, image);
        return a;
    }

    /**
     * Rebuilds an annotation's appearance after its dictionary changed
     * (geometry, colours, contents). An image stamp is redrawn from the
     * picture its appearance already holds; other stamps are left alone (PDFBox
     * has no handler for them).
     *
     * @param doc the document, never null
     * @param a   the annotation, never null
     * @throws UncheckedIOException when an image stamp's stream cannot be written
     */
    public static void rebuildAppearance(PDDocument doc, PDAnnotation a) {
        SUS.checkIfNull("annotation null", a);
        if (a instanceof PDAnnotationFreeText)
            FreeTextAppearance.build(doc, (PDAnnotationFreeText) a);
        else if (a instanceof PDAnnotationRubberStamp) {
            try {
                ImageStamp.rebuild(doc, a);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        } else
            a.constructAppearances(doc);
    }

    /** The DA string of a text box: Helvetica (for other editors), size, RGB fill colour. */
    public static String defaultAppearance(Color textColor, float fontSize) {
        float[] c = rgb(textColor);
        return String.format(Locale.US, "/Helv %.1f Tf %.3f %.3f %.3f rg", fontSize, c[0], c[1], c[2]);
    }

    /** @return the colour as a DeviceRGB {@link PDColor} */
    public static PDColor pdColor(Color c) {
        return new PDColor(rgb(c), PDDeviceRGB.INSTANCE);
    }

    /** @return the colour of a PDF colour array (DeviceRGB, Gray or CMYK), null when absent */
    public static Color awtColor(PDColor c) {
        if (c == null)
            return null;
        float[] v = c.getComponents();
        switch (v.length) {
            case 1:
                return new Color(v[0], v[0], v[0]);
            case 3:
                return new Color(clamp(v[0]), clamp(v[1]), clamp(v[2]));
            case 4:
                return new Color(clamp((1 - v[0]) * (1 - v[3])), clamp((1 - v[1]) * (1 - v[3])), clamp((1 - v[2]) * (1 - v[3])));
            default:
                return null;
        }
    }

    static float[] rgb(Color c) {
        return new float[]{c.getRed() / 255f, c.getGreen() / 255f, c.getBlue() / 255f};
    }

    private static float clamp(float f) {
        return Math.max(0f, Math.min(1f, f));
    }

    static PDBorderStyleDictionary border(float width) {
        PDBorderStyleDictionary bs = new PDBorderStyleDictionary();
        bs.setWidth(width);
        bs.setStyle(PDBorderStyleDictionary.STYLE_SOLID);
        return bs;
    }

    /** Flags, dates, title, opacity: the part every created annotation shares. */
    private static void common(PDAnnotation a, PDPage page, AnnotationStyle style) {
        SUS.checkIfNull("page null", page);
        SUS.checkIfNull("style null", style);
        a.setPage(page);
        a.setPrinted(true);
        a.setModifiedDate(Calendar.getInstance());
        if (a instanceof PDAnnotationMarkup) {
            PDAnnotationMarkup m = (PDAnnotationMarkup) a;
            m.setCreationDate(Calendar.getInstance());
            if (style.getAuthor() != null)
                m.setTitlePopup(style.getAuthor());
            m.setConstantOpacity(style.getOpacity());
        }
    }

    static Rectangle2D.Float union(List<Rectangle2D.Float> rects) {
        Rectangle2D.Float u = null;
        for (Rectangle2D.Float r : rects)
            u = u == null ? new Rectangle2D.Float(r.x, r.y, r.width, r.height) : (Rectangle2D.Float) u.createUnion(r);
        return u;
    }

    static Rectangle2D.Float grow(Rectangle2D.Float r, float by) {
        return new Rectangle2D.Float(r.x - by, r.y - by, r.width + 2 * by, r.height + 2 * by);
    }

    /** @return the subtype name of an annotation dictionary, e.g. "Highlight" */
    public static String subtype(PDAnnotation a) {
        return a.getCOSObject().getNameAsString(COSName.SUBTYPE);
    }

    /** @return a copy of {@code r} as a PDFBox rectangle */
    public static PDRectangle copy(PDRectangle r) {
        return new PDRectangle(r.getLowerLeftX(), r.getLowerLeftY(), r.getWidth(), r.getHeight());
    }
}
