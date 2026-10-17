package io.xlogistx.editor.pdf;

import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.PDResources;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.graphics.PDXObject;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;
import org.apache.pdfbox.pdmodel.graphics.state.PDExtendedGraphicsState;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotation;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationRubberStamp;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceDictionary;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceEntry;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceStream;
import org.apache.pdfbox.util.Matrix;
import org.zoxweb.shared.util.SUS;

import java.awt.geom.AffineTransform;
import java.io.IOException;

/**
 * An image placed over a page as a rubber stamp annotation ({@code /Stamp},
 * name {@value #NAME}): the picture is the stamp's own normal appearance, an
 * image XObject drawn to fill the annotation's rectangle, so every viewer shows
 * and prints it and the editor can move, resize, rotate, restyle, delete and
 * undo it like any other annotation. PDFBox has no appearance handler for
 * stamps, so the appearance is (re)built here; the image XObject is kept in the
 * appearance's resources under {@link #IMAGE_KEY} and reused on every rebuild
 * (a resize or rotation only redraws, it never re-encodes the picture).
 * <p>
 * Rotation is in steps of 90 degrees, clockwise like a page's {@code /Rotate},
 * kept on the annotation under {@link #ROTATION_KEY} (a private key other
 * viewers ignore: the rotation itself is drawn into the appearance, so they
 * show the picture turned). {@link #rotate} turns the picture about the centre
 * of its box, swapping the box's width and height for a quarter turn.
 * Pure PDFBox, no Swing.
 */
public final class ImageStamp {

    /** The stamp's {@code /Name}: not one of the standard rubber stamps, the appearance carries the picture. */
    public static final String NAME = "Image";
    /** Resource name of the picture inside the appearance stream. */
    public static final COSName IMAGE_KEY = COSName.getPDFName("Im0");
    /** Annotation key holding the picture's rotation in degrees clockwise (0, 90, 180, 270; absent = 0). */
    public static final COSName ROTATION_KEY = COSName.getPDFName("Rotate");
    private static final COSName OPACITY_KEY = COSName.getPDFName("GS0");

    private ImageStamp() {
    }

    /**
     * Draws (or redraws) the stamp's normal appearance: the image scaled to the
     * annotation's current rectangle, turned by its {@linkplain #rotationOf
     * rotation}, with the annotation's constant opacity.
     *
     * @param doc   the document, never null
     * @param a     the stamp, with a rectangle
     * @param image the picture, never null
     * @throws IOException when the stream cannot be written
     */
    public static void build(PDDocument doc, PDAnnotationRubberStamp a, PDImageXObject image) throws IOException {
        SUS.checkIfNull("document null", doc);
        SUS.checkIfNull("annotation null", a);
        SUS.checkIfNull("image null", image);
        PDRectangle rect = a.getRectangle();
        if (rect == null)
            throw new IllegalArgumentException("the stamp has no rectangle");
        float w = Math.max(1f, rect.getWidth()), h = Math.max(1f, rect.getHeight());
        int rotation = rotationOf(a);
        PDAppearanceStream ap = new PDAppearanceStream(doc);
        ap.setBBox(new PDRectangle(0, 0, w, h));
        PDResources res = new PDResources();
        res.put(IMAGE_KEY, image);
        ap.setResources(res);
        float opacity = a.getConstantOpacity();
        try (PDPageContentStream cs = new PDPageContentStream(doc, ap)) {
            if (opacity < 1f) {
                PDExtendedGraphicsState gs = new PDExtendedGraphicsState();
                gs.setNonStrokingAlphaConstant(opacity);
                gs.setStrokingAlphaConstant(opacity);
                res.put(OPACITY_KEY, gs);
                cs.setGraphicsStateParameters(gs);
            }
            if (rotation == 0)
                cs.drawImage(image, 0, 0, w, h);
            else {
                // turn about the centre of the box; PDF space has y up, so a clockwise
                // turn on the page is a negative angle here
                float cx = w / 2, cy = h / 2;
                cs.transform(new Matrix(AffineTransform.getRotateInstance(Math.toRadians(-rotation), cx, cy)));
                // a quarter turn draws the picture with the box's sides swapped so the turned picture fills the box
                float dw = rotation == 180 ? w : h, dh = rotation == 180 ? h : w;
                cs.drawImage(image, cx - dw / 2, cy - dh / 2, dw, dh);
            }
        }
        PDAppearanceDictionary apd = new PDAppearanceDictionary();
        apd.setNormalAppearance(ap);
        a.setAppearance(apd);
    }

    /**
     * Redraws the appearance of an image stamp after its rectangle, rotation or
     * opacity changed; does nothing for a stamp without a picture.
     *
     * @throws IOException when the stream cannot be written
     */
    public static void rebuild(PDDocument doc, PDAnnotation a) throws IOException {
        PDImageXObject image = imageOf(a);
        if (image != null)
            build(doc, (PDAnnotationRubberStamp) a, image);
    }

    /**
     * @return the picture's rotation in degrees clockwise, one of 0, 90, 180,
     *         270 (anything else on the key is rounded to the nearest quarter turn)
     */
    public static int rotationOf(PDAnnotation a) {
        SUS.checkIfNull("annotation null", a);
        return normalize(a.getCOSObject().getInt(ROTATION_KEY, 0));
    }

    /**
     * Sets the picture's rotation without touching the box or the appearance
     * (see {@link #rotate} for the whole turn).
     *
     * @param degrees clockwise, rounded to a quarter turn; 0 removes the key
     */
    public static void setRotation(PDAnnotation a, int degrees) {
        SUS.checkIfNull("annotation null", a);
        int r = normalize(degrees);
        if (r == 0)
            a.getCOSObject().removeItem(ROTATION_KEY);
        else
            a.getCOSObject().setInt(ROTATION_KEY, r);
    }

    /**
     * Turns the picture by a multiple of 90 degrees about the centre of its
     * box: the rotation is added, and for a quarter turn the box's width and
     * height are swapped (centre kept). The appearance is not rebuilt here, the
     * caller does that under its own lock.
     *
     * @param a      an image stamp with a rectangle
     * @param delta  degrees clockwise (negative = counter-clockwise), rounded to a quarter turn
     * @param within when not null, the turned box is shifted to stay inside this
     *               rectangle (PDF space) if it fits, e.g. the page's box
     * @return the new rotation, 0..270
     */
    public static int rotate(PDAnnotation a, int delta, PDRectangle within) {
        SUS.checkIfNull("annotation null", a);
        int step = normalize(delta);
        int rotation = normalize(rotationOf(a) + step);
        setRotation(a, rotation);
        PDRectangle rect = a.getRectangle();
        if (rect != null && (step == 90 || step == 270)) {
            float cx = (rect.getLowerLeftX() + rect.getUpperRightX()) / 2, cy = (rect.getLowerLeftY() + rect.getUpperRightY()) / 2;
            float w = rect.getHeight(), h = rect.getWidth();
            float x = cx - w / 2, y = cy - h / 2;
            if (within != null) {
                if (w <= within.getWidth()) {
                    x = Math.max(within.getLowerLeftX(), Math.min(x, within.getUpperRightX() - w));
                }
                if (h <= within.getHeight()) {
                    y = Math.max(within.getLowerLeftY(), Math.min(y, within.getUpperRightY() - h));
                }
            }
            a.setRectangle(new PDRectangle(x, y, w, h));
        }
        return rotation;
    }

    private static int normalize(int degrees) {
        int q = Math.round(degrees / 90f) * 90;
        q %= 360;
        return q < 0 ? q + 360 : q;
    }

    /**
     * @return the picture of an image stamp (from its appearance resources),
     *         null for any other annotation
     */
    public static PDImageXObject imageOf(PDAnnotation a) {
        if (!(a instanceof PDAnnotationRubberStamp))
            return null;
        PDAppearanceDictionary apd = a.getAppearance();
        if (apd == null)
            return null;
        PDAppearanceEntry normal = apd.getNormalAppearance();
        if (normal == null || !normal.isStream())
            return null;
        PDAppearanceStream stream = normal.getAppearanceStream();
        PDResources res = stream.getResources();
        if (res == null)
            return null;
        try {
            PDXObject x = res.getXObject(IMAGE_KEY);
            return x instanceof PDImageXObject ? (PDImageXObject) x : null;
        } catch (IOException e) {
            return null;
        }
    }

    /** @return true for a stamp carrying a picture built by this class */
    public static boolean isImage(PDAnnotation a) {
        return imageOf(a) != null;
    }

    /**
     * @return the width / height of the picture as shown, i.e. inverted for a
     *         quarter turn; 1 when the annotation is not an image stamp or the
     *         picture has no size
     */
    public static float aspect(PDAnnotation a) {
        PDImageXObject image = imageOf(a);
        if (image == null || image.getWidth() <= 0 || image.getHeight() <= 0)
            return 1f;
        float aspect = image.getWidth() / (float) image.getHeight();
        int rotation = rotationOf(a);
        return rotation == 90 || rotation == 270 ? 1f / aspect : aspect;
    }
}
