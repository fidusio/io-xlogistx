package io.xlogistx.editor.pdf;

import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSStream;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.graphics.image.LosslessFactory;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotation;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationMarkup;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationRubberStamp;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationText;
import org.zoxweb.shared.util.SUS;

import java.awt.GraphicsEnvironment;
import java.awt.HeadlessException;
import java.awt.Image;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.util.Arrays;
import java.util.Calendar;
import java.util.List;

/**
 * Copy and paste of annotations. A {@link Clip} is a document-independent
 * snapshot of one annotation: a deep copy of its dictionary without the
 * appearance, page and popup links, plus the decoded picture of an image
 * stamp. It travels on a {@link Clipboard} as a {@link Transferable} that also
 * offers the text of a note or text box and the picture of an image stamp to
 * other programs, and {@link #read} gives back the clip, or the plain text or
 * picture another program put there since: whatever was copied last wins.
 * A headless JVM has no system clipboard, so {@link #clipboard()} falls back
 * to one local to the JVM.
 */
public final class AnnotationClipboard {

    /** The flavour the clip itself travels under (never leaves the JVM). */
    public static final DataFlavor CLIP_FLAVOR = new DataFlavor(DataFlavor.javaJVMLocalObjectMimeType + ";class=" + Clip.class.getName(), "PDF annotation");

    private static final Clipboard LOCAL = new Clipboard("pdf-editor");
    /** Dictionary entries that tie an annotation to its document and are never copied. */
    private static final List<COSName> UNCOPIED = Arrays.asList(COSName.AP, COSName.P, COSName.getPDFName("Popup"),
            COSName.PARENT, COSName.getPDFName("IRT"), COSName.getPDFName("RT"), COSName.NM);

    private AnnotationClipboard() {
    }

    /**
     * @return the system clipboard, or a JVM-local one when the JVM is headless
     *         (tests) or the toolkit refuses
     */
    public static Clipboard clipboard() {
        if (GraphicsEnvironment.isHeadless())
            return LOCAL;
        try {
            return Toolkit.getDefaultToolkit().getSystemClipboard();
        } catch (HeadlessException | SecurityException e) {
            return LOCAL;
        }
    }

    /**
     * Snapshots an annotation (call under the document lock).
     *
     * @param doc the document the annotation lives in, never null
     * @param a   the annotation, never null
     * @return the clip
     */
    public static Clip copy(PDDocument doc, PDAnnotation a) {
        SUS.checkIfNull("document null", doc);
        SUS.checkIfNull("annotation null", a);
        COSDictionary d = new COSDictionary(a.getCOSObject());
        for (COSName key : UNCOPIED)
            d.removeItem(key);
        PDImageXObject image = ImageStamp.imageOf(a);
        BufferedImage picture = null;
        if (image != null) {
            try {
                picture = image.getImage();
            } catch (IOException | RuntimeException e) {
                picture = null; // the stamp can still be pasted into its own document
            }
        }
        PDRectangle r = a.getRectangle();
        return new Clip((COSDictionary) deepCopy(d), r == null ? new PDRectangle() : AnnotationFactory.copy(r), doc, image, picture,
                AddAnnotationEdit.label(a));
    }

    /** Puts a clip on a clipboard. */
    public static void write(Clipboard clipboard, Clip clip) {
        SUS.checkIfNull("clipboard null", clipboard);
        SUS.checkIfNull("clip null", clip);
        clipboard.setContents(new ClipTransferable(clip), null);
    }

    /**
     * What a clipboard holds for the editor: a {@link Clip}, else a
     * {@link BufferedImage}, else a {@link String}; null when none of these.
     * A busy or empty clipboard gives null.
     */
    public static Object read(Clipboard clipboard) {
        SUS.checkIfNull("clipboard null", clipboard);
        try {
            Transferable t = clipboard.getContents(null);
            if (t == null)
                return null;
            if (t.isDataFlavorSupported(CLIP_FLAVOR))
                return t.getTransferData(CLIP_FLAVOR);
            if (t.isDataFlavorSupported(DataFlavor.imageFlavor)) {
                Object o = t.getTransferData(DataFlavor.imageFlavor);
                if (o instanceof Image)
                    return toBuffered((Image) o);
            }
            if (t.isDataFlavorSupported(DataFlavor.stringFlavor)) {
                Object o = t.getTransferData(DataFlavor.stringFlavor);
                if (o instanceof String && !((String) o).trim().isEmpty())
                    return o;
            }
            return null;
        } catch (IllegalStateException | IOException | UnsupportedFlavorException e) {
            return null;
        }
    }

    /** @return true when {@link #read} would give something */
    public static boolean hasContent(Clipboard clipboard) {
        SUS.checkIfNull("clipboard null", clipboard);
        try {
            if (clipboard.isDataFlavorAvailable(CLIP_FLAVOR) || clipboard.isDataFlavorAvailable(DataFlavor.imageFlavor))
                return true;
            if (!clipboard.isDataFlavorAvailable(DataFlavor.stringFlavor))
                return false;
            Object o = clipboard.getData(DataFlavor.stringFlavor); // blank text is nothing to paste
            return o instanceof String && !((String) o).trim().isEmpty();
        } catch (IllegalStateException | IOException | UnsupportedFlavorException e) {
            return false;
        }
    }

    private static BufferedImage toBuffered(Image img) {
        if (img instanceof BufferedImage)
            return (BufferedImage) img;
        int w = img.getWidth(null), h = img.getHeight(null);
        if (w <= 0 || h <= 0)
            return null;
        BufferedImage b = new BufferedImage(w, h, BufferedImage.TYPE_INT_ARGB);
        java.awt.Graphics2D g = b.createGraphics();
        g.drawImage(img, 0, 0, null);
        g.dispose();
        return b;
    }

    /**
     * Copies a value: dictionaries and arrays recursively, streams (the picture
     * of an image stamp, say) by reference, scalars as they are.
     */
    static COSBase deepCopy(COSBase v) {
        if (v instanceof COSStream)
            return v;
        if (v instanceof COSDictionary) {
            COSDictionary in = (COSDictionary) v, out = new COSDictionary();
            for (COSName k : in.keySet())
                out.setItem(k, deepCopy(in.getDictionaryObject(k)));
            return out;
        }
        if (v instanceof COSArray) {
            COSArray in = (COSArray) v, out = new COSArray();
            for (int i = 0; i < in.size(); i++)
                out.add(deepCopy(in.getObject(i)));
            return out;
        }
        return v;
    }

    /**
     * A snapshot of one annotation that can be put back into any document, any
     * number of times, each time as a new annotation.
     */
    public static final class Clip {
        private final COSDictionary dict;
        private final PDRectangle rect;
        private final PDDocument source;
        private final PDImageXObject image;
        private final BufferedImage picture;
        private final String kind;

        Clip(COSDictionary dict, PDRectangle rect, PDDocument source, PDImageXObject image, BufferedImage picture, String kind) {
            this.dict = dict;
            this.rect = rect;
            this.source = source;
            this.image = image;
            this.picture = picture;
            this.kind = kind;
        }

        /** @return the lower-case name of the kind ("image", "text box", "rectangle", ...) */
        public String kind() {
            return kind;
        }

        /** @return the subtype name ("Stamp", "FreeText", ...) */
        public String subtype() {
            return dict.getNameAsString(COSName.SUBTYPE);
        }

        /** @return the width of the annotation's box in points */
        public float width() {
            return rect.getWidth();
        }

        /** @return the height of the annotation's box in points */
        public float height() {
            return rect.getHeight();
        }

        /** @return the text of a note or text box, empty otherwise */
        public String text() {
            String s = dict.getString(COSName.CONTENTS);
            return s == null ? "" : s;
        }

        /** @return true for an image stamp */
        public boolean isImage() {
            return image != null || picture != null;
        }

        /** @return the decoded picture of an image stamp, null for anything else (or when it could not be decoded) */
        public BufferedImage picture() {
            return picture;
        }

        /**
         * Makes a new annotation from the clip on a page, with its appearance
         * built and its box's lower-left corner at a point (call under the
         * document lock; the caller adds it to the page).
         *
         * @param doc  the target document, never null
         * @param page the target page, never null
         * @param llx  lower-left x in PDF space
         * @param lly  lower-left y in PDF space
         * @return the annotation
         * @throws IOException when the picture of an image stamp cannot be embedded or drawn
         */
        public PDAnnotation create(PDDocument doc, PDPage page, float llx, float lly) throws IOException {
            SUS.checkIfNull("document null", doc);
            SUS.checkIfNull("page null", page);
            PDAnnotation a = PDAnnotation.createAnnotation(deepCopy(dict));
            a.setPage(page);
            AnnotationGeometry.translate(a, llx - rect.getLowerLeftX(), lly - rect.getLowerLeftY());
            Calendar now = Calendar.getInstance();
            a.setModifiedDate(now);
            if (a instanceof PDAnnotationMarkup)
                ((PDAnnotationMarkup) a).setCreationDate(now);
            if (a instanceof PDAnnotationText)
                ((PDAnnotationText) a).setPopup(AnnotationFactory.popupFor((PDAnnotationText) a, page));
            if (a instanceof PDAnnotationRubberStamp && isImage()) {
                PDImageXObject img = image != null && source == doc && !doc.getDocument().isClosed() ? image
                        : picture != null ? LosslessFactory.createFromImage(doc, picture) : null;
                if (img == null)
                    throw new IOException("the picture of the copied image is no longer available");
                ImageStamp.build(doc, (PDAnnotationRubberStamp) a, img);
            } else
                AnnotationFactory.rebuildAppearance(doc, a);
            return a;
        }
    }

    /** The clip on a clipboard, with its text and picture for other programs. */
    static final class ClipTransferable implements Transferable {
        private final Clip clip;
        private final DataFlavor[] flavors;

        ClipTransferable(Clip clip) {
            this.clip = clip;
            java.util.List<DataFlavor> f = new java.util.ArrayList<>();
            f.add(CLIP_FLAVOR);
            if (clip.picture() != null)
                f.add(DataFlavor.imageFlavor);
            if (!clip.text().isEmpty())
                f.add(DataFlavor.stringFlavor);
            flavors = f.toArray(new DataFlavor[0]);
        }

        @Override
        public DataFlavor[] getTransferDataFlavors() {
            return flavors.clone();
        }

        @Override
        public boolean isDataFlavorSupported(DataFlavor flavor) {
            for (DataFlavor f : flavors)
                if (f.equals(flavor))
                    return true;
            return false;
        }

        @Override
        public Object getTransferData(DataFlavor flavor) throws UnsupportedFlavorException {
            if (CLIP_FLAVOR.equals(flavor))
                return clip;
            if (DataFlavor.imageFlavor.equals(flavor) && clip.picture() != null)
                return clip.picture();
            if (DataFlavor.stringFlavor.equals(flavor) && !clip.text().isEmpty())
                return clip.text();
            throw new UnsupportedFlavorException(flavor);
        }
    }
}
