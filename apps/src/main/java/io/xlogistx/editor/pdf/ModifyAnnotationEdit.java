package io.xlogistx.editor.pdf;

import io.xlogistx.gui.pdf.PDFViewerPanel;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotation;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationMarkup;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationPopup;
import org.zoxweb.shared.util.SUS;

import java.util.Arrays;
import java.util.List;

/**
 * Undoable change of an annotation's geometry, colours, border, opacity or
 * contents. Works on snapshots of the tracked dictionary keys taken
 * {@linkplain #snapshot(PDAnnotation) before} and after the caller changed the
 * annotation: apply writes the "after" snapshot, revert the "before" one, both
 * rebuild the appearance and re-render the page. A note's popup follows the
 * note's rectangle. One edit per gesture or dialog, never per mouse move.
 */
public final class ModifyAnnotationEdit implements PDFEdit {

    /** The keys a snapshot carries. */
    public static final List<COSName> TRACKED = Arrays.asList(
            COSName.RECT, COSName.QUADPOINTS, COSName.INKLIST, COSName.L, COSName.C, COSName.IC, COSName.CA,
            COSName.BS, COSName.DA, COSName.CONTENTS, COSName.VERTICES, COSName.DS, COSName.Q,
            COSName.getPDFName("LE"), COSName.getPDFName("Popup"), ImageStamp.ROTATION_KEY);

    private final PDFViewerPanel panel;
    private final int page;
    private final PDAnnotation annotation;
    private final COSDictionary before;
    private COSDictionary after;
    private final String name;

    /**
     * @param panel      the panel showing the document, never null
     * @param page       zero-based page index
     * @param annotation the annotation, already carrying the new state
     * @param before     {@link #snapshot(PDAnnotation)} taken before the change
     * @param after      snapshot taken after the change
     * @param name       e.g. "Move rectangle"
     */
    public ModifyAnnotationEdit(PDFViewerPanel panel, int page, PDAnnotation annotation, COSDictionary before, COSDictionary after, String name) {
        SUS.checkIfNull("panel null", panel);
        SUS.checkIfNull("annotation null", annotation);
        SUS.checkIfNull("before null", before);
        SUS.checkIfNull("after null", after);
        this.panel = panel;
        this.page = page;
        this.annotation = annotation;
        this.before = before;
        this.after = after;
        this.name = name == null ? "Modify " + AddAnnotationEdit.label(annotation) : name;
    }

    /**
     * Copies the tracked keys of an annotation (a shallow copy of each value's
     * container: arrays and dictionaries are cloned one level deep).
     *
     * @param a the annotation, never null
     * @return the snapshot
     */
    public static COSDictionary snapshot(PDAnnotation a) {
        SUS.checkIfNull("annotation null", a);
        COSDictionary s = new COSDictionary();
        for (COSName key : TRACKED) {
            COSBase v = a.getCOSObject().getDictionaryObject(key);
            if (v == null)
                continue;
            if (key.equals(COSName.getPDFName("Popup"))) {
                // only the popup's rectangle matters for undo; keep it under the same key as a dictionary
                PDAnnotationPopup popup = a instanceof PDAnnotationMarkup ? ((PDAnnotationMarkup) a).getPopup() : null;
                if (popup != null && popup.getRectangle() != null) {
                    COSDictionary pr = new COSDictionary();
                    pr.setItem(COSName.RECT, popup.getRectangle().getCOSArray());
                    s.setItem(key, pr);
                }
                continue;
            }
            s.setItem(key, clone(v));
        }
        return s;
    }

    /** @return true if the two snapshots differ in any tracked key */
    public static boolean differs(COSDictionary a, COSDictionary b) {
        for (COSName key : TRACKED) {
            COSBase x = a.getDictionaryObject(key), y = b.getDictionaryObject(key);
            if (x == null ? y != null : (y == null || !x.toString().equals(y.toString())))
                return true;
        }
        return false;
    }

    /**
     * Replaces the "after" state, so a burst of small changes (keyboard nudges)
     * stays one undo step: the edit must be the top of the undo stack and the
     * annotation must already carry the new state.
     *
     * @param after a fresh {@link #snapshot(PDAnnotation)}, never null
     */
    public void amend(COSDictionary after) {
        SUS.checkIfNull("after null", after);
        this.after = after;
    }

    @Override
    public String name() {
        return name;
    }

    @Override
    public void apply() {
        write(after);
    }

    @Override
    public void revert() {
        write(before);
    }

    private void write(COSDictionary snap) {
        synchronized (panel.getDocumentLock()) {
            PDDocument doc = panel.getDocument();
            if (doc == null)
                return;
            COSDictionary dict = annotation.getCOSObject();
            for (COSName key : TRACKED) {
                if (key.equals(COSName.getPDFName("Popup")))
                    continue;
                COSBase v = snap.getDictionaryObject(key);
                if (v == null)
                    dict.removeItem(key);
                else
                    dict.setItem(key, clone(v));
            }
            COSBase popupRect = snap.getDictionaryObject(COSName.getPDFName("Popup"));
            PDAnnotationPopup popup = annotation instanceof PDAnnotationMarkup ? ((PDAnnotationMarkup) annotation).getPopup() : null;
            if (popup != null && popupRect instanceof COSDictionary) {
                COSBase r = ((COSDictionary) popupRect).getDictionaryObject(COSName.RECT);
                if (r instanceof org.apache.pdfbox.cos.COSArray)
                    popup.setRectangle(new PDRectangle((org.apache.pdfbox.cos.COSArray) clone(r)));
            }
            AnnotationFactory.rebuildAppearance(doc, annotation);
        }
        panel.invalidatePage(page);
    }

    private static COSBase clone(COSBase v) {
        if (v instanceof org.apache.pdfbox.cos.COSArray) {
            org.apache.pdfbox.cos.COSArray in = (org.apache.pdfbox.cos.COSArray) v, out = new org.apache.pdfbox.cos.COSArray();
            for (int i = 0; i < in.size(); i++)
                out.add(clone(in.getObject(i)));
            return out;
        }
        if (v instanceof COSDictionary && !(v instanceof org.apache.pdfbox.cos.COSStream)) {
            COSDictionary in = (COSDictionary) v, out = new COSDictionary();
            for (COSName k : in.keySet())
                out.setItem(k, in.getDictionaryObject(k));
            return out;
        }
        return v;
    }

    @Override
    public int[] affectedPages() {
        return new int[]{page};
    }

    @Override
    public boolean structural() {
        return false;
    }

    /** @return the modified annotation */
    public PDAnnotation getAnnotation() {
        return annotation;
    }
}
