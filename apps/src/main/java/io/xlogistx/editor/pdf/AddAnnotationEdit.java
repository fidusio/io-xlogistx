package io.xlogistx.editor.pdf;

import io.xlogistx.gui.PDFViewerPanel;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotation;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationMarkup;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationPopup;
import org.zoxweb.shared.util.SUS;

import java.io.IOException;
import java.util.List;

/**
 * Undoable addition of one annotation (plus the popup of a note) to a page.
 */
public final class AddAnnotationEdit implements PDFEdit {

    private final PDFViewerPanel panel;
    private final int page;
    private final PDAnnotation annotation;
    private final String name;

    /**
     * @param panel      the panel showing the document, never null
     * @param page       zero-based page index
     * @param annotation the annotation (with appearance), never null
     */
    public AddAnnotationEdit(PDFViewerPanel panel, int page, PDAnnotation annotation) {
        this(panel, page, annotation, "Add " + label(annotation));
    }

    public AddAnnotationEdit(PDFViewerPanel panel, int page, PDAnnotation annotation, String name) {
        SUS.checkIfNull("panel null", panel);
        SUS.checkIfNull("annotation null", annotation);
        this.panel = panel;
        this.page = page;
        this.annotation = annotation;
        this.name = name;
    }

    @Override
    public String name() {
        return name;
    }

    @Override
    public void apply() throws IOException {
        synchronized (panel.getDocumentLock()) {
            PDDocument doc = panel.getDocument();
            if (doc == null)
                return;
            PDPage p = doc.getPage(page);
            List<PDAnnotation> list = p.getAnnotations();
            annotation.setPage(p);
            if (indexOf(list, annotation) < 0)
                list.add(annotation);
            PDAnnotationPopup popup = popup(annotation);
            if (popup != null && indexOf(list, popup) < 0) {
                popup.setPage(p);
                list.add(popup);
            }
            p.setAnnotations(list);
        }
        panel.invalidatePage(page);
    }

    @Override
    public void revert() throws IOException {
        synchronized (panel.getDocumentLock()) {
            PDDocument doc = panel.getDocument();
            if (doc == null)
                return;
            PDPage p = doc.getPage(page);
            List<PDAnnotation> list = p.getAnnotations();
            remove(list, popup(annotation));
            remove(list, annotation);
            p.setAnnotations(list);
        }
        panel.invalidatePage(page);
    }

    @Override
    public int[] affectedPages() {
        return new int[]{page};
    }

    @Override
    public boolean structural() {
        return false;
    }

    /** @return the added annotation */
    public PDAnnotation getAnnotation() {
        return annotation;
    }

    /** @return the page index */
    public int getPage() {
        return page;
    }

    static PDAnnotationPopup popup(PDAnnotation a) {
        return a instanceof PDAnnotationMarkup ? ((PDAnnotationMarkup) a).getPopup() : null;
    }

    /** Index by dictionary identity: {@code getAnnotations()} wraps each entry in a fresh object. */
    static int indexOf(List<PDAnnotation> list, PDAnnotation a) {
        if (a == null)
            return -1;
        for (int i = 0; i < list.size(); i++)
            if (list.get(i).getCOSObject() == a.getCOSObject())
                return i;
        return -1;
    }

    static boolean remove(List<PDAnnotation> list, PDAnnotation a) {
        int i = indexOf(list, a);
        if (i < 0)
            return false;
        list.remove(i);
        return true;
    }

    static String label(PDAnnotation a) {
        String sub = AnnotationFactory.subtype(a);
        if (sub == null)
            return "annotation";
        switch (sub) {
            case "Highlight":
                return "highlight";
            case "Underline":
                return "underline";
            case "StrikeOut":
                return "strikeout";
            case "Text":
                return "note";
            case "FreeText":
                return "text box";
            case "Ink":
                return "ink";
            case "Square":
                return "rectangle";
            case "Circle":
                return "ellipse";
            case "Line":
                return "line";
            case "Stamp":
                return ImageStamp.isImage(a) ? "image" : "stamp";
            default:
                return sub.toLowerCase();
        }
    }
}
