package io.xlogistx.editor.pdf;

import io.xlogistx.gui.PDFViewerPanel;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotation;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationPopup;
import org.zoxweb.shared.util.SUS;

import java.io.IOException;
import java.util.List;

/**
 * Undoable removal of one annotation (plus the popup of a note) from a page;
 * revert puts it back at the position it had.
 */
public final class RemoveAnnotationEdit implements PDFEdit {

    private final PDFViewerPanel panel;
    private final int page;
    private final PDAnnotation annotation;
    private final String name;
    private int index = -1;
    private int popupIndex = -1;

    /**
     * @param panel      the panel showing the document, never null
     * @param page       zero-based page index
     * @param annotation the annotation to remove, never null
     */
    public RemoveAnnotationEdit(PDFViewerPanel panel, int page, PDAnnotation annotation) {
        this(panel, page, annotation, "Delete");
    }

    /**
     * @param verb what the undo history calls the removal: "Delete", "Cut"
     */
    public RemoveAnnotationEdit(PDFViewerPanel panel, int page, PDAnnotation annotation, String verb) {
        SUS.checkIfNull("panel null", panel);
        SUS.checkIfNull("annotation null", annotation);
        this.panel = panel;
        this.page = page;
        this.annotation = annotation;
        this.name = (verb == null ? "Delete" : verb) + " " + AddAnnotationEdit.label(annotation);
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
            PDAnnotationPopup popup = AddAnnotationEdit.popup(annotation);
            popupIndex = AddAnnotationEdit.indexOf(list, popup);
            if (popupIndex >= 0)
                list.remove(popupIndex);
            index = AddAnnotationEdit.indexOf(list, annotation);
            if (index >= 0)
                list.remove(index);
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
            if (index >= 0 && AddAnnotationEdit.indexOf(list, annotation) < 0)
                list.add(Math.min(index, list.size()), annotation);
            PDAnnotationPopup popup = AddAnnotationEdit.popup(annotation);
            if (popupIndex >= 0 && popup != null && AddAnnotationEdit.indexOf(list, popup) < 0)
                list.add(Math.min(popupIndex, list.size()), popup);
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

    /** @return the removed annotation */
    public PDAnnotation getAnnotation() {
        return annotation;
    }
}
