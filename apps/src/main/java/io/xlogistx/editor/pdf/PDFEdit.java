package io.xlogistx.editor.pdf;

import io.xlogistx.gui.pdf.PDFViewerPanel;

import java.io.IOException;

/**
 * One undoable change to the document shown by a
 * {@link PDFViewerPanel}. An edit applies and reverts itself
 * through the panel's direct primitives (which refresh the view and never ask
 * the edit delegate again), so the {@link PDFEditModel} only has to keep the
 * stacks. Edits run on the EDT.
 */
public interface PDFEdit {

    /** @return a short description for menus and tooltips, e.g. {@code "Delete 2 pages"} */
    String name();

    /** Performs the change (first time and on redo). @throws IOException if the document refuses it */
    void apply() throws IOException;

    /** Undoes {@link #apply()}. @throws IOException if the document refuses it */
    void revert() throws IOException;

    /** @return zero-based pages whose content changed, for a non-structural edit; informational for a structural one */
    int[] affectedPages();

    /** @return true when the page tree changed (count, order or size), so the whole view was rebuilt */
    boolean structural();
}
