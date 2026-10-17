package io.xlogistx.editor.pdf;

import io.xlogistx.gui.PDFViewerPanel;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.zoxweb.shared.util.SUS;

import java.io.IOException;

/**
 * Undoable replacement of a page's content stream, produced by
 * {@link TextEditor#replace}: apply installs the new bytes, revert the old
 * ones, both re-render the page (which also drops its extracted text and
 * selection).
 */
public final class ReplaceTextEdit implements PDFEdit {

    private final PDFViewerPanel panel;
    private final int page;
    private final byte[] before;
    private final byte[] after;
    private final String name;

    /**
     * @param panel  the panel showing the document, never null
     * @param page   zero-based page index
     * @param before the page's content stream before the change, never null
     * @param after  the content stream with the text replaced, never null
     * @param name   e.g. {@code Replace "first" with "third"}
     */
    public ReplaceTextEdit(PDFViewerPanel panel, int page, byte[] before, byte[] after, String name) {
        SUS.checkIfNull("panel null", panel);
        SUS.checkIfNull("before null", before);
        SUS.checkIfNull("after null", after);
        this.panel = panel;
        this.page = page;
        this.before = before.clone();
        this.after = after.clone();
        this.name = name == null ? "Replace text" : name;
    }

    @Override
    public String name() {
        return name;
    }

    @Override
    public void apply() throws IOException {
        install(after);
    }

    @Override
    public void revert() throws IOException {
        install(before);
    }

    private void install(byte[] content) throws IOException {
        synchronized (panel.getDocumentLock()) {
            PDDocument doc = panel.getDocument();
            if (doc == null || page < 0 || page >= doc.getNumberOfPages())
                return;
            TextEditor.setContent(doc, doc.getPage(page), content);
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

    /** @return the page index */
    public int getPage() {
        return page;
    }
}
