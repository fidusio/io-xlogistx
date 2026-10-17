package io.xlogistx.editor.pdf;

import io.xlogistx.gui.PDFViewerPanel;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageTree;
import org.zoxweb.shared.util.SUS;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Undoable insert of another document's pages at an index. The first
 * {@link #apply()} merges the source through
 * {@link PDFViewerPanel#insertPagesDirect(PDDocument, int)} and remembers the
 * page objects that landed; {@link #revert()} removes exactly those, and a
 * later apply (redo) puts the same objects back, so the source document may be
 * closed once the edit was applied the first time.
 */
public final class InsertPagesEdit implements PDFEdit {

    private final PDFViewerPanel panel;
    private final PDDocument source;
    private final int at;
    /** The inserted page objects, null until the first apply. */
    private List<PDPage> inserted;
    private int[] indexes = new int[0];

    /**
     * @param panel  the panel showing the target document, never null
     * @param source the document whose pages are inserted, never null
     * @param at     zero-based index the first new page lands at (clamped by the panel)
     */
    public InsertPagesEdit(PDFViewerPanel panel, PDDocument source, int at) {
        SUS.checkIfNull("panel null", panel);
        SUS.checkIfNull("source null", source);
        this.panel = panel;
        this.source = source;
        this.at = Math.max(0, at);
    }

    @Override
    public String name() {
        int n = inserted == null ? -1 : inserted.size();
        return n < 0 ? "Insert pages" : "Insert " + n + (n == 1 ? " page" : " pages");
    }

    @Override
    public void apply() throws IOException {
        if (inserted != null) {
            panel.insertPagesDirect(inserted, indexes, at);
            return;
        }
        int added = panel.insertPagesDirect(source, at);
        List<PDPage> pages = new ArrayList<>(added);
        indexes = new int[added];
        synchronized (panel.getDocumentLock()) {
            PDDocument doc = panel.getDocument();
            if (doc != null) {
                PDPageTree tree = doc.getPages();
                int first = Math.min(at, tree.getCount() - added);
                for (int i = 0; i < added; i++) {
                    pages.add(tree.get(first + i));
                    indexes[i] = first + i;
                }
            }
        }
        inserted = Collections.unmodifiableList(pages);
    }

    @Override
    public void revert() {
        if (inserted == null || inserted.isEmpty())
            return;
        int remaining = panel.getPageCount() - inserted.size();
        panel.removePagesDirect(inserted, Math.max(0, Math.min(indexes[0], remaining - 1)));
    }

    @Override
    public int[] affectedPages() {
        return indexes.clone();
    }

    @Override
    public boolean structural() {
        return true;
    }

    /** @return the page objects this edit inserted, empty before the first apply */
    public List<PDPage> getInsertedPages() {
        return inserted == null ? Collections.<PDPage>emptyList() : inserted;
    }
}
