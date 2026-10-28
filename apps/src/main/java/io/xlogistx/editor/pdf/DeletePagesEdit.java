package io.xlogistx.editor.pdf;

import io.xlogistx.gui.pdf.PDFViewerPanel;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.zoxweb.shared.util.SUS;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Undoable removal of pages by index. The first {@link #apply()} captures the
 * page objects at the given indexes and removes them through
 * {@link PDFViewerPanel#removePagesDirect(List, int)}; {@link #revert()} puts
 * the same objects back at their original indexes (lowest first, which
 * restores the exact order), and a later apply removes them again. A page
 * removed from the tree stays a valid object of the document, so nothing is
 * cloned.
 */
public final class DeletePagesEdit implements PDFEdit {

    private final PDFViewerPanel panel;
    private final int[] indexes;
    /** The removed page objects, null until the first apply. */
    private List<PDPage> removed;

    /**
     * @param panel   the panel showing the document, never null
     * @param indexes zero-based pages to remove, any order, duplicates ignored; never null or empty
     */
    public DeletePagesEdit(PDFViewerPanel panel, int[] indexes) {
        SUS.checkIfNull("panel null", panel);
        SUS.checkIfNull("indexes null", indexes);
        int[] sorted = Arrays.stream(indexes).distinct().sorted().toArray();
        if (sorted.length == 0)
            throw new IllegalArgumentException("no pages to delete");
        this.panel = panel;
        this.indexes = sorted;
    }

    @Override
    public String name() {
        int n = indexes.length;
        return "Delete " + n + (n == 1 ? " page" : " pages");
    }

    @Override
    public void apply() {
        if (removed == null) {
            List<PDPage> pages = new ArrayList<>(indexes.length);
            synchronized (panel.getDocumentLock()) {
                PDDocument doc = panel.getDocument();
                if (doc == null)
                    return;
                int count = doc.getNumberOfPages();
                for (int p : indexes) {
                    if (p < 0 || p >= count)
                        throw new IllegalArgumentException("Page " + (p + 1) + " is out of range (1-" + count + ").");
                    pages.add(doc.getPage(p));
                }
            }
            removed = Collections.unmodifiableList(pages);
        }
        int remaining = panel.getPageCount() - removed.size();
        panel.removePagesDirect(removed, Math.max(0, Math.min(indexes[0], remaining - 1)));
    }

    @Override
    public void revert() {
        if (removed == null)
            return;
        panel.insertPagesDirect(removed, indexes, indexes[0]);
    }

    @Override
    public int[] affectedPages() {
        return indexes.clone();
    }

    @Override
    public boolean structural() {
        return true;
    }

    /** @return the page objects this edit removed, empty before the first apply */
    public List<PDPage> getRemovedPages() {
        return removed == null ? Collections.<PDPage>emptyList() : removed;
    }
}
