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
 * Undoable move of pages to another position. {@code target} uses the Insert
 * positions: the moved block lands in front of the page that is at
 * {@code target} <em>before</em> the move (0 = beginning, page count or more =
 * end, {@code n} = after page {@code n}). The first {@link #apply()} captures the
 * page objects and their original indexes; revert moves them back there.
 */
public final class MovePagesEdit implements PDFEdit {

    private final PDFViewerPanel panel;
    private final int[] pages;
    private final int target;
    private List<PDPage> moved;
    private int[] landing;

    /**
     * @param panel  the panel showing the document, never null
     * @param pages  zero-based pages to move, any order, duplicates ignored; never null or empty
     * @param target zero-based index (before the move) the block lands in front of; clamped to the page count
     */
    public MovePagesEdit(PDFViewerPanel panel, int[] pages, int target) {
        SUS.checkIfNull("panel null", panel);
        SUS.checkIfNull("pages null", pages);
        int[] sorted = Arrays.stream(pages).distinct().sorted().toArray();
        if (sorted.length == 0)
            throw new IllegalArgumentException("no pages to move");
        this.panel = panel;
        this.pages = sorted;
        this.target = Math.max(0, target);
    }

    @Override
    public String name() {
        int n = pages.length;
        return "Move " + n + (n == 1 ? " page" : " pages");
    }

    @Override
    public void apply() {
        if (moved == null) {
            List<PDPage> list = new ArrayList<>(pages.length);
            synchronized (panel.getDocumentLock()) {
                PDDocument doc = panel.getDocument();
                if (doc == null)
                    return;
                int count = doc.getNumberOfPages();
                for (int p : pages) {
                    if (p < 0 || p >= count)
                        throw new IllegalArgumentException("Page " + (p + 1) + " is out of range (1-" + count + ").");
                    list.add(doc.getPage(p));
                }
                int t = Math.min(target, count);
                int shift = 0;
                for (int p : pages)
                    if (p < t)
                        shift++;
                landing = new int[pages.length];
                for (int i = 0; i < pages.length; i++)
                    landing[i] = t - shift + i;
            }
            moved = Collections.unmodifiableList(list);
        }
        panel.movePagesDirect(moved, landing, landing[0]);
    }

    @Override
    public void revert() {
        if (moved == null)
            return;
        panel.movePagesDirect(moved, pages, pages[0]);
    }

    @Override
    public int[] affectedPages() {
        return landing == null ? pages.clone() : landing.clone();
    }

    @Override
    public boolean structural() {
        return true;
    }

    /** @return the zero-based indexes the moved pages occupy after apply, empty before the first apply */
    public int[] getLandingIndexes() {
        return landing == null ? new int[0] : landing.clone();
    }
}
