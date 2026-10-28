package io.xlogistx.editor.pdf;

import io.xlogistx.gui.pdf.PDFViewerPanel;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.zoxweb.shared.util.SUS;

import java.util.Arrays;

/**
 * Undoable rotation of pages by a multiple of 90 degrees. The first
 * {@link #apply()} captures the current rotations; apply sets
 * {@code (current + delta) mod 360}, revert restores the captured values, both
 * through {@link PDFViewerPanel#setRotationsDirect(int[], int[], int)}.
 */
public final class RotatePagesEdit implements PDFEdit {

    private final PDFViewerPanel panel;
    private final int[] pages;
    private final int delta;
    private int[] before;
    private int[] after;

    /**
     * @param panel the panel showing the document, never null
     * @param pages zero-based pages, any order, duplicates ignored; never null or empty
     * @param delta degrees, a multiple of 90 (positive = clockwise)
     */
    public RotatePagesEdit(PDFViewerPanel panel, int[] pages, int delta) {
        SUS.checkIfNull("panel null", panel);
        SUS.checkIfNull("pages null", pages);
        int[] sorted = Arrays.stream(pages).distinct().sorted().toArray();
        if (sorted.length == 0)
            throw new IllegalArgumentException("no pages to rotate");
        if (delta % 90 != 0)
            throw new IllegalArgumentException("rotation must be a multiple of 90: " + delta);
        this.panel = panel;
        this.pages = sorted;
        this.delta = ((delta % 360) + 360) % 360;
    }

    @Override
    public String name() {
        int n = pages.length;
        return "Rotate " + n + (n == 1 ? " page" : " pages") + (delta == 90 ? " clockwise" : delta == 270 ? " counter-clockwise" : " by " + delta + "°");
    }

    @Override
    public void apply() {
        if (before == null) {
            before = new int[pages.length];
            after = new int[pages.length];
            synchronized (panel.getDocumentLock()) {
                PDDocument doc = panel.getDocument();
                if (doc == null)
                    return;
                int count = doc.getNumberOfPages();
                for (int i = 0; i < pages.length; i++) {
                    if (pages[i] < 0 || pages[i] >= count)
                        throw new IllegalArgumentException("Page " + (pages[i] + 1) + " is out of range (1-" + count + ").");
                    before[i] = doc.getPage(pages[i]).getRotation();
                    after[i] = (before[i] + delta) % 360;
                }
            }
        }
        panel.setRotationsDirect(pages, after, pages[0]);
    }

    @Override
    public void revert() {
        if (before == null)
            return;
        panel.setRotationsDirect(pages, before, pages[0]);
    }

    @Override
    public int[] affectedPages() {
        return pages.clone();
    }

    @Override
    public boolean structural() {
        return true;
    }
}
