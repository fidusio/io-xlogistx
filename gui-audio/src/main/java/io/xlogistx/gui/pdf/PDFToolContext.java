package io.xlogistx.gui.pdf;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.annotation.AnnotationFilter;

import javax.swing.JComponent;
import javax.swing.JViewport;
import java.awt.Cursor;
import java.awt.Point;
import java.awt.Rectangle;
import java.awt.geom.Point2D;
import java.awt.geom.Rectangle2D;
import java.util.List;

/**
 * What a {@link PDFToolHandler} may touch of its {@link PDFViewerPanel}: hit
 * testing, coordinate conversion, the text selection, repainting and a few
 * view operations. Implemented by the panel; handlers never reach into panel
 * fields directly. Points given to and returned from this interface are in
 * <em>pages-panel</em> pixel coordinates (the component the mouse events come
 * from) unless the name says otherwise. All methods must be called on the EDT.
 */
public interface PDFToolContext {

    /** @return the panel this context belongs to */
    PDFViewerPanel panel();

    /** @return the component the mouse events come from (the stack of pages); popups and scrolling target it */
    JComponent owner();

    /** @return the viewport showing the pages */
    JViewport viewport();

    /** @return the current zoom factor (points to pixels) */
    float zoom();

    /** @return the number of pages, 0 when nothing is loaded */
    int pageCount();

    /**
     * @param p a point over the pages
     * @return the zero-based index of the page nearest to the point, -1 when nothing is loaded
     */
    int pageAt(Point p);

    /**
     * @param page zero-based page index
     * @param p    a point over the pages
     * @return the point in PDF points from the displayed page's top-left corner (view space)
     */
    Point2D.Float toPagePt(int page, Point p);

    /**
     * @param page zero-based page index
     * @param pt   a point in view space of that page
     * @return the same point over the pages, in pixels
     */
    Point toPanelPoint(int page, Point2D pt);

    /**
     * @param page zero-based page index
     * @return the page's bounds over the pages, in pixels; empty when out of range
     */
    Rectangle pageBounds(int page);

    /** @return the loaded document, null when none; access it only under {@link #docLock()} */
    PDDocument document();

    /** @return the lock every document access must hold */
    Object docLock();

    /** Repaints one page (its raster is kept). @param page zero-based page index */
    void repaintPage(int page);

    /** Drops one page's raster so it is rendered again. @param page zero-based page index */
    void invalidatePage(int page);

    /**
     * Text hit test.
     *
     * @param p a point over the pages
     * @return {@code {page, charIndex}} of the nearest character, null when there is no text
     */
    int[] hitText(Point p);

    /** Selects a text range, see {@link PDFViewerPanel#select(int, int, int, int)}. */
    void select(int startPage, int startIndex, int endPage, int endIndex);

    /** Selects the word around a character. */
    void selectWordAt(int page, int index);

    /** Clears the text selection. */
    void clearSelection();

    /** @return whether some text is selected */
    boolean hasSelection();

    /** @return {@code {startPage, startIndex, endPage, endIndex}}, null when nothing is selected */
    int[] selectionRange();

    /**
     * @param page zero-based page index
     * @return the selected text's glyph rectangles on that page, one per line, in view
     *         space (points, top-left origin); empty when the page holds no selection
     */
    List<Rectangle2D.Float> selectionRects(int page);

    /**
     * @param page zero-based page index
     * @return the selected characters' text positions on that page (as the text
     *         extractor saw them), in selection order; empty when none
     */
    List<org.apache.pdfbox.text.TextPosition> selectionTextPositions(int page);

    /**
     * Restricts which annotations the renderer draws (e.g. to hide the one being
     * dragged); the caller invalidates the affected pages.
     *
     * @param filter the filter, null to draw every annotation again
     */
    void setAnnotationFilter(AnnotationFilter filter);

    /**
     * @param p a point over the pages
     * @return the followable link under the point, null when none
     */
    PDFViewerPanel.Link linkAt(Point p);

    /** Sets the cursor shown over the pages. @param cursor the cursor, null for the handler's default */
    void setCursor(Cursor cursor);

    /** Shows an error dialog parented to the panel. @param message the text */
    void showError(String message);

    /**
     * Hosts a component over an area of a page (an in-place editor): it becomes
     * a child of that page's view, placed over the area and resized with the
     * zoom, so it scrolls with the page. One at a time; {@link #hideOverlay()}
     * removes it, as does the page's view being rebuilt.
     *
     * @param comp     the component, never null
     * @param page     zero-based page
     * @param viewRect the area in view space (points, top-left origin of the page)
     */
    void showOverlay(JComponent comp, int page, java.awt.geom.Rectangle2D viewRect);

    /** Removes the overlay component, if any. */
    void hideOverlay();

    /** @return the overlay component, null when none is shown */
    JComponent overlay();
}
