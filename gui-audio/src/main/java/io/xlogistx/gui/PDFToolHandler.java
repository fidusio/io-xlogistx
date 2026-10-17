package io.xlogistx.gui;

import java.awt.Cursor;
import java.awt.Graphics2D;
import java.awt.event.KeyEvent;
import java.awt.event.MouseEvent;

/**
 * Strategy behind a {@link PDFViewerPanel.Tool}: what a plain left-button
 * press / drag / release over the pages does, what it paints on top of a page
 * and which cursor it shows. The panel dispatches to the active handler and
 * keeps the gestures shared by every tool (Shift+drag zoom rectangle, popup
 * menu, link clicks, hover) to itself. Mouse events are in pages-panel
 * coordinates; everything a handler needs from the panel comes through the
 * {@link PDFToolContext}. Handlers for the built-in tools live in the panel;
 * hosts add their own with {@link PDFViewerPanel#setCustomTool(PDFToolHandler)}.
 * <p>
 * A handler keeps gesture state (anchor, origin, ...) in its own fields: one
 * handler instance belongs to one panel. All methods run on the EDT.
 */
public abstract class PDFToolHandler {

    /** The tool became active. @param c the panel's context */
    public void activated(PDFToolContext c) {
    }

    /** Another tool was selected; also ends any gesture in progress. @param c the panel's context */
    public void deactivated(PDFToolContext c) {
        cancel(c);
    }

    /**
     * Aborts a gesture in progress (Escape, document change) without applying it.
     *
     * @param c the panel's context
     */
    public void cancel(PDFToolContext c) {
    }

    /**
     * Left button pressed over the pages (not a popup trigger, not a Shift+drag).
     *
     * @param c the panel's context
     * @param e the event, in pages-panel coordinates
     */
    public void pressed(PDFToolContext c, MouseEvent e) {
    }

    /** Dragged after {@link #pressed}. */
    public void dragged(PDFToolContext c, MouseEvent e) {
    }

    /** Released after {@link #pressed}. */
    public void released(PDFToolContext c, MouseEvent e) {
    }

    /**
     * Pointer moved over the pages with no button down, after the panel set the
     * cursor from {@link #cursor()} (or the hand over a link): a tool may set a
     * more specific cursor through {@link PDFToolContext#setCursor(Cursor)}.
     *
     * @param c the panel's context
     * @param e the event, in pages-panel coordinates
     */
    public void moved(PDFToolContext c, MouseEvent e) {
    }

    /**
     * Key pressed while the pages have the focus; the panel's own bindings
     * (Escape, Ctrl+C, ...) run regardless.
     */
    public void keyPressed(PDFToolContext c, KeyEvent e) {
    }

    /**
     * Paints the tool's overlay on top of a page, after the page raster and the
     * text/search highlights and before the page border. Geometry kept in points
     * is multiplied by {@link PDFToolContext#zoom()} here, so zooming mid-gesture
     * stays correct.
     *
     * @param c    the panel's context
     * @param page zero-based page index
     * @param g2   graphics of that page, origin at its top-left corner, in pixels
     */
    public void paintOverlay(PDFToolContext c, int page, Graphics2D g2) {
    }

    /** @return the cursor shown over the pages while this tool is active and no link is hovered */
    public Cursor cursor() {
        return Cursor.getDefaultCursor();
    }

    /**
     * @return true when a plain drag rubber-bands the zoom rectangle (the panel
     *         then handles the whole gesture and never calls {@link #pressed})
     */
    public boolean marqueeZoom() {
        return false;
    }

    /** @return true when hovering a link shows the hand cursor and a click follows it */
    public boolean followsLinks() {
        return !marqueeZoom();
    }
}
