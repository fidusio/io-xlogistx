package io.xlogistx.gui;

import javax.swing.JViewport;
import javax.swing.SwingUtilities;
import java.awt.Cursor;
import java.awt.Point;
import java.awt.Rectangle;
import java.awt.event.MouseEvent;

/**
 * The handlers of the built-in {@link PDFViewerPanel.Tool}s. Package-private:
 * the panel creates one of each per instance.
 */
final class PDFToolHandlers {

    private PDFToolHandlers() {
    }

    /** {@link PDFViewerPanel.Tool#PAN}: a drag scrolls the view. */
    static final class PanHandler extends PDFToolHandler {
        /** Where the drag is, in viewport coordinates (the pages move under the pointer); null when idle. */
        private Point origin;

        @Override
        public void cancel(PDFToolContext c) {
            origin = null;
        }

        @Override
        public void pressed(PDFToolContext c, MouseEvent e) {
            origin = SwingUtilities.convertPoint(c.owner(), e.getPoint(), c.viewport());
            if (c.linkAt(e.getPoint()) == null)
                c.setCursor(Cursor.getPredefinedCursor(Cursor.MOVE_CURSOR));
        }

        @Override
        public void dragged(PDFToolContext c, MouseEvent e) {
            if (origin == null)
                return;
            c.setCursor(Cursor.getPredefinedCursor(Cursor.MOVE_CURSOR));
            JViewport vp = c.viewport();
            Point now = SwingUtilities.convertPoint(c.owner(), e.getPoint(), vp);
            Point pos = vp.getViewPosition();
            int maxX = Math.max(0, c.owner().getWidth() - vp.getWidth());
            int maxY = Math.max(0, c.owner().getHeight() - vp.getHeight());
            pos.x = Math.max(0, Math.min(maxX, pos.x - (now.x - origin.x)));
            pos.y = Math.max(0, Math.min(maxY, pos.y - (now.y - origin.y)));
            vp.setViewPosition(pos);
            origin = now;
        }

        @Override
        public void released(PDFToolContext c, MouseEvent e) {
            origin = null;
        }
    }

    /** {@link PDFViewerPanel.Tool#SELECT_TEXT}: a drag selects text, a double click a word. */
    static final class SelectTextHandler extends PDFToolHandler {
        /** {page, index} where the drag started; null when idle. */
        private int[] anchor;

        @Override
        public void cancel(PDFToolContext c) {
            anchor = null;
        }

        @Override
        public void pressed(PDFToolContext c, MouseEvent e) {
            int[] hit = c.hitText(e.getPoint());
            if (hit != null && e.getClickCount() == 2) {
                anchor = null;
                c.selectWordAt(hit[0], hit[1]);
                return;
            }
            anchor = hit;
            c.clearSelection();
        }

        @Override
        public void dragged(PDFToolContext c, MouseEvent e) {
            if (anchor == null)
                return;
            int[] hit = c.hitText(e.getPoint());
            if (hit != null)
                c.select(anchor[0], anchor[1], hit[0], hit[1]);
            c.owner().scrollRectToVisible(new Rectangle(e.getX(), e.getY(), 1, 1));
        }

        @Override
        public void released(PDFToolContext c, MouseEvent e) {
            anchor = null;
        }

        @Override
        public Cursor cursor() {
            return Cursor.getPredefinedCursor(Cursor.TEXT_CURSOR);
        }
    }

    /**
     * {@link PDFViewerPanel.Tool#ZOOM_TO_SELECTION}: the panel rubber-bands the zoom
     * rectangle itself (the gesture spans pages), this handler only declares it.
     */
    static final class ZoomSelectionHandler extends PDFToolHandler {
        @Override
        public Cursor cursor() {
            return Cursor.getPredefinedCursor(Cursor.CROSSHAIR_CURSOR);
        }

        @Override
        public boolean marqueeZoom() {
            return true;
        }
    }
}
