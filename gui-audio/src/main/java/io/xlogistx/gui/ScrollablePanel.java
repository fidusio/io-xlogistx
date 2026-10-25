package io.xlogistx.gui;

import javax.swing.JPanel;
import javax.swing.JViewport;
import javax.swing.Scrollable;
import java.awt.Dimension;
import java.awt.LayoutManager;
import java.awt.Rectangle;

/**
 * A panel meant to be a {@link javax.swing.JScrollPane}'s view: it always follows the viewport's
 * width (so its content wraps instead of scrolling sideways) and follows the viewport's height
 * while it fits — which lets its layout centre a card in the free space — and scrolls vertically
 * only once its content is taller than the viewport.
 */
public class ScrollablePanel extends JPanel implements Scrollable {

    public ScrollablePanel(LayoutManager layout) {
        super(layout);
    }

    @Override
    public Dimension getPreferredScrollableViewportSize() {
        return getPreferredSize();
    }

    @Override
    public int getScrollableUnitIncrement(Rectangle visibleRect, int orientation, int direction) {
        return 16;
    }

    @Override
    public int getScrollableBlockIncrement(Rectangle visibleRect, int orientation, int direction) {
        return Math.max(16, (orientation == java.awt.Adjustable.VERTICAL ? visibleRect.height : visibleRect.width) - 16);
    }

    @Override
    public boolean getScrollableTracksViewportWidth() {
        return true;
    }

    @Override
    public boolean getScrollableTracksViewportHeight() {
        if (getParent() instanceof JViewport) {
            return getParent().getHeight() >= getPreferredSize().height;
        }
        return false;
    }
}
