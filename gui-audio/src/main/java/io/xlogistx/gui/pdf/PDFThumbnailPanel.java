package io.xlogistx.gui.pdf;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.Scrollable;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.GraphicsConfiguration;
import java.awt.Point;
import java.awt.Rectangle;
import java.awt.RenderingHints;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.geom.AffineTransform;
import java.awt.image.BufferedImage;
import java.util.ArrayList;
import java.util.List;

/**
 * The page thumbnails of a {@link PDFViewerPanel}: one small picture per page
 * in a column, rendered lazily on the viewer's render thread as they are
 * painted, the current page framed in blue. A click shows that page; a drag
 * moves the page in front of the thumbnail the pointer is released on (a blue
 * line shows where) through {@link PDFViewerPanel#movePages}, which a host's
 * edit delegate can make undoable. The viewer owns the panel (see
 * {@link PDFViewerPanel#setThumbnailsVisible}), reloads it whenever its page
 * views are rebuilt and drops one picture when a page is invalidated.
 */
public final class PDFThumbnailPanel extends JPanel implements Scrollable {

    /** Width of a thumbnail picture in pixels (at device scale 1). */
    public static final int THUMB_WIDTH = 100;
    /** Space around the pictures, the frame around each, the page number line, and the drag threshold. */
    static final int GAP = 10, PAD = 4, LABEL_HEIGHT = 16, DRAG_SLOP = 5;
    private static final Color FRAME = new Color(30, 110, 220), RULE = new Color(170, 170, 170), BACKGROUND = new Color(236, 236, 236);

    private final PDFViewerPanel viewer;
    private final List<Thumb> thumbs = new ArrayList<>();
    private int current = -1;
    /** Drag state: the pressed thumbnail, where it would drop, the press point. */
    private int dragFrom = -1, dropIndex = -1;
    private Point pressPoint;
    private boolean dragging;

    PDFThumbnailPanel(PDFViewerPanel viewer) {
        this.viewer = viewer;
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
        setBorder(BorderFactory.createEmptyBorder(GAP / 2, GAP, GAP / 2, GAP));
        setBackground(BACKGROUND);
        setOpaque(true);
        setAutoscrolls(true);
        MouseAdapter mouse = new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                if (!SwingUtilities.isLeftMouseButton(e))
                    return;
                pressPoint = e.getPoint();
                dragFrom = indexAt(pressPoint);
                dragging = false;
                dropIndex = -1;
            }

            @Override
            public void mouseDragged(MouseEvent e) {
                if (dragFrom < 0 || pressPoint == null)
                    return;
                if (!dragging) {
                    if (e.getPoint().distance(pressPoint) < DRAG_SLOP)
                        return;
                    dragging = true;
                    setCursor(Cursor.getPredefinedCursor(Cursor.MOVE_CURSOR));
                }
                dropIndex = dropIndexAt(e.getPoint());
                repaint();
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                if (!SwingUtilities.isLeftMouseButton(e))
                    return;
                int from = dragFrom, to = dropIndex;
                boolean wasDragging = dragging;
                dragFrom = -1;
                dropIndex = -1;
                dragging = false;
                pressPoint = null;
                setCursor(Cursor.getDefaultCursor());
                repaint();
                if (wasDragging) {
                    if (from >= 0 && to >= 0 && to != from && to != from + 1)
                        PDFThumbnailPanel.this.viewer.movePages(new int[]{from}, to);
                } else if (from >= 0 && indexAt(e.getPoint()) == from)
                    PDFThumbnailPanel.this.viewer.gotoPage(from);
            }
        };
        addMouseListener(mouse);
        addMouseMotionListener(mouse);
        viewer.addPageChangeListener((page, count) -> setCurrent(page));
    }

    /** Rebuilds one thumbnail per page of the viewer's document (EDT). */
    void reload() {
        removeAll();
        thumbs.clear();
        dragFrom = -1;
        dropIndex = -1;
        dragging = false;
        int n = viewer.getPageCount();
        for (int i = 0; i < n; i++) {
            float[] size = viewer.pageSizePt(i);
            Thumb t = new Thumb(i, size[0], size[1]);
            if (i > 0)
                add(Box.createVerticalStrut(GAP));
            t.setAlignmentX(CENTER_ALIGNMENT);
            add(t);
            thumbs.add(t);
        }
        current = viewer.getCurrentPage();
        revalidate();
        repaint();
    }

    /** Drops a page's picture so it is rendered again (EDT). */
    void invalidateThumbnail(int page) {
        if (page < 0 || page >= thumbs.size())
            return;
        Thumb t = thumbs.get(page);
        t.image = null;
        t.version++;
        t.pending = false;
        t.repaint();
    }

    private void setCurrent(int page) {
        if (page == current)
            return;
        current = page;
        if (page >= 0 && page < thumbs.size())
            scrollRectToVisible(thumbs.get(page).getBounds());
        repaint();
    }

    /** @return the number of thumbnails (pages) */
    public int getThumbnailCount() {
        return thumbs.size();
    }

    /** @return the framed (current) page, -1 when none */
    public int getCurrentIndex() {
        return current;
    }

    /** @return a thumbnail's bounds in this panel */
    public Rectangle getThumbnailBounds(int index) {
        return thumbs.get(index).getBounds();
    }

    /** @return a thumbnail's rendered picture, null until rendered (see {@link #requestThumbnail}) */
    public BufferedImage getThumbnailImage(int index) {
        return thumbs.get(index).image;
    }

    /** Renders a thumbnail on the viewer's render thread if it has no picture yet (painting does this by itself). */
    public void requestThumbnail(int index) {
        request(thumbs.get(index));
    }

    /** @return the thumbnail under a point of this panel, -1 when none */
    public int indexAt(Point p) {
        for (Thumb t : thumbs)
            if (t.getBounds().contains(p))
                return t.index;
        return -1;
    }

    /**
     * @return where a page dragged to a point of this panel lands: the index of
     *         the thumbnail whose upper half the point is in, or of the next one
     *         below; the page count below the last thumbnail
     */
    public int dropIndexAt(Point p) {
        for (Thumb t : thumbs) {
            Rectangle b = t.getBounds();
            if (p.y < b.y + b.height / 2)
                return t.index;
        }
        return thumbs.size();
    }

    /** @return true while a thumbnail is being dragged */
    public boolean isDragging() {
        return dragging;
    }

    private void request(Thumb t) {
        if (t.pending || t.image != null)
            return;
        t.pending = true;
        final int gen = viewer.renderGeneration(), ver = t.version, index = t.index;
        final int widthPx = Math.round(THUMB_WIDTH * deviceScale());
        PDFViewerPanel.renderExecutor().submit(() -> {
            BufferedImage img = viewer.renderThumbnail(index, widthPx, gen);
            SwingUtilities.invokeLater(() -> {
                if (ver != t.version || !thumbs.contains(t))
                    return; // invalidated or reloaded meanwhile: a newer request is on its way
                t.pending = false;
                if (img != null) {
                    t.image = img;
                    t.repaint();
                }
            });
        });
    }

    private float deviceScale() {
        GraphicsConfiguration gc = getGraphicsConfiguration();
        if (gc == null)
            return 1f;
        AffineTransform t = gc.getDefaultTransform();
        return t == null ? 1f : (float) Math.max(1.0, t.getScaleX());
    }

    @Override
    public void paint(Graphics g) {
        super.paint(g);
        if (!dragging || dropIndex < 0 || thumbs.isEmpty())
            return;
        int y;
        if (dropIndex < thumbs.size())
            y = thumbs.get(dropIndex).getY() - GAP / 2;
        else {
            Rectangle last = thumbs.get(thumbs.size() - 1).getBounds();
            y = last.y + last.height + GAP / 2;
        }
        Graphics2D g2 = (Graphics2D) g.create();
        try {
            g2.setColor(FRAME);
            g2.setStroke(new BasicStroke(3f));
            g2.drawLine(GAP / 2, y, getWidth() - GAP / 2, y);
        } finally {
            g2.dispose();
        }
    }

    // ------------------------------------------------------------------ Scrollable

    @Override
    public Dimension getPreferredScrollableViewportSize() {
        return getPreferredSize();
    }

    @Override
    public int getScrollableUnitIncrement(Rectangle visibleRect, int orientation, int direction) {
        return 20;
    }

    @Override
    public int getScrollableBlockIncrement(Rectangle visibleRect, int orientation, int direction) {
        return orientation == SwingConstants.VERTICAL ? Math.max(20, visibleRect.height - 20) : Math.max(20, visibleRect.width - 20);
    }

    @Override
    public boolean getScrollableTracksViewportWidth() {
        return true;
    }

    @Override
    public boolean getScrollableTracksViewportHeight() {
        return false;
    }

    /** One page: a picture in page proportions with its number underneath, framed when current. */
    private final class Thumb extends JComponent {
        final int index;
        final int pageW, pageH;
        BufferedImage image;
        boolean pending;
        int version;

        Thumb(int index, float widthPt, float heightPt) {
            this.index = index;
            pageW = THUMB_WIDTH;
            pageH = Math.max(1, Math.round(THUMB_WIDTH * heightPt / Math.max(1f, widthPt)));
            Dimension d = new Dimension(pageW + 2 * PAD, pageH + 2 * PAD + LABEL_HEIGHT);
            setPreferredSize(d);
            setMinimumSize(d);
            setMaximumSize(d);
            setSize(d);
            setOpaque(false);
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            try {
                g2.setColor(Color.WHITE);
                g2.fillRect(PAD, PAD, pageW, pageH);
                if (image != null) {
                    g2.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BILINEAR);
                    g2.drawImage(image, PAD, PAD, pageW, pageH, null);
                } else
                    request(this);
                boolean isCurrent = index == current;
                g2.setColor(isCurrent ? FRAME : RULE);
                g2.setStroke(new BasicStroke(isCurrent ? 2f : 1f));
                g2.drawRect(PAD - 1, PAD - 1, pageW + 1, pageH + 1);
                g2.setColor(isCurrent ? FRAME : Color.DARK_GRAY);
                String label = String.valueOf(index + 1);
                FontMetrics fm = g2.getFontMetrics();
                g2.drawString(label, (getWidth() - fm.stringWidth(label)) / 2, pageH + 2 * PAD + fm.getAscent());
            } finally {
                g2.dispose();
            }
        }
    }
}
