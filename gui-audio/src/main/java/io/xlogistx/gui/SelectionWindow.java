package io.xlogistx.gui;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.MouseMotionAdapter;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;

/**
 * Semi-transparent, always-on-top window covering one monitor that lets the user
 * drag out a rectangular screen selection with the mouse. The selection outline is
 * drawn in red while dragging. {@link GUIUtil#captureSelectedArea()} shows one
 * instance per monitor — a single window spanning all monitors would be clipped to
 * one display on macOS ("Displays have separate Spaces"), so multi-monitor support
 * uses one overlay per display everywhere.
 * <p>
 * When the mouse is released, the selection is finalized and the supplied
 * {@link Condition} is signaled so a thread blocked in
 * {@link GUIUtil#captureSelectedArea()} can resume and read
 * {@link #getSelectedArea()}.
 */
public class SelectionWindow extends JWindow {
        private Point startPoint;
        private Point endPoint;
        private Rectangle selectionBounds;
        private boolean selectionMade = false;


    /**
     * Creates the selection overlay on the default screen device.
     *
     * @param lock      lock guarding the condition, may be null if no signaling is needed
     * @param condition condition signaled when the user releases the mouse, may be null
     */
    public SelectionWindow(final Lock lock, final Condition condition) {
        this(GraphicsEnvironment.getLocalGraphicsEnvironment().getDefaultScreenDevice().getDefaultConfiguration(),
                lock, condition);
    }

    /**
     * Creates the selection overlay sized to the given screen configuration's monitor.
     *
     * @param gc        screen configuration whose monitor this overlay covers
     * @param lock      lock guarding the condition, may be null if no signaling is needed
     * @param condition condition signaled when the user releases the mouse, may be null
     */
    public SelectionWindow(GraphicsConfiguration gc, final Lock lock, final Condition condition) {
        super(gc);
        setAlwaysOnTop(true);
        // the monitor's region of the virtual screen: the origin may be non-zero,
        // even negative when the monitor sits left of or above the primary
        setBounds(gc.getBounds());
        setBackground(new Color(0, 0, 0, 50)); // Semi-transparent background

        // Mouse listeners
        addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {

                startPoint = e.getPoint();
                endPoint = startPoint;
                //System.out.println("mousePreset: " + startPoint);
                repaint();
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                endPoint = e.getPoint();
                //System.out.println("mouseReleased: " + endPoint);
                if (lock != null && condition != null)
                {
                    // finalize the selection under the lock so a waiter checking
                    // isSelectionMade() sees a consistent state with the signal
                    lock.lock();
                    try {
                        selectionBounds = toScreenRectangle();
                        selectionMade = true;
                        condition.signalAll();
                    }
                    finally {
                        lock.unlock();
                    }
                }
                else
                {
                    selectionBounds = toScreenRectangle();
                    selectionMade = true;
                }
            }
        });

        addMouseMotionListener(new MouseMotionAdapter() {
            @Override
            public void mouseDragged(MouseEvent e) {
                endPoint = e.getPoint();
                repaint();
            }
        });
    }

    @Override
    public void paint(Graphics g) {
        super.paint(g);
        if (startPoint != null && endPoint != null) {
            Graphics2D g2d = (Graphics2D) g;
            g2d.setColor(Color.RED);
            Rectangle rect = calculateSelectionRectangle();
            g2d.draw(rect);
        }
    }

    /**
     * Normalizes the drag start/end points into a rectangle regardless of drag
     * direction, in window coordinates (used for painting).
     *
     * @return the rectangle spanned by the current start and end points
     */
    private Rectangle calculateSelectionRectangle() {
        int x = Math.min(startPoint.x, endPoint.x);
        int y = Math.min(startPoint.y, endPoint.y);
        int width = Math.abs(startPoint.x - endPoint.x);
        int height = Math.abs(startPoint.y - endPoint.y);
        return new Rectangle(x, y, width, height);
    }

    /**
     * Converts the current selection to screen coordinates by offsetting it with the
     * window origin — this monitor's origin in the virtual screen. AWT keeps sending
     * drag events to the pressed window even when the mouse leaves it, so the result
     * is clipped at this monitor's edge.
     *
     * @return the selection rectangle in screen coordinates, confined to this monitor
     */
    private Rectangle toScreenRectangle() {
        Rectangle ret = calculateSelectionRectangle();
        ret.translate(getX(), getY());
        return ret.intersection(getBounds());
    }

    /**
     * Returns the finalized selection.
     *
     * @return the selected rectangle in screen coordinates, or null if the user has
     *         not released the mouse yet
     */
    public Rectangle getSelectedArea() {
        return selectionBounds;
    }

    /**
     * Indicates whether the user has completed a selection.
     *
     * @return true once the mouse has been released and the selection finalized
     */
    public boolean isSelectionMade() {
        return selectionMade;
    }
}