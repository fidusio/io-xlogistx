package io.xlogistx.widget;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.MouseMotionAdapter;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;

public class SelectionWindow extends JWindow {
        private Point startPoint;
        private Point endPoint;
        private Rectangle selectionBounds;
        private boolean selectionMade = false;



    public SelectionWindow(final Lock lock, final Condition condition) {
        setAlwaysOnTop(true);
        //System.out.println(Toolkit.getDefaultToolkit().getScreenSize());
        setSize(Toolkit.getDefaultToolkit().getScreenSize());
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
                selectionBounds = calulateSelectionRectangle();
                //System.out.println("mouseReleased: " + endPoint);
                selectionMade = true;
                if (lock != null && condition != null)
                {
                    lock.lock();;
                    try {
                        condition.signalAll();
                    }
                    finally {
                        lock.unlock();
                    }
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
            Rectangle rect = calulateSelectionRectangle();
            g2d.draw(rect);
        }
    }

    private Rectangle calulateSelectionRectangle() {
        int x = Math.min(startPoint.x, endPoint.x);
        int y = Math.min(startPoint.y, endPoint.y);
        int width = Math.abs(startPoint.x - endPoint.x);
        int height = Math.abs(startPoint.y - endPoint.y);
        return new Rectangle(x, y, width, height);
    }

    public Rectangle getSelectedArea() {
        return selectionBounds;
    }

    public boolean isSelectionMade() {
        return selectionMade;
    }
}