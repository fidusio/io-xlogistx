package io.xlogistx.gui.test;

import io.xlogistx.gui.GUIUtil;

import javax.swing.*;
import java.awt.*;
import java.awt.image.BufferedImage;

/**
 * Interactive demo for {@link GUIUtil#captureSelectedArea()}.
 * <p>
 * Click "Capture Area": the full-screen translucent selection overlay appears —
 * drag a rectangle with the mouse. On release the overlay closes and the demo shows
 * the selected coordinates plus a screenshot of the selected region.
 * <p>
 * The capture call blocks, so the demo runs it on a background thread — never on
 * the EDT (this also demonstrates the intended usage pattern).
 */
public class CaptureSelectedAreaDemo {

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            JFrame frame = new JFrame("Capture Selected Area Demo");
            frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            frame.setLayout(new BorderLayout(10, 10));

            JButton captureBtn = new JButton("Capture Area");
            JLabel resultLabel = new JLabel("No selection yet — click Capture Area and drag on the screen");
            JLabel imageLabel = new JLabel();
            imageLabel.setHorizontalAlignment(SwingConstants.CENTER);

            JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
            top.add(captureBtn);
            top.add(resultLabel);

            frame.add(top, BorderLayout.NORTH);
            frame.add(GUIUtil.createScrollPane(imageLabel, "Captured Image", null, new Dimension(640, 400)),
                    BorderLayout.CENTER);

            captureBtn.addActionListener(e -> {
                captureBtn.setEnabled(false);
                resultLabel.setText("Drag a rectangle on the screen...");

                // captureSelectedArea() blocks until the mouse is released, so it must
                // run off the EDT
                Thread worker = new Thread(() -> {
                    try {
                        Rectangle area = GUIUtil.captureSelectedArea();
                        BufferedImage screenshot = (area.width > 0 && area.height > 0)
                                ? GUIUtil.captureSelectedArea(area)
                                : null;

                        SwingUtilities.invokeLater(() -> {
                            resultLabel.setText(String.format("Selected: x=%d y=%d w=%d h=%d",
                                    area.x, area.y, area.width, area.height));
                            imageLabel.setIcon(screenshot != null ? new ImageIcon(screenshot) : null);
                            imageLabel.setText(screenshot == null ? "empty selection (click without drag)" : null);
                            captureBtn.setEnabled(true);
                        });
                    } catch (Exception ex) {
                        ex.printStackTrace();
                        SwingUtilities.invokeLater(() -> {
                            resultLabel.setText("Capture failed: " + ex);
                            captureBtn.setEnabled(true);
                        });
                    }
                }, "capture-selected-area");
                worker.setDaemon(true);
                worker.start();
            });

            frame.pack();
            frame.setLocationRelativeTo(null);
            frame.setVisible(true);
        });
    }
}
