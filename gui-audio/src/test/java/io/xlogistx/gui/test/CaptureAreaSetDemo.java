package io.xlogistx.gui.test;

import io.xlogistx.gui.BackgroundTask;
import io.xlogistx.gui.CaptureArea;
import io.xlogistx.gui.CaptureAreaSet;
import io.xlogistx.gui.GUIUtil;
import io.xlogistx.gui.SnapShot;
import org.zoxweb.shared.util.SUS;

import javax.swing.*;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.util.List;

/**
 * Interactive demo for {@link CaptureAreaSet} snapshot capture.
 * <p>
 * "Add Area": the demo window hides itself, a rectangle is dragged on the screen
 * (via the translucent {@link GUIUtil#captureSelectedArea()} overlay) and named —
 * the window then reappears and the area is added to the set and the list. Select
 * one or more areas and click "Snap Selected", or "Snap All" for the whole set:
 * the sweep runs off the EDT; a single snapshot is shown as-is, multiple snapshots
 * are composed into a captioned grid image. "Remove" deletes the selected areas.
 * <p>
 * Demonstrates the intended threading: the blocking area selection runs on a plain
 * background thread (so the window can be restored on both success and failure),
 * the capture sweep goes through {@link BackgroundTask}, results land on the EDT.
 */
public class CaptureAreaSetDemo {

    /** Longest side an image may occupy inside a grid cell before being scaled down. */
    private static final int MAX_CELL_DIMENSION = 480;
    /** Pixel gap between grid cells and around the grid's outer edge. */
    private static final int GRID_GAP = 10;
    /** Vertical space above each cell's image reserved for its name/sequence caption. */
    private static final int CAPTION_HEIGHT = 18;

    public static void main(String[] args) {
        SwingUtilities.invokeLater(CaptureAreaSetDemo::createAndShow);
    }

    /**
     * Builds and shows the demo frame: button bar on top, area list on the left
     * (multi-select, rendered as {@code name — WxH @ x,y}), snapshot viewer in the
     * center. Must run on the EDT.
     */
    private static void createAndShow() {
        CaptureAreaSet areaSet = new CaptureAreaSet();

        JFrame frame = new JFrame("CaptureAreaSet SnapShot Demo");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setLayout(new BorderLayout(10, 10));

        DefaultListModel<CaptureArea> listModel = new DefaultListModel<>();
        JList<CaptureArea> areaList = new JList<>(listModel);
        areaList.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        areaList.setCellRenderer(new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                                                          boolean isSelected, boolean cellHasFocus) {
                super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                CaptureArea ca = (CaptureArea) value;
                Rectangle r = ca.getCaptureArea();
                setText(String.format("%s — %dx%d @ %d,%d", ca.getName(), r.width, r.height, r.x, r.y));
                return this;
            }
        });

        JButton addBtn = new JButton("Add Area");
        JButton snapSelectedBtn = new JButton("Snap Selected");
        JButton snapAllBtn = new JButton("Snap All");
        JButton removeBtn = new JButton("Remove");
        JLabel statusLabel = new JLabel("No areas yet — click Add Area and drag on the screen");
        JLabel imageLabel = new JLabel();
        imageLabel.setHorizontalAlignment(SwingConstants.CENTER);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        buttons.add(addBtn);
        buttons.add(snapSelectedBtn);
        buttons.add(snapAllBtn);
        buttons.add(removeBtn);
        buttons.add(statusLabel);

        frame.add(buttons, BorderLayout.NORTH);
        frame.add(GUIUtil.createScrollPane(areaList, "Areas", null, new Dimension(260, 400)),
                BorderLayout.WEST);
        frame.add(GUIUtil.createScrollPane(imageLabel, "Latest SnapShot", null, new Dimension(640, 400)),
                BorderLayout.CENTER);

        addBtn.addActionListener(e -> {
            addBtn.setEnabled(false);
            // hide the demo so it is not part of the screen being selected; a plain
            // thread (not BackgroundTask) so the window is restored on error too
            frame.setVisible(false);
            Thread worker = new Thread(() -> {
                Rectangle area = null;
                Exception failure = null;
                try {
                    area = GUIUtil.captureSelectedArea();
                } catch (Exception ex) {
                    failure = ex;
                }
                Rectangle selected = area;
                Exception error = failure;
                SwingUtilities.invokeLater(() -> {
                    frame.setVisible(true);
                    frame.toFront();
                    addBtn.setEnabled(true);
                    if (error != null) {
                        statusLabel.setText("Selection failed: " + error);
                        return;
                    }
                    if (selected.isEmpty()) {
                        statusLabel.setText("Empty selection ignored (click without drag)");
                        return;
                    }
                    String defaultName = "area-" + (listModel.size() + 1);
                    String name = JOptionPane.showInputDialog(frame, "Area name:", defaultName);
                    // null = dialog cancelled, blank = accept the default name
                    if (name == null) {
                        statusLabel.setText("Area discarded");
                        return;
                    }
                    if (SUS.isEmpty(name))
                        name = defaultName;
                    CaptureArea ca = new CaptureArea(name, null, selected);
                    areaSet.addCaptureArea(ca);
                    listModel.addElement(ca);
                    statusLabel.setText(String.format("%s added: x=%d y=%d w=%d h=%d (%d total)",
                            name, selected.x, selected.y, selected.width, selected.height, listModel.size()));
                });
            }, "select-area");
            worker.setDaemon(true);
            worker.start();
        });

        snapSelectedBtn.addActionListener(e -> {
            List<CaptureArea> selected = areaList.getSelectedValuesList();
            if (selected.isEmpty()) {
                statusLabel.setText("Select one or more areas in the list first");
                return;
            }
            snap(frame, snapSelectedBtn, statusLabel, imageLabel, areaSet,
                    selected.toArray(new CaptureArea[0]));
        });

        snapAllBtn.addActionListener(e -> {
            if (listModel.isEmpty()) {
                statusLabel.setText("Add at least one area first");
                return;
            }
            snap(frame, snapAllBtn, statusLabel, imageLabel, areaSet, areaSet.getCaptureAreas());
        });

        removeBtn.addActionListener(e -> {
            List<CaptureArea> selected = areaList.getSelectedValuesList();
            if (selected.isEmpty()) {
                statusLabel.setText("Select one or more areas in the list first");
                return;
            }
            areaSet.removeCaptureAreas(selected.toArray(new CaptureArea[0]));
            selected.forEach(listModel::removeElement);
            statusLabel.setText(selected.size() + " removed (" + listModel.size() + " left)");
        });

        frame.pack();
        frame.setLocationRelativeTo(null);
        frame.setVisible(true);
    }

    /**
     * Runs one capture sweep off the EDT and shows the result on the EDT: one
     * snapshot as-is, several composed into a captioned grid.
     */
    private static void snap(JFrame frame, JButton trigger, JLabel statusLabel, JLabel imageLabel,
                             CaptureAreaSet areaSet, CaptureArea... targets) {
        BackgroundTask.run(frame, trigger, () -> areaSet.takeSnapShots(targets), snaps -> {
            if (snaps.length == 0) {
                statusLabel.setText("Nothing captured (empty or unset rectangles)");
                return;
            }
            BufferedImage display = snaps.length == 1 ? snaps[0].getImage() : gridImage(snaps);
            imageLabel.setIcon(new ImageIcon(display));
            imageLabel.setText(null);
            statusLabel.setText(snaps.length + " snapped — latest: " + snaps[snaps.length - 1]);
        });
    }

    /**
     * Composes the snapshots into one image: a near-square grid of uniform cells,
     * each captioned with the snapshot's area name and sequence number; images larger
     * than {@link #MAX_CELL_DIMENSION} are scaled down proportionally.
     */
    private static BufferedImage gridImage(SnapShot... snaps) {
        int cols = (int) Math.ceil(Math.sqrt(snaps.length));
        int rows = (int) Math.ceil((double) snaps.length / cols);

        int cellW = 1, cellH = 1;
        double[] scales = new double[snaps.length];
        for (int i = 0; i < snaps.length; i++) {
            BufferedImage img = snaps[i].getImage();
            scales[i] = Math.min(1.0, (double) MAX_CELL_DIMENSION / Math.max(img.getWidth(), img.getHeight()));
            cellW = Math.max(cellW, (int) Math.round(img.getWidth() * scales[i]));
            cellH = Math.max(cellH, (int) Math.round(img.getHeight() * scales[i]));
        }

        int gridW = GRID_GAP + cols * (cellW + GRID_GAP);
        int gridH = GRID_GAP + rows * (cellH + CAPTION_HEIGHT + GRID_GAP);
        BufferedImage grid = new BufferedImage(gridW, gridH, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = grid.createGraphics();
        g.setColor(Color.DARK_GRAY);
        g.fillRect(0, 0, gridW, gridH);
        g.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BILINEAR);
        g.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
        g.setFont(new Font("SansSerif", Font.BOLD, 12));

        for (int i = 0; i < snaps.length; i++) {
            int cellX = GRID_GAP + (i % cols) * (cellW + GRID_GAP);
            int cellY = GRID_GAP + (i / cols) * (cellH + CAPTION_HEIGHT + GRID_GAP);

            g.setColor(Color.WHITE);
            g.drawString(snaps[i].getSourceID() + " #" + snaps[i].getSequence(),
                    cellX, cellY + CAPTION_HEIGHT - 5);

            BufferedImage img = snaps[i].getImage();
            int w = (int) Math.round(img.getWidth() * scales[i]);
            int h = (int) Math.round(img.getHeight() * scales[i]);
            // center the image within its cell
            int x = cellX + (cellW - w) / 2;
            int y = cellY + CAPTION_HEIGHT + (cellH - h) / 2;
            g.drawImage(img, x, y, w, h, null);
            g.setColor(Color.GRAY);
            g.drawRect(x - 1, y - 1, w + 1, h + 1);
        }
        g.dispose();
        return grid;
    }
}
