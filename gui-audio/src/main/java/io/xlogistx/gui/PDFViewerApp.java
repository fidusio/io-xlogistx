package io.xlogistx.gui;

import io.xlogistx.common.util.NVColor;

import javax.swing.*;
import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;

/**
 * Standalone PDF viewer application around {@link PDFViewerPanel}:
 * {@code PDFViewerApp [file.pdf | file.md | image.png]}. Without an argument the
 * viewer starts empty; use the toolbar Open button to load a PDF, a Markdown file
 * or an image (PNG, JPEG, GIF, BMP; shown as a one-page document). The
 * title bar follows the loaded file and the current page, and closing the
 * window asks before unsaved changes are discarded.
 */
public class PDFViewerApp {

    private static final String TITLE = "PDF Viewer";

    private static String title(PDFViewerPanel viewer, int page, int count) {
        if (count <= 0)
            return TITLE;
        File f = viewer.getFile();
        String name = (f != null ? f.getName() : "untitled") + (viewer.isModified() ? " *" : "");
        return TITLE + " - " + name + "  [" + (page + 1) + " / " + count + "]";
    }

    /**
     * Main entry point.
     *
     * @param args command line arguments (optional PDF, Markdown or image file to open)
     */
    public static void main(String[] args) {
        File file = args.length > 0 ? new File(args[0]) : null;
        SwingUtilities.invokeLater(() -> {
            JFrame frame = new JFrame(TITLE);
            frame.setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
            frame.setIconImages(IconUtil.windowIcons(IconUtil.PDFIcon::new, Color.WHITE, NVColor.BOOTSTRAP_RED.getValue()));

            PDFViewerPanel viewer = new PDFViewerPanel();
            viewer.addPageChangeListener((page, count) -> frame.setTitle(title(viewer, page, count)));
            frame.addWindowListener(new WindowAdapter() {
                @Override
                public void windowClosing(WindowEvent e) {
                    if (viewer.confirmDiscard()) {
                        viewer.close();
                        System.exit(0);
                    }
                }
            });
            frame.add(viewer, BorderLayout.CENTER);
            frame.setSize(900, 800);
            frame.setLocationRelativeTo(null);
            frame.setVisible(true);

            if (file != null)
                viewer.setPDF(file);
        });
    }
}
