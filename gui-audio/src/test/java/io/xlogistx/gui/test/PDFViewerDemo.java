package io.xlogistx.gui.test;

import io.xlogistx.gui.MDToPDF;
import io.xlogistx.gui.PDFViewerPanel;

import javax.swing.*;
import java.awt.*;
import java.io.File;

/**
 * Standalone demo for {@link PDFViewerPanel}: {@code PDFViewerDemo [file.pdf]}.
 * Without an argument a generated multi-page sample is shown; use the toolbar
 * Open button to load any PDF. The title bar follows the loaded file and the
 * current page.
 */
public class PDFViewerDemo {

    private static final String PAGE_BREAK = "\n\n<div style=\"page-break-before: always\"></div>\n\n";

    private static String sample() {
        StringBuilder sb = new StringBuilder("# PDFViewerPanel Demo\n\n"
                + "Generated with **MDToPDF**. Try the search field with `chapter`, "
                + "zoom with Ctrl+wheel, drag to pan, PgUp/PgDn to navigate.\n\n"
                + "| Key | Action |\n|---|---|\n| Ctrl +/- | zoom |\n| Ctrl+0 | fit width |\n"
                + "| PgUp / PgDn | page |\n| Enter in search | next match |\n");
        for (int i = 1; i <= 5; i++) {
            sb.append(PAGE_BREAK).append("## Chapter ").append(i).append("\n\n");
            for (int p = 0; p < 6; p++)
                sb.append("Chapter ").append(i).append(" paragraph ").append(p + 1)
                        .append(": lorem ipsum dolor sit amet, consectetur adipiscing elit, "
                                + "sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.\n\n");
        }
        return sb.toString();
    }

    public static void main(String[] args) {
        File file = args.length > 0 ? new File(args[0]) : null;
        SwingUtilities.invokeLater(() -> {
            JFrame frame = new JFrame("PDFViewerPanel Demo");
            frame.setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);

            PDFViewerPanel viewer = new PDFViewerPanel();
            viewer.addPageChangeListener((page, count) -> {
                File f = viewer.getFile();
                String name = (f != null ? f.getName() : "sample") + (viewer.isModified() ? " *" : "");
                frame.setTitle("PDFViewerPanel Demo - " + name + (count > 0 ? "  [" + (page + 1) + " / " + count + "]" : ""));
            });
            frame.addWindowListener(new java.awt.event.WindowAdapter() {
                @Override
                public void windowClosing(java.awt.event.WindowEvent e) {
                    if (viewer.confirmDiscard())
                        System.exit(0);
                }
            });
            frame.add(viewer, BorderLayout.CENTER);
            frame.setSize(900, 800);
            frame.setLocationRelativeTo(null);
            frame.setVisible(true);

            if (file != null)
                viewer.setPDF(file);
            else {
                try {
                    viewer.setPDF(MDToPDF.mdToPDF(sample()).toByteArray());
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
    }
}
