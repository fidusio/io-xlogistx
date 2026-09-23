package io.xlogistx.gui.test;

import io.xlogistx.gui.BackgroundTask;
import io.xlogistx.gui.MDToPDF;
import io.xlogistx.gui.MDViewerPanel;
import io.xlogistx.gui.PDFViewerPanel;
import org.apache.pdfbox.Loader;
import org.zoxweb.server.io.IOUtil;

import javax.swing.*;
import java.awt.*;

/**
 * Interactive demo for {@link MDViewerPanel} and {@link PDFViewerPanel}:
 * markdown source on the left, rendered view in the middle (re-rendered on
 * every keystroke) and the {@link MDToPDF} output on the right, regenerated
 * off the EDT after a short typing pause; page and zoom are preserved across
 * regenerations.
 */
public class MDViewerDemo {

    private static final String SAMPLE = "# MDViewerPanel Demo\n" +
            "\n" +
            "A **read-only** markdown viewer backed by *commonmark*.\n" +
            "\n" +
            "## Features\n" +
            "\n" +
            "- Headings, **bold**, *italic*, ~~strikethrough~~\n" +
            "- Inline `code` and code blocks\n" +
            "- Links: [xlogistx](https://xlogistx.io)\n" +
            "\n" +
            "## Task List\n" +
            "\n" +
            "- [x] Parse markdown\n" +
            "- [x] Render tables\n" +
            "- [ ] World domination\n" +
            "\n" +
            "## Table\n" +
            "\n" +
            "| Module | Purpose |\n" +
            "|--------|---------|\n" +
            "| core | Core utilities |\n" +
            "| gui-audio | Swing widgets |\n" +
            "\n" +
            "## Code\n" +
            "\n" +
            "```java\n" +
            "MDViewerPanel viewer = new MDViewerPanel();\n" +
            "viewer.setMarkdown(\"# Hello\");\n" +
            "```\n" +
            "\n" +
            "> Blockquotes are styled with a muted color.\n";

    public static void main(String[] args) {
        String filename = args.length > 0 ? args[0] : null;
        try {
            String content = filename != null ? IOUtil.inputStreamToString(filename) : SAMPLE;
            SwingUtilities.invokeLater(() -> {
                JFrame frame = new JFrame("MDViewerPanel Demo");
                frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

                MDViewerPanel viewer = new MDViewerPanel(content);
                PDFViewerPanel pdfViewer = new PDFViewerPanel();
                PDFRefresher pdfRefresher = new PDFRefresher(pdfViewer);

                JTextArea source = new JTextArea(content);
                source.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
                    private void update() {
                        viewer.setMarkdown(source.getText());
                        pdfRefresher.schedule(source.getText());
                    }

                    public void insertUpdate(javax.swing.event.DocumentEvent e) {
                        update();
                    }

                    public void removeUpdate(javax.swing.event.DocumentEvent e) {
                        update();
                    }

                    public void changedUpdate(javax.swing.event.DocumentEvent e) {
                        update();
                    }
                });

                JSplitPane right = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, viewer, pdfViewer);
                right.setResizeWeight(0.5);
                JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                        new JScrollPane(source), right);
                split.setResizeWeight(0.34);

                // visual demo of overrideScrollPane: orange border + always-on scrollbars
                JCheckBox override = new JCheckBox("Custom scroll pane (overrideScrollPane)");
                override.addActionListener(e -> {
                    if (override.isSelected()) {
                        JScrollPane custom = new JScrollPane();
                        custom.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
                        custom.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);
                        custom.setBorder(BorderFactory.createLineBorder(Color.ORANGE, 3));
                        viewer.overrideScrollPane(custom);
                    } else {
                        viewer.overrideScrollPane(new JScrollPane());
                    }
                });

                frame.add(split, BorderLayout.CENTER);
                frame.add(override, BorderLayout.SOUTH);
                frame.setSize(1400, 800);
                frame.setLocationRelativeTo(null);
                frame.setVisible(true);
                pdfRefresher.schedule(content);
            });
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Debounced markdown to PDF regeneration: waits {@value #DELAY_MS} ms after the
     * last edit, converts and parses off the EDT, then swaps the document into the
     * viewer keeping the current page. An edit arriving while a conversion is
     * running is picked up as soon as it finishes.
     */
    private static final class PDFRefresher {
        private static final int DELAY_MS = 500;
        private final PDFViewerPanel viewer;
        private final Timer timer;
        private String pending;
        private boolean running;

        PDFRefresher(PDFViewerPanel viewer) {
            this.viewer = viewer;
            timer = new Timer(DELAY_MS, e -> start());
            timer.setRepeats(false);
        }

        void schedule(String markdown) {
            pending = markdown;
            timer.restart();
        }

        private void start() {
            if (running || pending == null)
                return;
            String markdown = pending;
            pending = null;
            running = true;
            int page = viewer.getCurrentPage();
            BackgroundTask.run(viewer, null,
                    () -> Loader.loadPDF(MDToPDF.mdToPDF(markdown).toByteArray()),
                    doc -> {
                        running = false;
                        viewer.setDocument(doc, true);
                        if (page > 0)
                            viewer.gotoPage(page);
                        if (pending != null)
                            timer.restart();
                    });
        }
    }

}
