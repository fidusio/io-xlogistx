package io.xlogistx.gui.test;

import io.xlogistx.gui.MDViewerPanel;

import javax.swing.*;

/**
 * Interactive demo for {@link MDViewerPanel}: markdown source on the left,
 * rendered view on the right, re-rendered on every keystroke.
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
        SwingUtilities.invokeLater(() -> {
            JFrame frame = new JFrame("MDViewerPanel Demo");
            frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

            MDViewerPanel viewer = new MDViewerPanel(SAMPLE);

            JTextArea source = new JTextArea(SAMPLE);
            source.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
                private void update() {
                    viewer.setMarkdown(source.getText());
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

            JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                    new JScrollPane(source), viewer);
            split.setResizeWeight(0.5);

            frame.add(split);
            frame.setSize(1000, 700);
            frame.setLocationRelativeTo(null);
            frame.setVisible(true);
        });
    }
}
