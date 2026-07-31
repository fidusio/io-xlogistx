package io.xlogistx.gui.test;

import io.xlogistx.gui.MDViewerPanel;
import org.zoxweb.server.io.IOUtil;

import javax.swing.*;
import java.awt.*;

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
        String filename = args.length > 0 ? args[0] : null;
        try {
            String content = filename != null ? IOUtil.inputStreamToString(filename) : SAMPLE;
            SwingUtilities.invokeLater(() -> {
                JFrame frame = new JFrame("MDViewerPanel Demo");
                frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

                MDViewerPanel viewer = new MDViewerPanel(content);

                JTextArea source = new JTextArea(content);
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
                frame.setSize(1000, 700);
                frame.setLocationRelativeTo(null);
                frame.setVisible(true);
            });
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }

}
