/*
 * Copyright (c) 2012-2017 ZoxWeb.com LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package io.xlogistx.gui.hexeditor;

import javax.swing.*;
import java.awt.*;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.io.IOException;

/**
 * Standalone window wrapper around {@link HexEditorPane}.
 * <p>
 * All editor functionality (toolbar, hex view, status bar, dialogs, menu actions)
 * lives in the embeddable pane; this frame only supplies the window: title
 * tracking, the menu bar with an added Exit item, and close handling. The JVM is
 * exited only when {@link #setExitOnClose(boolean)} is enabled (done by
 * {@link #main(String[])}), so third-party applications can open this frame — or
 * embed {@link HexEditorPane} directly — without their process being terminated.
 */
public class HexEditorFrame extends JFrame {

    private final HexEditorPane editorPane;
    private boolean exitOnClose;

    /**
     * Creates a frame around a new empty editor pane.
     */
    public HexEditorFrame() {
        this(new HexEditorPane());
    }

    /**
     * Creates a frame around the given editor pane.
     *
     * @param editorPane the pane to host
     */
    public HexEditorFrame(HexEditorPane editorPane) {
        super("Hex Editor");
        this.editorPane = editorPane;

        setLayout(new BorderLayout());
        add(editorPane, BorderLayout.CENTER);

        JMenuBar menuBar = editorPane.createMenuBar();
        appendExitMenuItem(menuBar);
        appendAboutMenuItem(menuBar);
        setJMenuBar(menuBar);

        // title follows the pane's document state
        editorPane.addChangeListener(e -> updateTitle());

        setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                handleClose();
            }
        });

        setSize(900, 700);
        setLocationRelativeTo(null);
        updateTitle();
    }

    /**
     * @return the embedded editor pane
     */
    public HexEditorPane getEditorPane() {
        return editorPane;
    }

    /**
     * Controls whether closing the window terminates the JVM. Default false, so
     * the frame is safe to open from a host application; {@link #main(String[])}
     * enables it for standalone use.
     *
     * @param exitOnClose true to System.exit on close
     */
    public void setExitOnClose(boolean exitOnClose) {
        this.exitOnClose = exitOnClose;
    }

    private void appendExitMenuItem(JMenuBar menuBar) {
        // File is the first menu built by the pane
        JMenu fileMenu = menuBar.getMenu(0);
        fileMenu.addSeparator();
        JMenuItem exitMenuItem = new JMenuItem("Exit", KeyEvent.VK_X);
        exitMenuItem.addActionListener(e -> handleClose());
        fileMenu.add(exitMenuItem);
    }

    private void appendAboutMenuItem(JMenuBar menuBar) {
        // Help is the last menu built by the pane
        JMenu helpMenu = menuBar.getMenu(menuBar.getMenuCount() - 1);
        helpMenu.addSeparator();
        JMenuItem aboutMenuItem = new JMenuItem("About", KeyEvent.VK_A);
        aboutMenuItem.addActionListener(e -> showAbout());
        helpMenu.add(aboutMenuItem);
    }

    private void updateTitle() {
        String documentTitle = editorPane.getDocumentTitle();
        setTitle(documentTitle.isEmpty() ? "Hex Editor" : "Hex Editor - " + documentTitle);
    }

    private void handleClose() {
        if (!editorPane.confirmDiscard()) return;
        dispose();
        if (exitOnClose) {
            System.exit(0);
        }
    }

    private void showAbout() {
        HexEditorPane.showMarkdownDialog(this, "about.md", "About Hex Editor", new Dimension(420, 380));
    }

    /**
     * Main entry point for standalone use.
     *
     * @param args command line arguments (optional file to open)
     */
    public static void main(String[] args) {
        // Set look and feel
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception e) {
            // Use default
        }

        SwingUtilities.invokeLater(() -> {
            HexEditorFrame frame = new HexEditorFrame();
            frame.setExitOnClose(true);

            // If file argument provided, open it
            if (args.length > 0) {
                try {
                    frame.getEditorPane().open(new File(args[0]));
                } catch (IOException e) {
                    JOptionPane.showMessageDialog(frame, "Failed to open file: " + e.getMessage(),
                            "Error", JOptionPane.ERROR_MESSAGE);
                }
            }

            frame.setVisible(true);
            frame.getEditorPane().getHexPanel().requestFocusInWindow();
        });
    }
}
