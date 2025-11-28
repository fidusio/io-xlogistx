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
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import java.awt.*;
import java.awt.event.*;
import java.io.File;
import java.io.IOException;

/**
 * Main GUI Frame for the Hex Editor
 */
public class HexEditorFrame extends JFrame {

    private HexEditor editor;
    private HexPanel hexPanel;
    private JScrollPane scrollPane;
    private JLabel statusLabel;
    private JLabel positionLabel;
    private JLabel sizeLabel;
    private JTextField searchField;
    private JFileChooser fileChooser;
    private File currentFile;

    // Menu items that need state management
    private JMenuItem saveMenuItem;
    private JMenuItem undoMenuItem;
    private JMenuItem redoMenuItem;

    /**
     * Creates a new HexEditorFrame
     */
    public HexEditorFrame() {
        super("Hex Editor");

        editor = new HexEditor();
        hexPanel = new HexPanel(editor);

        initializeUI();
        setupMenuBar();
        setupToolBar();
        setupStatusBar();
        setupFileChooser();

        // Listen for changes
        hexPanel.addChangeListener(new ChangeListener() {
            @Override
            public void stateChanged(ChangeEvent e) {
                updateStatus();
            }
        });

        setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                handleExit();
            }
        });

        setSize(900, 700);
        setLocationRelativeTo(null);
        updateTitle();
        updateStatus();
    }

    private void initializeUI() {
        setLayout(new BorderLayout());

        // Main hex panel in scroll pane
        scrollPane = new JScrollPane(hexPanel);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        scrollPane.getVerticalScrollBar().setUnitIncrement(20);
        add(scrollPane, BorderLayout.CENTER);

        // Set dark theme for scroll pane
        scrollPane.getViewport().setBackground(new Color(30, 30, 30));
    }

    private void setupMenuBar() {
        JMenuBar menuBar = new JMenuBar();

        // File Menu
        JMenu fileMenu = new JMenu("File");
        fileMenu.setMnemonic(KeyEvent.VK_F);

        JMenuItem newMenuItem = new JMenuItem("New", KeyEvent.VK_N);
        newMenuItem.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_N, InputEvent.CTRL_DOWN_MASK));
        newMenuItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                handleNew();
            }
        });
        fileMenu.add(newMenuItem);

        JMenuItem openMenuItem = new JMenuItem("Open...", KeyEvent.VK_O);
        openMenuItem.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_O, InputEvent.CTRL_DOWN_MASK));
        openMenuItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                handleOpen();
            }
        });
        fileMenu.add(openMenuItem);

        fileMenu.addSeparator();

        saveMenuItem = new JMenuItem("Save", KeyEvent.VK_S);
        saveMenuItem.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_S, InputEvent.CTRL_DOWN_MASK));
        saveMenuItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                handleSave();
            }
        });
        fileMenu.add(saveMenuItem);

        JMenuItem saveAsMenuItem = new JMenuItem("Save As...", KeyEvent.VK_A);
        saveAsMenuItem.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_S,
                InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK));
        saveAsMenuItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                handleSaveAs();
            }
        });
        fileMenu.add(saveAsMenuItem);

        fileMenu.addSeparator();

        JMenuItem exitMenuItem = new JMenuItem("Exit", KeyEvent.VK_X);
        exitMenuItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                handleExit();
            }
        });
        fileMenu.add(exitMenuItem);

        menuBar.add(fileMenu);

        // Edit Menu
        JMenu editMenu = new JMenu("Edit");
        editMenu.setMnemonic(KeyEvent.VK_E);

        undoMenuItem = new JMenuItem("Undo", KeyEvent.VK_U);
        undoMenuItem.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_Z, InputEvent.CTRL_DOWN_MASK));
        undoMenuItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (editor.undo()) {
                    hexPanel.refresh();
                    updateStatus();
                }
            }
        });
        editMenu.add(undoMenuItem);

        redoMenuItem = new JMenuItem("Redo", KeyEvent.VK_R);
        redoMenuItem.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_Y, InputEvent.CTRL_DOWN_MASK));
        redoMenuItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (editor.redo()) {
                    hexPanel.refresh();
                    updateStatus();
                }
            }
        });
        editMenu.add(redoMenuItem);

        editMenu.addSeparator();

        JMenuItem cutMenuItem = new JMenuItem("Cut", KeyEvent.VK_T);
        cutMenuItem.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_X, InputEvent.CTRL_DOWN_MASK));
        cutMenuItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                hexPanel.getActionMap().get("cut").actionPerformed(
                        new ActionEvent(hexPanel, ActionEvent.ACTION_PERFORMED, "cut"));
            }
        });
        editMenu.add(cutMenuItem);

        JMenuItem copyMenuItem = new JMenuItem("Copy", KeyEvent.VK_C);
        copyMenuItem.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_C, InputEvent.CTRL_DOWN_MASK));
        copyMenuItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                hexPanel.getActionMap().get("copy").actionPerformed(
                        new ActionEvent(hexPanel, ActionEvent.ACTION_PERFORMED, "copy"));
            }
        });
        editMenu.add(copyMenuItem);

        JMenuItem pasteMenuItem = new JMenuItem("Paste", KeyEvent.VK_P);
        pasteMenuItem.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_V, InputEvent.CTRL_DOWN_MASK));
        pasteMenuItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                hexPanel.getActionMap().get("paste").actionPerformed(
                        new ActionEvent(hexPanel, ActionEvent.ACTION_PERFORMED, "paste"));
            }
        });
        editMenu.add(pasteMenuItem);

        editMenu.addSeparator();

        JMenuItem selectAllMenuItem = new JMenuItem("Select All", KeyEvent.VK_A);
        selectAllMenuItem.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_A, InputEvent.CTRL_DOWN_MASK));
        selectAllMenuItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                hexPanel.getActionMap().get("selectAll").actionPerformed(
                        new ActionEvent(hexPanel, ActionEvent.ACTION_PERFORMED, "selectAll"));
            }
        });
        editMenu.add(selectAllMenuItem);

        editMenu.addSeparator();

        JMenuItem insertBytesMenuItem = new JMenuItem("Insert Bytes...", KeyEvent.VK_I);
        insertBytesMenuItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                showInsertDialog();
            }
        });
        editMenu.add(insertBytesMenuItem);

        JMenuItem fillMenuItem = new JMenuItem("Fill...", KeyEvent.VK_F);
        fillMenuItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                showFillDialog();
            }
        });
        editMenu.add(fillMenuItem);

        menuBar.add(editMenu);

        // Search Menu
        JMenu searchMenu = new JMenu("Search");
        searchMenu.setMnemonic(KeyEvent.VK_S);

        JMenuItem findMenuItem = new JMenuItem("Find...", KeyEvent.VK_F);
        findMenuItem.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_F, InputEvent.CTRL_DOWN_MASK));
        findMenuItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                showFindDialog();
            }
        });
        searchMenu.add(findMenuItem);

        JMenuItem findNextMenuItem = new JMenuItem("Find Next", KeyEvent.VK_N);
        findNextMenuItem.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_F3, 0));
        findNextMenuItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                findNext();
            }
        });
        searchMenu.add(findNextMenuItem);

        JMenuItem gotoMenuItem = new JMenuItem("Go to Offset...", KeyEvent.VK_G);
        gotoMenuItem.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_G, InputEvent.CTRL_DOWN_MASK));
        gotoMenuItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                showGotoDialog();
            }
        });
        searchMenu.add(gotoMenuItem);

        searchMenu.addSeparator();

        JMenuItem replaceMenuItem = new JMenuItem("Replace...", KeyEvent.VK_R);
        replaceMenuItem.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_H, InputEvent.CTRL_DOWN_MASK));
        replaceMenuItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                showReplaceDialog();
            }
        });
        searchMenu.add(replaceMenuItem);

        menuBar.add(searchMenu);

        // View Menu
        JMenu viewMenu = new JMenu("View");
        viewMenu.setMnemonic(KeyEvent.VK_V);

        JMenu bytesPerRowMenu = new JMenu("Bytes Per Row");
        ButtonGroup bprGroup = new ButtonGroup();
        int[] options = {8, 16, 24, 32};
        for (final int opt : options) {
            JRadioButtonMenuItem item = new JRadioButtonMenuItem(String.valueOf(opt));
            item.setSelected(opt == 16);
            item.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    hexPanel.setBytesPerRow(opt);
                    hexPanel.refresh();
                }
            });
            bprGroup.add(item);
            bytesPerRowMenu.add(item);
        }
        viewMenu.add(bytesPerRowMenu);

        viewMenu.addSeparator();

        JMenuItem statsMenuItem = new JMenuItem("Statistics...", KeyEvent.VK_S);
        statsMenuItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                showStatistics();
            }
        });
        viewMenu.add(statsMenuItem);

        JMenuItem dataInspectorMenuItem = new JMenuItem("Data Inspector...", KeyEvent.VK_D);
        dataInspectorMenuItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                showDataInspector();
            }
        });
        viewMenu.add(dataInspectorMenuItem);

        menuBar.add(viewMenu);

        // Help Menu
        JMenu helpMenu = new JMenu("Help");
        helpMenu.setMnemonic(KeyEvent.VK_H);

        JMenuItem shortcutsMenuItem = new JMenuItem("Keyboard Shortcuts", KeyEvent.VK_K);
        shortcutsMenuItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                showShortcuts();
            }
        });
        helpMenu.add(shortcutsMenuItem);

        helpMenu.addSeparator();

        JMenuItem aboutMenuItem = new JMenuItem("About", KeyEvent.VK_A);
        aboutMenuItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                showAbout();
            }
        });
        helpMenu.add(aboutMenuItem);

        menuBar.add(helpMenu);

        setJMenuBar(menuBar);
    }

    private void setupToolBar() {
        JToolBar toolBar = new JToolBar();
        toolBar.setFloatable(false);

        JButton newBtn = createToolButton("New", "Create new file", new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                handleNew();
            }
        });
        toolBar.add(newBtn);

        JButton openBtn = createToolButton("Open", "Open file", new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                handleOpen();
            }
        });
        toolBar.add(openBtn);

        JButton saveBtn = createToolButton("Save", "Save file", new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                handleSave();
            }
        });
        toolBar.add(saveBtn);

        toolBar.addSeparator();

        JButton undoBtn = createToolButton("Undo", "Undo", new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (editor.undo()) {
                    hexPanel.refresh();
                    updateStatus();
                }
            }
        });
        toolBar.add(undoBtn);

        JButton redoBtn = createToolButton("Redo", "Redo", new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (editor.redo()) {
                    hexPanel.refresh();
                    updateStatus();
                }
            }
        });
        toolBar.add(redoBtn);

        toolBar.addSeparator();

        // Quick search field
        toolBar.add(new JLabel(" Find: "));
        searchField = new JTextField(15);
        searchField.setMaximumSize(new Dimension(150, 25));
        searchField.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                findNext();
            }
        });
        toolBar.add(searchField);

        JButton findBtn = createToolButton("Find", "Find next", new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                findNext();
            }
        });
        toolBar.add(findBtn);

        toolBar.addSeparator();

        // Go to offset
        toolBar.add(new JLabel(" Go to: "));
        final JTextField gotoField = new JTextField(10);
        gotoField.setMaximumSize(new Dimension(100, 25));
        gotoField.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    String text = gotoField.getText().trim();
                    int offset;
                    if (text.toLowerCase().startsWith("0x")) {
                        offset = Integer.parseInt(text.substring(2), 16);
                    } else {
                        offset = Integer.parseInt(text);
                    }
                    hexPanel.gotoOffset(offset);
                    hexPanel.requestFocusInWindow();
                } catch (NumberFormatException ex) {
                    showError("Invalid offset: " + gotoField.getText());
                }
            }
        });
        toolBar.add(gotoField);

        add(toolBar, BorderLayout.NORTH);
    }

    private JButton createToolButton(String text, String tooltip, ActionListener action) {
        JButton button = new JButton(text);
        button.setToolTipText(tooltip);
        button.setFocusable(false);
        button.addActionListener(action);
        return button;
    }

    private void setupStatusBar() {
        JPanel statusBar = new JPanel(new BorderLayout());
        statusBar.setBorder(BorderFactory.createEmptyBorder(2, 5, 2, 5));

        statusLabel = new JLabel("Ready");
        statusBar.add(statusLabel, BorderLayout.WEST);

        JPanel rightPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));

        positionLabel = new JLabel("Offset: 0x00000000");
        rightPanel.add(positionLabel);

        sizeLabel = new JLabel("Size: 0 bytes");
        rightPanel.add(sizeLabel);

        statusBar.add(rightPanel, BorderLayout.EAST);

        add(statusBar, BorderLayout.SOUTH);

        // Update position on caret movement
        hexPanel.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                updatePositionLabel();
            }
        });

        hexPanel.addKeyListener(new KeyAdapter() {
            @Override
            public void keyReleased(KeyEvent e) {
                updatePositionLabel();
            }
        });
    }

    private void setupFileChooser() {
        fileChooser = new JFileChooser();
        //fileChooser.setFileFilter(new FileNameExtensionFilter("All Files", "*"));
        //fileChooser.setAcceptAllFileFilterUsed(true);
    }

    private void updateTitle() {
        String title = "Hex Editor";
        if (currentFile != null) {
            title += " - " + currentFile.getName();
        } else if (editor.size() > 0) {
            title += " - Untitled";
        }
        if (editor.isModified()) {
            title += " *";
        }
        setTitle(title);
    }

    private void updateStatus() {
        updateTitle();
        updatePositionLabel();
        sizeLabel.setText(String.format("Size: %,d bytes", editor.size()));
    }

    private void updatePositionLabel() {
        int pos = hexPanel.getCaretPosition();
        String text = String.format("Offset: 0x%08X (%,d)", pos, pos);

        if (hexPanel.getSelectionStart() >= 0) {
            int start = hexPanel.getSelectionStart();
            int end = hexPanel.getSelectionEnd();
            int len = end - start + 1;
            text += String.format(" | Selected: %,d bytes", len);
        }

        if (editor.size() > 0 && pos < editor.size()) {
            int b = editor.getByte(pos);
            text += String.format(" | Byte: 0x%02X (%d)", b, b);
        }

        positionLabel.setText(text);
    }

    // File operations
    private void handleNew() {
        if (!confirmDiscard()) return;

        editor.clear();
        hexPanel.clearModifiedMarkers();
        currentFile = null;
        hexPanel.setEditor(editor);
        updateStatus();
    }

    private void handleOpen() {
        if (!confirmDiscard()) return;

        if (fileChooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            try {
                editor.loadFile(file);
                currentFile = file;
                hexPanel.setEditor(editor);
                hexPanel.clearModifiedMarkers();
                updateStatus();
                statusLabel.setText("Loaded: " + file.getName());
            } catch (IOException e) {
                showError("Failed to open file: " + e.getMessage());
            }
        }
    }

    private void handleSave() {
        if (currentFile == null) {
            handleSaveAs();
        } else {
            try {
                editor.save();
                hexPanel.clearModifiedMarkers();
                updateStatus();
                statusLabel.setText("Saved: " + currentFile.getName());
            } catch (IOException e) {
                showError("Failed to save file: " + e.getMessage());
            }
        }
    }

    private void handleSaveAs() {
        if (fileChooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            try {
                editor.saveAs(file);
                currentFile = file;
                hexPanel.clearModifiedMarkers();
                updateStatus();
                statusLabel.setText("Saved: " + file.getName());
            } catch (IOException e) {
                showError("Failed to save file: " + e.getMessage());
            }
        }
    }

    private void handleExit() {
        if (!confirmDiscard()) return;
        dispose();
        System.exit(0);
    }

    private boolean confirmDiscard() {
        if (editor.isModified()) {
            int result = JOptionPane.showConfirmDialog(this,
                    "There are unsaved changes. Do you want to save before continuing?",
                    "Unsaved Changes",
                    JOptionPane.YES_NO_CANCEL_OPTION,
                    JOptionPane.WARNING_MESSAGE);

            if (result == JOptionPane.CANCEL_OPTION) {
                return false;
            }
            if (result == JOptionPane.YES_OPTION) {
                handleSave();
                return !editor.isModified();
            }
        }
        return true;
    }

    // Search operations
    private String lastSearchPattern = "";

    private void showFindDialog() {
        JPanel panel = new JPanel(new GridLayout(3, 1, 5, 5));

        JTextField patternField = new JTextField(lastSearchPattern, 30);
        panel.add(new JLabel("Search pattern (hex or text):"));
        panel.add(patternField);

        JCheckBox hexCheckbox = new JCheckBox("Hex pattern (e.g., CA FE BA BE)", true);
        panel.add(hexCheckbox);

        int result = JOptionPane.showConfirmDialog(this, panel, "Find",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);

        if (result == JOptionPane.OK_OPTION) {
            lastSearchPattern = patternField.getText();
            searchField.setText(lastSearchPattern);
            findNext();
        }
    }

    private void findNext() {
        String pattern = searchField.getText().trim();
        if (pattern.isEmpty()) {
            showFindDialog();
            return;
        }

        if (editor.size() == 0) {
            statusLabel.setText("Buffer is empty");
            return;
        }

        int startPos = hexPanel.getCaretPosition() + 1;
        int foundPos;

        // Try as hex first
        try {
            foundPos = editor.findHex(pattern, startPos);
            if (foundPos == -1) {
                // Wrap around
                foundPos = editor.findHex(pattern, 0);
            }
        } catch (Exception e) {
            // Try as text
            foundPos = editor.findText(pattern, startPos);
            if (foundPos == -1) {
                foundPos = editor.findText(pattern, 0);
            }
        }

        if (foundPos >= 0) {
            byte[] searchBytes;
            try {
                searchBytes = HexEditor.parseHexString(pattern);
            } catch (Exception e) {
                searchBytes = pattern.getBytes();
            }
            hexPanel.setSelection(foundPos, foundPos + searchBytes.length - 1);
            statusLabel.setText(String.format("Found at offset 0x%08X", foundPos));
        } else {
            statusLabel.setText("Pattern not found");
            JOptionPane.showMessageDialog(this, "Pattern not found.", "Find",
                    JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private void showReplaceDialog() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;

        gbc.gridx = 0;
        gbc.gridy = 0;
        panel.add(new JLabel("Find (hex):"), gbc);
        gbc.gridx = 1;
        final JTextField findField = new JTextField(20);
        panel.add(findField, gbc);

        gbc.gridx = 0;
        gbc.gridy = 1;
        panel.add(new JLabel("Replace (hex):"), gbc);
        gbc.gridx = 1;
        final JTextField replaceField = new JTextField(20);
        panel.add(replaceField, gbc);

        Object[] options = {"Replace All", "Replace", "Find Next", "Cancel"};

        int result = JOptionPane.showOptionDialog(this, panel, "Replace",
                JOptionPane.DEFAULT_OPTION, JOptionPane.PLAIN_MESSAGE,
                null, options, options[2]);

        if (result == 0) { // Replace All
            try {
                byte[] search = HexEditor.parseHexString(findField.getText());
                byte[] replace = HexEditor.parseHexString(replaceField.getText());
                int count = editor.replaceAll(search, replace);
                hexPanel.refresh();
                updateStatus();
                statusLabel.setText("Replaced " + count + " occurrences");
            } catch (Exception e) {
                showError("Invalid hex pattern: " + e.getMessage());
            }
        } else if (result == 1) { // Replace
            try {
                byte[] search = HexEditor.parseHexString(findField.getText());
                byte[] replace = HexEditor.parseHexString(replaceField.getText());
                if (editor.replace(search, replace, hexPanel.getCaretPosition())) {
                    hexPanel.refresh();
                    updateStatus();
                    statusLabel.setText("Replaced one occurrence");
                } else {
                    statusLabel.setText("Pattern not found");
                }
            } catch (Exception e) {
                showError("Invalid hex pattern: " + e.getMessage());
            }
        } else if (result == 2) { // Find Next
            searchField.setText(findField.getText());
            findNext();
        }
    }

    private void showGotoDialog() {
        String input = JOptionPane.showInputDialog(this,
                "Enter offset (hex with 0x prefix, or decimal):",
                "Go to Offset",
                JOptionPane.PLAIN_MESSAGE);

        if (input != null && !input.trim().isEmpty()) {
            try {
                String text = input.trim();
                int offset;
                if (text.toLowerCase().startsWith("0x")) {
                    offset = Integer.parseInt(text.substring(2), 16);
                } else {
                    offset = Integer.parseInt(text);
                }

                if (offset >= 0 && offset < editor.size()) {
                    hexPanel.gotoOffset(offset);
                    updatePositionLabel();
                    statusLabel.setText(String.format("Jumped to offset 0x%08X", offset));
                } else {
                    showError("Offset out of range (0 - " + (editor.size() - 1) + ")");
                }
            } catch (NumberFormatException e) {
                showError("Invalid offset: " + input);
            }
        }
    }

    // Edit dialogs
    private void showInsertDialog() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;

        gbc.gridx = 0;
        gbc.gridy = 0;
        panel.add(new JLabel("Offset:"), gbc);
        gbc.gridx = 1;
        JTextField offsetField = new JTextField(String.format("0x%08X", hexPanel.getCaretPosition()), 15);
        panel.add(offsetField, gbc);

        gbc.gridx = 0;
        gbc.gridy = 1;
        panel.add(new JLabel("Bytes (hex):"), gbc);
        gbc.gridx = 1;
        JTextField bytesField = new JTextField("00", 30);
        panel.add(bytesField, gbc);

        int result = JOptionPane.showConfirmDialog(this, panel, "Insert Bytes",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);

        if (result == JOptionPane.OK_OPTION) {
            try {
                String offsetText = offsetField.getText().trim();
                int offset;
                if (offsetText.toLowerCase().startsWith("0x")) {
                    offset = Integer.parseInt(offsetText.substring(2), 16);
                } else {
                    offset = Integer.parseInt(offsetText);
                }

                byte[] bytes = HexEditor.parseHexString(bytesField.getText());
                editor.insertBytes(offset, bytes);
                hexPanel.refresh();
                updateStatus();
                statusLabel.setText("Inserted " + bytes.length + " bytes");
            } catch (Exception e) {
                showError("Error: " + e.getMessage());
            }
        }
    }

    private void showFillDialog() {
        if (hexPanel.getSelectionStart() < 0) {
            showError("Please select a range first");
            return;
        }

        String input = JOptionPane.showInputDialog(this,
                "Fill selected range with byte value (hex, e.g., FF):",
                "Fill",
                JOptionPane.PLAIN_MESSAGE);

        if (input != null && !input.trim().isEmpty()) {
            try {
                int value = Integer.parseInt(input.trim(), 16);
                int start = hexPanel.getSelectionStart();
                int end = hexPanel.getSelectionEnd();
                int length = end - start + 1;

                editor.fill(start, length, value);
                hexPanel.refresh();
                updateStatus();
                statusLabel.setText(String.format("Filled %d bytes with 0x%02X", length, value));
            } catch (Exception e) {
                showError("Invalid hex value: " + input);
            }
        }
    }

    // View dialogs
    private void showStatistics() {
        if (editor.size() == 0) {
            JOptionPane.showMessageDialog(this, "Buffer is empty.", "Statistics",
                    JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        JTextArea textArea = new JTextArea(editor.getStatistics());
        textArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        textArea.setEditable(false);

        JScrollPane scrollPane = new JScrollPane(textArea);
        scrollPane.setPreferredSize(new Dimension(400, 250));

        JOptionPane.showMessageDialog(this, scrollPane, "Buffer Statistics",
                JOptionPane.INFORMATION_MESSAGE);
    }

    private void showDataInspector() {
        if (editor.size() == 0) {
            showError("Buffer is empty");
            return;
        }

        int pos = hexPanel.getCaretPosition();
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("Position: 0x%08X (%d)\n\n", pos, pos));

        // Single byte
        int b = editor.getByte(pos);
        sb.append(String.format("Int8 (unsigned): %d\n", b));
        sb.append(String.format("Int8 (signed): %d\n", (byte) b));
        sb.append(String.format("Binary: %8s\n", Integer.toBinaryString(b)).replace(' ', '0'));
        sb.append(String.format("Char: %s\n\n", b >= 32 && b < 127 ? "'" + (char) b + "'" : "(non-printable)"));

        // Multi-byte values
        if (pos + 1 < editor.size()) {
            sb.append(String.format("Int16 LE: %d\n", editor.readInt16LE(pos)));
            sb.append(String.format("Int16 BE: %d\n", editor.readInt16BE(pos)));
        }
        if (pos + 3 < editor.size()) {
            sb.append(String.format("Int32 LE: %d\n", editor.readInt32LE(pos)));
            sb.append(String.format("Int32 BE: %d\n", editor.readInt32BE(pos)));
        }
        if (pos + 7 < editor.size()) {
            sb.append(String.format("Int64 LE: %d\n", editor.readInt64LE(pos)));
            sb.append(String.format("Int64 BE: %d\n", editor.readInt64BE(pos)));
        }

        JTextArea textArea = new JTextArea(sb.toString());
        textArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        textArea.setEditable(false);

        JOptionPane.showMessageDialog(this, textArea, "Data Inspector",
                JOptionPane.INFORMATION_MESSAGE);
    }

    private void showShortcuts() {
        String shortcuts =
                "Keyboard Shortcuts\n" +
                "==================\n\n" +
                "File Operations:\n" +
                "  Ctrl+N        New file\n" +
                "  Ctrl+O        Open file\n" +
                "  Ctrl+S        Save\n" +
                "  Ctrl+Shift+S  Save As\n\n" +
                "Navigation:\n" +
                "  Arrow Keys    Move cursor\n" +
                "  Page Up/Down  Scroll page\n" +
                "  Home          Start of line\n" +
                "  End           End of line\n" +
                "  Ctrl+Home     Start of file\n" +
                "  Ctrl+End      End of file\n" +
                "  Ctrl+G        Go to offset\n" +
                "  Tab           Toggle hex/ASCII editing\n\n" +
                "Selection:\n" +
                "  Shift+Arrows  Extend selection\n" +
                "  Ctrl+A        Select all\n" +
                "  Double-click  Select byte\n\n" +
                "Editing:\n" +
                "  0-9, A-F      Edit hex nibble\n" +
                "  Delete        Delete byte\n" +
                "  Backspace     Delete previous byte\n" +
                "  Insert        Insert zero byte\n\n" +
                "Clipboard:\n" +
                "  Ctrl+C        Copy (as hex)\n" +
                "  Ctrl+X        Cut\n" +
                "  Ctrl+V        Paste\n\n" +
                "Undo/Redo:\n" +
                "  Ctrl+Z        Undo\n" +
                "  Ctrl+Y        Redo\n\n" +
                "Search:\n" +
                "  Ctrl+F        Find\n" +
                "  F3            Find next\n" +
                "  Ctrl+H        Replace\n";

        JTextArea textArea = new JTextArea(shortcuts);
        textArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        textArea.setEditable(false);

        JScrollPane scrollPane = new JScrollPane(textArea);
        scrollPane.setPreferredSize(new Dimension(400, 450));

        JOptionPane.showMessageDialog(this, scrollPane, "Keyboard Shortcuts",
                JOptionPane.INFORMATION_MESSAGE);
    }

    private void showAbout() {
        String about =
                "Hex Editor\n" +
                "Version 1.0.0\n\n" +
                "A hexadecimal editor using UByteArrayOutputStream\n" +
                "from zoxweb-core as data buffer.\n\n" +
                "Features:\n" +
                "  - View and edit binary files\n" +
                "  - Search and replace hex patterns\n" +
                "  - Undo/Redo support\n" +
                "  - Data type inspector\n" +
                "  - Copy/Paste support\n\n" +
                "Built with Java Swing\n" +
                "Package: io.xlogistx.gui.hexeditor";

        JOptionPane.showMessageDialog(this, about, "About Hex Editor",
                JOptionPane.INFORMATION_MESSAGE);
    }

    private void showError(String message) {
        JOptionPane.showMessageDialog(this, message, "Error",
                JOptionPane.ERROR_MESSAGE);
    }

    /**
     * Main entry point
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

        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                final HexEditorFrame frame = new HexEditorFrame();

                // If file argument provided, open it
                if (args.length > 0) {
                    try {
                        frame.editor.loadFile(args[0]);
                        frame.currentFile = new File(args[0]);
                        frame.hexPanel.setEditor(frame.editor);
                        frame.updateStatus();
                    } catch (IOException e) {
                        frame.showError("Failed to open file: " + e.getMessage());
                    }
                }

                frame.setVisible(true);
                frame.hexPanel.requestFocusInWindow();
            }
        });
    }
}
