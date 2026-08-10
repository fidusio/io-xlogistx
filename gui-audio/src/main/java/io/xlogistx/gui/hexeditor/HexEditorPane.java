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

import io.xlogistx.gui.MDViewerPanel;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import java.awt.*;
import java.awt.event.InputEvent;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Embeddable hex editor component: toolbar (file, undo/redo, quick find, go to),
 * scrollable {@link HexPanel} and status bar composed into a single JPanel.
 * <p>
 * All dialogs are parented to this pane and nothing here exits the JVM or owns a
 * window, so third-party applications can drop it into any container. Hosts that
 * want the full menu (File/Edit/Search/View/Help) install {@link #createMenuBar()}
 * into their own frame or dialog. {@link HexEditorFrame} is the standalone wrapper.
 * <p>
 * Document-level state changes (edits, load, save, new) are reported to
 * {@link #addChangeListener(ChangeListener) change listeners} so hosts can track
 * titles and dirty state via {@link #getDocumentTitle()} / {@link #isModified()}.
 */
public class HexEditorPane extends JPanel {

    private final HexEditor editor;
    private final HexPanel hexPanel;
    private JLabel statusLabel;
    private JLabel positionLabel;
    private JLabel sizeLabel;
    private JTextField searchField;
    private JFileChooser fileChooser;
    private File currentFile;
    private String lastSearchPattern = "";
    private final List<ChangeListener> changeListeners = new ArrayList<>();

    /**
     * Creates a pane with a new empty editor.
     */
    public HexEditorPane() {
        this(new HexEditor());
    }

    /**
     * Creates a pane around the given editor.
     *
     * @param editor the editor model to display and edit
     */
    public HexEditorPane(HexEditor editor) {
        super(new BorderLayout());
        this.editor = editor;
        this.hexPanel = new HexPanel(editor);

        JScrollPane scrollPane = new JScrollPane(hexPanel);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        scrollPane.getVerticalScrollBar().setUnitIncrement(20);
        scrollPane.getViewport().setBackground(new Color(30, 30, 30));
        add(scrollPane, BorderLayout.CENTER);

        add(buildToolBar(), BorderLayout.NORTH);
        add(buildStatusBar(), BorderLayout.SOUTH);

        fileChooser = new JFileChooser();

        hexPanel.addChangeListener(e -> updateStatus());
        updateStatus();
    }

    // ==================== Public API ====================

    /**
     * @return the editor model
     */
    public HexEditor getEditor() {
        return editor;
    }

    /**
     * @return the hex view component
     */
    public HexPanel getHexPanel() {
        return hexPanel;
    }

    /**
     * @return the file currently associated with the document, or null
     */
    public File getCurrentFile() {
        return currentFile;
    }

    /**
     * @return true if the document has unsaved changes
     */
    public boolean isModified() {
        return editor.isModified();
    }

    /**
     * @return display title of the current document, e.g. {@code "data.bin *"},
     *         {@code "Untitled"} for unsaved content, or empty for a fresh pane
     */
    public String getDocumentTitle() {
        String title = "";
        if (currentFile != null) {
            title = currentFile.getName();
        } else if (editor.size() > 0) {
            title = "Untitled";
        }
        if (editor.isModified()) {
            title += " *";
        }
        return title.trim();
    }

    /**
     * Asks the user how to proceed when the document has unsaved changes.
     * Hosts call this before closing the window or replacing the document.
     *
     * @return true to proceed (saved or discarded), false to cancel
     */
    public boolean confirmDiscard() {
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

    /**
     * Starts a fresh empty document (not undoable), without confirmation.
     */
    public void newDocument() {
        editor.reset();
        hexPanel.clearModifiedMarkers();
        currentFile = null;
        hexPanel.setEditor(editor);
        updateStatus();
        statusLabel.setText("New document");
    }

    /**
     * Loads the given file into the editor.
     *
     * @param file the file to load
     * @throws IOException if the file cannot be read
     */
    public void open(File file) throws IOException {
        editor.loadFile(file);
        currentFile = file;
        hexPanel.setEditor(editor);
        hexPanel.clearModifiedMarkers();
        updateStatus();
        statusLabel.setText("Loaded: " + file.getName());
    }

    /**
     * Saves to the current file; falls back to a Save As dialog when the
     * document has no file yet.
     */
    public void save() {
        handleSave();
    }

    /**
     * Saves the document to the given file and associates it.
     *
     * @param file the file to save to
     * @throws IOException if the file cannot be written
     */
    public void saveAs(File file) throws IOException {
        editor.saveAs(file);
        currentFile = file;
        hexPanel.clearModifiedMarkers();
        updateStatus();
        statusLabel.setText("Saved: " + file.getName());
    }

    /**
     * Adds a listener notified on document-level changes (edits, load, save, new).
     *
     * @param listener the listener to add
     */
    public void addChangeListener(ChangeListener listener) {
        changeListeners.add(listener);
    }

    /**
     * Removes a previously added change listener.
     *
     * @param listener the listener to remove
     */
    public void removeChangeListener(ChangeListener listener) {
        changeListeners.remove(listener);
    }

    // ==================== Menu bar (installed by the host window) ====================

    /**
     * Builds the full menu bar (File/Edit/Search/View/Help) wired to this pane.
     * The pane does not install it anywhere — the host window decides where it goes.
     * The File menu intentionally has no Exit item; window lifecycle belongs to the host.
     *
     * @return a new menu bar bound to this pane
     */
    public JMenuBar createMenuBar() {
        JMenuBar menuBar = new JMenuBar();

        // File Menu
        JMenu fileMenu = new JMenu("File");
        fileMenu.setMnemonic(KeyEvent.VK_F);
        fileMenu.add(menuItem("New", KeyEvent.VK_N,
                KeyStroke.getKeyStroke(KeyEvent.VK_N, InputEvent.CTRL_DOWN_MASK), e -> handleNew()));
        fileMenu.add(menuItem("Open...", KeyEvent.VK_O,
                KeyStroke.getKeyStroke(KeyEvent.VK_O, InputEvent.CTRL_DOWN_MASK), e -> handleOpen()));
        fileMenu.addSeparator();
        fileMenu.add(menuItem("Save", KeyEvent.VK_S,
                KeyStroke.getKeyStroke(KeyEvent.VK_S, InputEvent.CTRL_DOWN_MASK), e -> handleSave()));
        fileMenu.add(menuItem("Save As...", KeyEvent.VK_A,
                KeyStroke.getKeyStroke(KeyEvent.VK_S, InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK),
                e -> handleSaveAs()));
        menuBar.add(fileMenu);

        // Edit Menu
        JMenu editMenu = new JMenu("Edit");
        editMenu.setMnemonic(KeyEvent.VK_E);
        editMenu.add(menuItem("Undo", KeyEvent.VK_U,
                KeyStroke.getKeyStroke(KeyEvent.VK_Z, InputEvent.CTRL_DOWN_MASK), e -> {
                    if (editor.undo()) {
                        hexPanel.refresh();
                        updateStatus();
                    }
                }));
        editMenu.add(menuItem("Redo", KeyEvent.VK_R,
                KeyStroke.getKeyStroke(KeyEvent.VK_Y, InputEvent.CTRL_DOWN_MASK), e -> {
                    if (editor.redo()) {
                        hexPanel.refresh();
                        updateStatus();
                    }
                }));
        editMenu.addSeparator();
        editMenu.add(menuItem("Cut", KeyEvent.VK_T,
                KeyStroke.getKeyStroke(KeyEvent.VK_X, InputEvent.CTRL_DOWN_MASK), e -> panelAction("cut")));
        editMenu.add(menuItem("Copy", KeyEvent.VK_C,
                KeyStroke.getKeyStroke(KeyEvent.VK_C, InputEvent.CTRL_DOWN_MASK), e -> panelAction("copy")));
        editMenu.add(menuItem("Paste", KeyEvent.VK_P,
                KeyStroke.getKeyStroke(KeyEvent.VK_V, InputEvent.CTRL_DOWN_MASK), e -> panelAction("paste")));
        editMenu.addSeparator();
        editMenu.add(menuItem("Select All", KeyEvent.VK_A,
                KeyStroke.getKeyStroke(KeyEvent.VK_A, InputEvent.CTRL_DOWN_MASK), e -> panelAction("selectAll")));
        editMenu.addSeparator();
        editMenu.add(menuItem("Insert Bytes...", KeyEvent.VK_I, null, e -> showInsertDialog()));
        editMenu.add(menuItem("Fill...", KeyEvent.VK_F, null, e -> showFillDialog()));
        menuBar.add(editMenu);

        // Search Menu
        JMenu searchMenu = new JMenu("Search");
        searchMenu.setMnemonic(KeyEvent.VK_S);
        searchMenu.add(menuItem("Find...", KeyEvent.VK_F,
                KeyStroke.getKeyStroke(KeyEvent.VK_F, InputEvent.CTRL_DOWN_MASK), e -> showFindDialog()));
        searchMenu.add(menuItem("Find Next", KeyEvent.VK_N,
                KeyStroke.getKeyStroke(KeyEvent.VK_F3, 0), e -> findNext()));
        searchMenu.add(menuItem("Go to Offset...", KeyEvent.VK_G,
                KeyStroke.getKeyStroke(KeyEvent.VK_G, InputEvent.CTRL_DOWN_MASK), e -> showGotoDialog()));
        searchMenu.addSeparator();
        searchMenu.add(menuItem("Replace...", KeyEvent.VK_R,
                KeyStroke.getKeyStroke(KeyEvent.VK_H, InputEvent.CTRL_DOWN_MASK), e -> showReplaceDialog()));
        menuBar.add(searchMenu);

        // View Menu
        JMenu viewMenu = new JMenu("View");
        viewMenu.setMnemonic(KeyEvent.VK_V);
        JMenu bytesPerRowMenu = new JMenu("Bytes Per Row");
        ButtonGroup bprGroup = new ButtonGroup();
        int[] options = {8, 16, 24, 32};
        for (final int opt : options) {
            JRadioButtonMenuItem item = new JRadioButtonMenuItem(String.valueOf(opt));
            item.setSelected(opt == hexPanel.getBytesPerRow());
            item.addActionListener(e -> {
                hexPanel.setBytesPerRow(opt);
                hexPanel.refresh();
            });
            bprGroup.add(item);
            bytesPerRowMenu.add(item);
        }
        viewMenu.add(bytesPerRowMenu);
        viewMenu.addSeparator();
        viewMenu.add(menuItem("Statistics...", KeyEvent.VK_S, null, e -> showStatistics()));
        viewMenu.add(menuItem("Data Inspector...", KeyEvent.VK_D, null, e -> showDataInspector()));
        menuBar.add(viewMenu);

        // Help Menu
        JMenu helpMenu = new JMenu("Help");
        helpMenu.setMnemonic(KeyEvent.VK_H);
        helpMenu.add(menuItem("Keyboard Shortcuts", KeyEvent.VK_K, null, e -> showShortcuts()));
        menuBar.add(helpMenu);

        return menuBar;
    }

    private JMenuItem menuItem(String text, int mnemonic, KeyStroke accelerator,
                               java.awt.event.ActionListener action) {
        JMenuItem item = new JMenuItem(text, mnemonic);
        if (accelerator != null) {
            item.setAccelerator(accelerator);
        }
        item.addActionListener(action);
        return item;
    }

    private void panelAction(String actionKey) {
        hexPanel.getActionMap().get(actionKey).actionPerformed(
                new java.awt.event.ActionEvent(hexPanel, java.awt.event.ActionEvent.ACTION_PERFORMED, actionKey));
    }

    // ==================== Toolbar / status bar ====================

    private JToolBar buildToolBar() {
        JToolBar toolBar = new JToolBar();
        toolBar.setFloatable(false);

        toolBar.add(toolButton("New", "Create new file", e -> handleNew()));
        toolBar.add(toolButton("Open", "Open file", e -> handleOpen()));
        toolBar.add(toolButton("Save", "Save file", e -> handleSave()));
        toolBar.addSeparator();
        toolBar.add(toolButton("Undo", "Undo", e -> {
            if (editor.undo()) {
                hexPanel.refresh();
                updateStatus();
            }
        }));
        toolBar.add(toolButton("Redo", "Redo", e -> {
            if (editor.redo()) {
                hexPanel.refresh();
                updateStatus();
            }
        }));
        toolBar.addSeparator();

        toolBar.add(new JLabel(" Find: "));
        searchField = new JTextField(15);
        searchField.setMaximumSize(new Dimension(150, 25));
        searchField.addActionListener(e -> findNext());
        toolBar.add(searchField);
        toolBar.add(toolButton("Find", "Find next", e -> findNext()));
        toolBar.addSeparator();

        toolBar.add(new JLabel(" Go to: "));
        final JTextField gotoField = new JTextField(10);
        gotoField.setMaximumSize(new Dimension(100, 25));
        gotoField.addActionListener(e -> {
            try {
                hexPanel.gotoOffset(parseOffset(gotoField.getText().trim()));
                hexPanel.requestFocusInWindow();
            } catch (NumberFormatException ex) {
                showError("Invalid offset: " + gotoField.getText());
            }
        });
        toolBar.add(gotoField);

        return toolBar;
    }

    private JButton toolButton(String text, String tooltip, java.awt.event.ActionListener action) {
        JButton button = new JButton(text);
        button.setToolTipText(tooltip);
        button.setFocusable(false);
        button.addActionListener(action);
        return button;
    }

    private JPanel buildStatusBar() {
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

        // track the caret for the position label
        MouseAdapter positionTracker = new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                updatePositionLabel();
            }

            @Override
            public void mouseDragged(MouseEvent e) {
                updatePositionLabel();
            }
        };
        hexPanel.addMouseListener(positionTracker);
        hexPanel.addMouseMotionListener(positionTracker);
        hexPanel.addKeyListener(new KeyAdapter() {
            @Override
            public void keyReleased(KeyEvent e) {
                updatePositionLabel();
            }
        });

        return statusBar;
    }

    // ==================== Status ====================

    private void updateStatus() {
        updatePositionLabel();
        sizeLabel.setText(String.format("Size: %,d bytes", editor.size()));
        fireChanged();
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

    private void fireChanged() {
        ChangeEvent event = new ChangeEvent(this);
        for (ChangeListener listener : changeListeners) {
            listener.stateChanged(event);
        }
    }

    // ==================== File operations ====================

    private void handleNew() {
        if (!confirmDiscard()) return;
        newDocument();
    }

    private void handleOpen() {
        if (!confirmDiscard()) return;

        if (fileChooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            try {
                open(fileChooser.getSelectedFile());
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
            try {
                saveAs(fileChooser.getSelectedFile());
            } catch (IOException e) {
                showError("Failed to save file: " + e.getMessage());
            }
        }
    }

    // ==================== Search operations ====================

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
                int offset = parseOffset(input.trim());
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

    // ==================== Edit dialogs ====================

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
                int offset = parseOffset(offsetField.getText().trim());
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

    // ==================== View dialogs ====================

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
        showMarkdownDialog(this, "shortcuts.md", "Keyboard Shortcuts", new Dimension(460, 500));
    }

    /**
     * Loads a markdown resource from this package and shows it rendered in an
     * {@link MDViewerPanel} dialog. Shared by the help/about dialogs of the pane
     * and {@link HexEditorFrame}.
     *
     * @param parent   component the dialog is parented to
     * @param resource resource name relative to this package (e.g. "shortcuts.md")
     * @param title    dialog title
     * @param size     preferred size of the viewer
     */
    static void showMarkdownDialog(Component parent, String resource, String title, Dimension size) {
        InputStream is = HexEditorPane.class.getResourceAsStream(resource);
        if (is == null) {
            JOptionPane.showMessageDialog(parent, "Missing resource: " + resource,
                    "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        try (Reader reader = new InputStreamReader(is, StandardCharsets.UTF_8)) {
            MDViewerPanel viewer = new MDViewerPanel();
            viewer.loadMarkdown(reader);
            viewer.setPreferredSize(size);
            JOptionPane.showMessageDialog(parent, viewer, title, JOptionPane.PLAIN_MESSAGE);
        } catch (IOException e) {
            JOptionPane.showMessageDialog(parent, "Failed to load " + resource + ": " + e.getMessage(),
                    "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void showError(String message) {
        JOptionPane.showMessageDialog(this, message, "Error",
                JOptionPane.ERROR_MESSAGE);
    }

    /**
     * Parses a decimal or 0x-prefixed hex offset.
     */
    private static int parseOffset(String text) {
        if (text.toLowerCase().startsWith("0x")) {
            return Integer.parseInt(text.substring(2), 16);
        }
        return Integer.parseInt(text);
    }
}
