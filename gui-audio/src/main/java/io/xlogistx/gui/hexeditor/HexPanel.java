
package io.xlogistx.gui.hexeditor;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import java.awt.*;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.StringSelection;
import java.awt.event.*;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Custom JComponent for rendering and editing hex data.
 * Displays offset, hex bytes, and ASCII representation.
 */
public class HexPanel extends JComponent implements Scrollable {

    private HexEditor editor;
    private int bytesPerRow = 16;
    private int cellWidth;
    private int cellHeight;
    private int offsetWidth;
    private int hexAreaX;
    private int asciiAreaX;
    private int totalWidth;

    private int selectionStart = -1;
    private int selectionEnd = -1;
    private int caretPosition = 0;
    private boolean caretInAscii = false;
    private boolean caretHighNibble = true;
    private boolean showCaret = true;

    private Font monoFont;
    private FontMetrics fontMetrics;

    // Colors
    private Color bgColor = new Color(30, 30, 30);
    private Color textColor = new Color(220, 220, 220);
    private Color offsetColor = new Color(100, 149, 237);
    private Color asciiColor = new Color(144, 238, 144);
    private Color selectionBg = new Color(51, 102, 153);
    private Color caretColor = new Color(255, 165, 0);
    private Color modifiedColor = new Color(255, 100, 100);
    private Color nullByteColor = new Color(100, 100, 100);
    private Color separatorColor = new Color(80, 80, 80);

    private Timer caretTimer;
    private Set<Integer> modifiedOffsets = new HashSet<Integer>();
    private List<ChangeListener> changeListeners = new ArrayList<ChangeListener>();

    /**
     * Creates a HexPanel with a new empty editor
     */
    public HexPanel() {
        this(new HexEditor());
    }

    /**
     * Creates a HexPanel with the specified editor
     *
     * @param editor the HexEditor to use
     */
    public HexPanel(HexEditor editor) {
        this.editor = editor;

        setFocusable(true);
        setBackground(bgColor);

        // Setup font
        monoFont = new Font(Font.MONOSPACED, Font.PLAIN, 14);
        setFont(monoFont);

        // Setup caret blink timer
        caretTimer = new Timer(500, new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                showCaret = !showCaret;
                repaint();
            }
        });
        caretTimer.start();

        // Setup mouse listeners
        MouseAdapter mouseAdapter = new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                requestFocusInWindow();
                handleMousePressed(e);
            }

            @Override
            public void mouseDragged(MouseEvent e) {
                handleMouseDragged(e);
            }

            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    selectWord();
                }
            }
        };
        addMouseListener(mouseAdapter);
        addMouseMotionListener(mouseAdapter);

        // Setup keyboard input
        setupKeyBindings();

        // Calculate dimensions
        recalculateDimensions();
    }

    private void setupKeyBindings() {
        InputMap im = getInputMap(WHEN_FOCUSED);
        ActionMap am = getActionMap();

        // Navigation
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_LEFT, 0), "left");
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_RIGHT, 0), "right");
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_UP, 0), "up");
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_DOWN, 0), "down");
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_HOME, 0), "lineStart");
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_END, 0), "lineEnd");
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_HOME, InputEvent.CTRL_DOWN_MASK), "docStart");
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_END, InputEvent.CTRL_DOWN_MASK), "docEnd");
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_PAGE_UP, 0), "pageUp");
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_PAGE_DOWN, 0), "pageDown");
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_TAB, 0), "toggleArea");

        // Selection
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_LEFT, InputEvent.SHIFT_DOWN_MASK), "selectLeft");
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_RIGHT, InputEvent.SHIFT_DOWN_MASK), "selectRight");
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_UP, InputEvent.SHIFT_DOWN_MASK), "selectUp");
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_DOWN, InputEvent.SHIFT_DOWN_MASK), "selectDown");
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_A, InputEvent.CTRL_DOWN_MASK), "selectAll");

        // Editing
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_DELETE, 0), "delete");
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_BACK_SPACE, 0), "backspace");
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_INSERT, 0), "insert");

        // Clipboard
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_C, InputEvent.CTRL_DOWN_MASK), "copy");
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_V, InputEvent.CTRL_DOWN_MASK), "paste");
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_X, InputEvent.CTRL_DOWN_MASK), "cut");

        // Undo/Redo
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_Z, InputEvent.CTRL_DOWN_MASK), "undo");
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_Y, InputEvent.CTRL_DOWN_MASK), "redo");

        // Actions
        am.put("left", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                moveCaret(-1, false);
            }
        });
        am.put("right", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                moveCaret(1, false);
            }
        });
        am.put("up", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                moveCaret(-bytesPerRow, false);
            }
        });
        am.put("down", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                moveCaret(bytesPerRow, false);
            }
        });
        am.put("lineStart", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                caretPosition = (caretPosition / bytesPerRow) * bytesPerRow;
                clearSelection();
                scrollToCaret();
                repaint();
            }
        });
        am.put("lineEnd", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                caretPosition = Math.min((caretPosition / bytesPerRow + 1) * bytesPerRow - 1, editor.size() - 1);
                clearSelection();
                scrollToCaret();
                repaint();
            }
        });
        am.put("docStart", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                caretPosition = 0;
                clearSelection();
                scrollToCaret();
                repaint();
            }
        });
        am.put("docEnd", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                caretPosition = Math.max(0, editor.size() - 1);
                clearSelection();
                scrollToCaret();
                repaint();
            }
        });
        am.put("pageUp", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int visibleRows = getVisibleRect().height / cellHeight;
                moveCaret(-visibleRows * bytesPerRow, false);
            }
        });
        am.put("pageDown", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int visibleRows = getVisibleRect().height / cellHeight;
                moveCaret(visibleRows * bytesPerRow, false);
            }
        });
        am.put("toggleArea", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                caretInAscii = !caretInAscii;
                caretHighNibble = true;
                repaint();
            }
        });
        am.put("selectLeft", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                moveCaret(-1, true);
            }
        });
        am.put("selectRight", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                moveCaret(1, true);
            }
        });
        am.put("selectUp", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                moveCaret(-bytesPerRow, true);
            }
        });
        am.put("selectDown", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                moveCaret(bytesPerRow, true);
            }
        });
        am.put("selectAll", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (editor.size() > 0) {
                    selectionStart = 0;
                    selectionEnd = editor.size() - 1;
                    repaint();
                }
            }
        });
        am.put("delete", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                deleteSelection();
            }
        });
        am.put("backspace", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (hasSelection()) {
                    deleteSelection();
                } else if (caretPosition > 0) {
                    caretPosition--;
                    editor.deleteBytes(caretPosition, 1);
                    fireDataChanged();
                    repaint();
                }
            }
        });
        am.put("insert", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                editor.insertByte(caretPosition, 0);
                fireDataChanged();
                repaint();
            }
        });
        am.put("copy", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                copyToClipboard();
            }
        });
        am.put("paste", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                pasteFromClipboard();
            }
        });
        am.put("cut", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                copyToClipboard();
                deleteSelection();
            }
        });
        am.put("undo", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (editor.undo()) {
                    fireDataChanged();
                    repaint();
                }
            }
        });
        am.put("redo", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (editor.redo()) {
                    fireDataChanged();
                    repaint();
                }
            }
        });

        // Hex input
        addKeyListener(new KeyAdapter() {
            @Override
            public void keyTyped(KeyEvent e) {
                char c = e.getKeyChar();
                if (editor.size() == 0) return;

                if (caretInAscii) {
                    // ASCII input
                    if (c >= 32 && c < 127) {
                        editor.setByte(caretPosition, c);
                        modifiedOffsets.add(caretPosition);
                        moveCaret(1, false);
                        fireDataChanged();
                    }
                } else {
                    // Hex input
                    if (isHexChar(c)) {
                        int nibble = Character.digit(c, 16);
                        int currentByte = editor.getByte(caretPosition);
                        int newByte;

                        if (caretHighNibble) {
                            newByte = (nibble << 4) | (currentByte & 0x0F);
                            caretHighNibble = false;
                        } else {
                            newByte = (currentByte & 0xF0) | nibble;
                            caretHighNibble = true;
                            if (caretPosition < editor.size() - 1) {
                                caretPosition++;
                            }
                        }

                        int targetOffset = caretHighNibble && caretPosition > 0 ? caretPosition - 1 : caretPosition;
                        editor.setByte(targetOffset, newByte);
                        modifiedOffsets.add(targetOffset);
                        fireDataChanged();
                        repaint();
                    }
                }
            }
        });
    }

    private boolean isHexChar(char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }

    private void recalculateDimensions() {
        fontMetrics = getFontMetrics(monoFont);
        cellWidth = fontMetrics.charWidth('0');
        cellHeight = fontMetrics.getHeight() + 4;

        // Offset area: "00000000  "
        offsetWidth = cellWidth * 10;

        // Hex area: 16 bytes * 3 chars each + extra space in middle
        hexAreaX = offsetWidth;
        int hexAreaWidth = bytesPerRow * cellWidth * 3 + cellWidth;

        // ASCII area
        asciiAreaX = hexAreaX + hexAreaWidth + cellWidth * 2;
        int asciiAreaWidth = bytesPerRow * cellWidth + cellWidth * 2;

        totalWidth = asciiAreaX + asciiAreaWidth + cellWidth;

        updatePreferredSize();
    }

    private void updatePreferredSize() {
        int rows = (editor.size() + bytesPerRow - 1) / bytesPerRow;
        if (rows == 0) rows = 1;
        int height = rows * cellHeight + cellHeight;
        setPreferredSize(new Dimension(totalWidth, height));
        revalidate();
    }

    @Override
    protected void paintComponent(Graphics g) {
        super.paintComponent(g);
        Graphics2D g2 = (Graphics2D) g;
        g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);

        // Background
        g2.setColor(bgColor);
        g2.fillRect(0, 0, getWidth(), getHeight());

        if (editor.size() == 0) {
            g2.setColor(textColor);
            g2.setFont(monoFont);
            g2.drawString("Empty - Press Insert to add bytes or open a file", 20, cellHeight);
            return;
        }

        g2.setFont(monoFont);

        // Calculate visible range
        Rectangle clip = g2.getClipBounds();
        int startRow = Math.max(0, clip.y / cellHeight);
        int endRow = Math.min((clip.y + clip.height) / cellHeight + 1,
                (editor.size() + bytesPerRow - 1) / bytesPerRow);

        // Draw separator lines
        g2.setColor(separatorColor);
        g2.drawLine(offsetWidth - cellWidth / 2, clip.y, offsetWidth - cellWidth / 2, clip.y + clip.height);
        g2.drawLine(asciiAreaX - cellWidth, clip.y, asciiAreaX - cellWidth, clip.y + clip.height);

        // Draw each row
        for (int row = startRow; row < endRow; row++) {
            int y = row * cellHeight + fontMetrics.getAscent() + 2;
            int offset = row * bytesPerRow;

            // Draw offset
            g2.setColor(offsetColor);
            g2.drawString(String.format("%08X", offset), 0, y);

            // Draw hex bytes and ASCII
            for (int col = 0; col < bytesPerRow && offset + col < editor.size(); col++) {
                int byteOffset = offset + col;
                int b = editor.getByte(byteOffset);

                // Calculate positions
                int hexX = hexAreaX + col * cellWidth * 3 + (col >= 8 ? cellWidth : 0);
                int asciiX = asciiAreaX + col * cellWidth;

                // Draw selection background
                if (isSelected(byteOffset)) {
                    g2.setColor(selectionBg);
                    g2.fillRect(hexX - 1, row * cellHeight, cellWidth * 2 + 2, cellHeight);
                    g2.fillRect(asciiX - 1, row * cellHeight, cellWidth + 2, cellHeight);
                }

                // Draw hex byte
                if (modifiedOffsets.contains(byteOffset)) {
                    g2.setColor(modifiedColor);
                } else if (b == 0) {
                    g2.setColor(nullByteColor);
                } else {
                    g2.setColor(textColor);
                }
                g2.drawString(String.format("%02X", b), hexX, y);

                // Draw ASCII char
                char c = (b >= 32 && b < 127) ? (char) b : '.';
                if (b >= 32 && b < 127) {
                    g2.setColor(asciiColor);
                } else {
                    g2.setColor(nullByteColor);
                }
                g2.drawString(String.valueOf(c), asciiX, y);
            }
        }

        // Draw caret
        if (showCaret && hasFocus() && caretPosition < editor.size()) {
            int row = caretPosition / bytesPerRow;
            int col = caretPosition % bytesPerRow;
            int y = row * cellHeight;

            g2.setColor(caretColor);
            g2.setStroke(new BasicStroke(2));

            if (caretInAscii) {
                int x = asciiAreaX + col * cellWidth;
                g2.drawRect(x - 1, y, cellWidth + 1, cellHeight - 1);
            } else {
                int x = hexAreaX + col * cellWidth * 3 + (col >= 8 ? cellWidth : 0);
                if (caretHighNibble) {
                    g2.drawLine(x, y + cellHeight - 2, x + cellWidth, y + cellHeight - 2);
                } else {
                    g2.drawLine(x + cellWidth, y + cellHeight - 2, x + cellWidth * 2, y + cellHeight - 2);
                }
            }
        }
    }

    private void handleMousePressed(MouseEvent e) {
        int offset = getOffsetFromPoint(e.getPoint());
        if (offset >= 0 && offset < editor.size()) {
            caretPosition = offset;
            caretInAscii = isPointInAsciiArea(e.getPoint());
            caretHighNibble = true;

            if ((e.getModifiersEx() & InputEvent.SHIFT_DOWN_MASK) != 0) {
                if (selectionStart == -1) {
                    selectionStart = caretPosition;
                }
                selectionEnd = offset;
            } else {
                clearSelection();
                selectionStart = offset;
            }
            repaint();
        }
    }

    private void handleMouseDragged(MouseEvent e) {
        int offset = getOffsetFromPoint(e.getPoint());
        if (offset >= 0) {
            offset = Math.min(offset, editor.size() - 1);
            selectionEnd = offset;
            caretPosition = offset;
            scrollToCaret();
            repaint();
        }
    }

    private int getOffsetFromPoint(Point p) {
        int row = p.y / cellHeight;
        int col = -1;

        if (p.x >= hexAreaX && p.x < asciiAreaX - cellWidth) {
            // In hex area
            int relX = p.x - hexAreaX;
            col = relX / (cellWidth * 3);
            if (col >= 8) {
                col = (relX - cellWidth) / (cellWidth * 3);
            }
            col = Math.min(col, bytesPerRow - 1);
        } else if (p.x >= asciiAreaX) {
            // In ASCII area
            col = (p.x - asciiAreaX) / cellWidth;
            col = Math.min(col, bytesPerRow - 1);
        }

        if (col >= 0) {
            return row * bytesPerRow + col;
        }
        return -1;
    }

    private boolean isPointInAsciiArea(Point p) {
        return p.x >= asciiAreaX;
    }

    private void moveCaret(int delta, boolean extend) {
        int newPos = caretPosition + delta;
        if (newPos < 0) newPos = 0;
        if (newPos >= editor.size()) newPos = Math.max(0, editor.size() - 1);

        if (extend) {
            if (selectionStart == -1) {
                selectionStart = caretPosition;
            }
            selectionEnd = newPos;
        } else {
            clearSelection();
        }

        caretPosition = newPos;
        caretHighNibble = true;
        scrollToCaret();
        repaint();
    }

    private void scrollToCaret() {
        int row = caretPosition / bytesPerRow;
        int y = row * cellHeight;
        Rectangle visible = new Rectangle(0, y, 1, cellHeight * 2);
        scrollRectToVisible(visible);
    }

    private boolean hasSelection() {
        return selectionStart >= 0 && selectionEnd >= 0 && selectionStart != selectionEnd;
    }

    private boolean isSelected(int offset) {
        if (selectionStart < 0 || selectionEnd < 0) return false;
        int start = Math.min(selectionStart, selectionEnd);
        int end = Math.max(selectionStart, selectionEnd);
        return offset >= start && offset <= end;
    }

    private void clearSelection() {
        selectionStart = -1;
        selectionEnd = -1;
    }

    private void selectWord() {
        selectionStart = caretPosition;
        selectionEnd = caretPosition;
        repaint();
    }

    private void deleteSelection() {
        if (!hasSelection()) {
            if (caretPosition < editor.size()) {
                editor.deleteBytes(caretPosition, 1);
                fireDataChanged();
                repaint();
            }
            return;
        }

        int start = Math.min(selectionStart, selectionEnd);
        int end = Math.max(selectionStart, selectionEnd);
        int length = end - start + 1;

        editor.deleteBytes(start, length);
        caretPosition = start;
        if (caretPosition >= editor.size()) {
            caretPosition = Math.max(0, editor.size() - 1);
        }
        clearSelection();
        fireDataChanged();
        repaint();
    }

    private void copyToClipboard() {
        if (!hasSelection() && editor.size() == 0) return;

        int start, end;
        if (hasSelection()) {
            start = Math.min(selectionStart, selectionEnd);
            end = Math.max(selectionStart, selectionEnd);
        } else {
            start = caretPosition;
            end = caretPosition;
        }

        byte[] data = editor.getBytes(start, end - start + 1);
        StringBuilder sb = new StringBuilder();
        for (byte b : data) {
            sb.append(String.format("%02X ", b & 0xFF));
        }

        StringSelection selection = new StringSelection(sb.toString().trim());
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, null);
    }

    private void pasteFromClipboard() {
        try {
            String data = (String) Toolkit.getDefaultToolkit()
                    .getSystemClipboard().getData(DataFlavor.stringFlavor);

            if (data != null && !data.isEmpty()) {
                byte[] bytes;
                // Try to parse as hex first
                try {
                    bytes = HexEditor.parseHexString(data.replaceAll("[^0-9A-Fa-f]", ""));
                } catch (Exception e) {
                    // If not valid hex, use as ASCII
                    bytes = data.getBytes();
                }

                if (hasSelection()) {
                    deleteSelection();
                }

                if (editor.size() == 0) {
                    editor.appendBytes(bytes);
                    caretPosition = bytes.length - 1;
                } else {
                    editor.insertBytes(caretPosition, bytes);
                    caretPosition += bytes.length;
                }

                for (int i = 0; i < bytes.length; i++) {
                    modifiedOffsets.add(caretPosition - bytes.length + i);
                }

                fireDataChanged();
                repaint();
            }
        } catch (Exception e) {
            // Ignore clipboard errors
        }
    }

    // Scrollable implementation
    @Override
    public Dimension getPreferredScrollableViewportSize() {
        return new Dimension(totalWidth, cellHeight * 25);
    }

    @Override
    public int getScrollableUnitIncrement(Rectangle visibleRect, int orientation, int direction) {
        return cellHeight;
    }

    @Override
    public int getScrollableBlockIncrement(Rectangle visibleRect, int orientation, int direction) {
        return cellHeight * 10;
    }

    @Override
    public boolean getScrollableTracksViewportWidth() {
        return false;
    }

    @Override
    public boolean getScrollableTracksViewportHeight() {
        return false;
    }

    // Public API

    /**
     * Gets the HexEditor
     *
     * @return the editor
     */
    public HexEditor getEditor() {
        return editor;
    }

    /**
     * Sets the HexEditor
     *
     * @param editor the editor to use
     */
    public void setEditor(HexEditor editor) {
        this.editor = editor;
        caretPosition = 0;
        clearSelection();
        modifiedOffsets.clear();
        updatePreferredSize();
        repaint();
    }

    /**
     * Refreshes the display
     */
    public void refresh() {
        updatePreferredSize();
        repaint();
    }

    /**
     * Gets the current caret position
     *
     * @return caret offset
     */
    public int getCaretPosition() {
        return caretPosition;
    }

    /**
     * Sets the caret position
     *
     * @param position new caret position
     */
    public void setCaretPosition(int position) {
        if (position >= 0 && position < editor.size()) {
            caretPosition = position;
            clearSelection();
            scrollToCaret();
            repaint();
        }
    }

    /**
     * Gets the selection start offset
     *
     * @return selection start, or -1 if no selection
     */
    public int getSelectionStart() {
        return hasSelection() ? Math.min(selectionStart, selectionEnd) : -1;
    }

    /**
     * Gets the selection end offset
     *
     * @return selection end, or -1 if no selection
     */
    public int getSelectionEnd() {
        return hasSelection() ? Math.max(selectionStart, selectionEnd) : -1;
    }

    /**
     * Sets the selection range
     *
     * @param start selection start
     * @param end   selection end
     */
    public void setSelection(int start, int end) {
        if (start >= 0 && end >= 0 && start < editor.size() && end < editor.size()) {
            selectionStart = start;
            selectionEnd = end;
            caretPosition = end;
            scrollToCaret();
            repaint();
        }
    }

    /**
     * Clears modified byte markers
     */
    public void clearModifiedMarkers() {
        modifiedOffsets.clear();
        repaint();
    }

    /**
     * Navigates to a specific offset
     *
     * @param offset the offset to go to
     */
    public void gotoOffset(int offset) {
        if (offset >= 0 && offset < editor.size()) {
            setCaretPosition(offset);
        }
    }

    /**
     * Adds a change listener
     *
     * @param listener the listener to add
     */
    public void addChangeListener(ChangeListener listener) {
        changeListeners.add(listener);
    }

    /**
     * Removes a change listener
     *
     * @param listener the listener to remove
     */
    public void removeChangeListener(ChangeListener listener) {
        changeListeners.remove(listener);
    }

    private void fireDataChanged() {
        updatePreferredSize();
        ChangeEvent event = new ChangeEvent(this);
        for (ChangeListener listener : changeListeners) {
            listener.stateChanged(event);
        }
    }

    /**
     * Sets the number of bytes per row
     *
     * @param bytes bytes per row (8-32)
     */
    public void setBytesPerRow(int bytes) {
        if (bytes >= 8 && bytes <= 32) {
            this.bytesPerRow = bytes;
            recalculateDimensions();
            repaint();
        }
    }

    /**
     * Gets the number of bytes per row
     *
     * @return bytes per row
     */
    public int getBytesPerRow() {
        return bytesPerRow;
    }
}
