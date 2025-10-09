package io.xlogistx.gui;

import org.zoxweb.server.io.UByteArrayOutputStream;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableColumn;
import java.awt.*;

/**
 * A simple embeddable hex editor widget using Swing.
 * Displays binary data in hexadecimal format with offset, hex bytes, and ASCII preview.
 * Uses UByteArrayOutputStream for managing the underlying byte data.
 *
 * To use: Include UByteArrayOutputStream.java in your project, instantiate HexEditor,
 * and call setData(byte[]) to load data. Editing is supported via the table.
 */
public class HexEditor extends JPanel {
    private JTable hexTable;
    private HexTableModel model;
    private UByteArrayOutputStream dataStream;

    public HexEditor() {
        dataStream = new UByteArrayOutputStream();
        model = new HexTableModel();
        hexTable = new JTable(model);
        hexTable.setShowGrid(true);
        hexTable.setGridColor(Color.GRAY);
        hexTable.setSelectionMode(ListSelectionModel.SINGLE_INTERVAL_SELECTION);
        hexTable.setDefaultRenderer(Object.class, new HexCellRenderer());

        // Configure columns
        setupColumns();

        setLayout(new BorderLayout());
        add(new JScrollPane(hexTable), BorderLayout.CENTER);
    }

    private void setupColumns() {
        // Offset column
        TableColumn offsetColumn = hexTable.getColumnModel().getColumn(0);
        offsetColumn.setPreferredWidth(80);
        offsetColumn.setMinWidth(80);
        offsetColumn.setMaxWidth(80);
        offsetColumn.setResizable(false);

        // Hex columns (16 columns for bytes 00-0F)
        for (int i = 1; i <= 16; i++) {
            TableColumn hexColumn = hexTable.getColumnModel().getColumn(i);
            hexColumn.setPreferredWidth(35);
            hexColumn.setMinWidth(35);
            hexColumn.setMaxWidth(35);
            hexColumn.setResizable(false);
        }

        // ASCII column
        TableColumn asciiColumn = hexTable.getColumnModel().getColumn(17);
        asciiColumn.setPreferredWidth(200);
        asciiColumn.setMinWidth(200);
        asciiColumn.setResizable(true);
        asciiColumn.setCellRenderer(new AsciiCellRenderer());
    }

    /**
     * Sets the data for the hex editor using UByteArrayOutputStream.
     * @param bytes The byte array to display and edit.
     */
    public void setData(byte[] bytes) {
        dataStream.reset();
        dataStream.write(bytes);
        model.fireTableDataChanged();
    }

    /**
     * Gets the current edited data as a byte array via UByteArrayOutputStream.
     * @return The byte array representing the current state.
     */
    public byte[] getData() {
        return dataStream.toByteArray();
    }

    private static final String[] COLUMN_NAMES = new String[18]; // Offset + 16 hex + ASCII

    static {
        COLUMN_NAMES[0] = "Offset";
        for (int i = 0; i < 16; i++) {
            COLUMN_NAMES[i + 1] = String.format("%02X", i);
        }
        COLUMN_NAMES[17] = "ASCII";
    }

    /**
     * Table model for the hex display.
     */
    private class HexTableModel extends AbstractTableModel {
        private static final int BYTES_PER_ROW = 16;

        @Override
        public int getRowCount() {
            return (int) Math.ceil((double) dataStream.size() / BYTES_PER_ROW);
        }

        @Override
        public int getColumnCount() {
            return COLUMN_NAMES.length;
        }

        @Override
        public String getColumnName(int column) {
            return COLUMN_NAMES[column];
        }

        @Override
        public Object getValueAt(int row, int column) {
            byte[] current = dataStream.getInternalBuffer();
            long dataSize = dataStream.size();
            int offset = row * BYTES_PER_ROW;
            if (column == 0) {
                // Offset column
                return String.format("0x%08X", offset);
            } else if (column <= 16) {
                // Hex columns 1-16
                int byteIndex = offset + (column - 1);
                if (byteIndex < dataSize) {
                    int b = current[byteIndex] & 0xFF;
                    return String.format("%02X", b);
                }
                return "";
            } else {
                // ASCII column (last)
                StringBuilder ascii = new StringBuilder();
                for (int i = 0; i < BYTES_PER_ROW; i++) {
                    int byteIndex = offset + i;
                    if (byteIndex < dataSize) {
                        int b = current[byteIndex] & 0xFF;
                        char c = (char) b;
                        ascii.append((c >= 32 && c <= 126) ? c : '.');
                    } else {
                        ascii.append(' ');
                    }
                }
                return ascii.toString();
            }
        }

        @Override
        public boolean isCellEditable(int row, int column) {
            return column > 0 && column <= 17; // Hex cells and ASCII editable
        }

        @Override
        public void setValueAt(Object value, int row, int column) {
            if (value instanceof String) {
                try {
                    int offset = row * BYTES_PER_ROW;
                    long dataSize = dataStream.size();
                    if (column > 0 && column <= 16) {
                        // Hex edit
                        int byteIndex = offset + (column - 1);
                        int newByte = Integer.parseInt((String) value, 16);
                        dataStream.writeAt(byteIndex, (byte) newByte);
                    } else if (column == 17) {
                        // ASCII edit
                        String newAscii = (String) value;
                        int maxBytes = Math.min(BYTES_PER_ROW, (int) (dataSize - offset));
                        for (int i = 0; i < newAscii.length() && i < maxBytes; i++) {
                            char ch = newAscii.charAt(i);
                            byte newByte = (byte) ch;
                            dataStream.writeAt(offset + i, newByte);
                        }
                        // If newAscii is longer than maxBytes, extra chars are ignored
                        // If shorter, remaining bytes unchanged
                    }
                    fireTableDataChanged(); // Refresh entire table for simplicity
                } catch (NumberFormatException e) {
                    // Invalid hex, ignore or handle error
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
    }

    /**
     * Renderer for hex cells to align and format.
     */
    private static class HexCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                                                       boolean isSelected, boolean hasFocus,
                                                       int row, int column) {
            super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            setHorizontalAlignment(CENTER);
            if (value != null && value instanceof String) {
                setText((String) value);
            }
            return this;
        }
    }

    /**
     * Renderer for ASCII cells to left-align.
     */
    private static class AsciiCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                                                       boolean isSelected, boolean hasFocus,
                                                       int row, int column) {
            super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            setHorizontalAlignment(LEFT);
            if (value != null && value instanceof String) {
                System.out.println(value);
                setText((String) value);
            }
            return this;
        }
    }

    // Example usage (for testing)
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            JFrame frame = new JFrame("Hex Editor");
            HexEditor editor = new HexEditor();
            byte[] sampleData = "Hello, World!\"The quick brown fox jumps over the lazy dog\" is an English-language pangram – a sentence that contains all the letters of the alphabet. The phrase is commonly used for touch-typing practice, testing typewriters and computer keyboards, displaying examples of fonts, and other applications involving text where the use of all letters in the alphabet is desired".getBytes();
            editor.setData(sampleData);
            frame.add(editor);
            frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            frame.pack();
            frame.setSize(800, 600);
            frame.setVisible(true);
        });
    }
}