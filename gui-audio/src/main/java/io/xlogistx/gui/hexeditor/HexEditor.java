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

import org.zoxweb.server.io.UByteArrayOutputStream;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * A hexadecimal editor that uses UByteArrayOutputStream as its data buffer.
 * Takes full advantage of UByteArrayOutputStream's insertAt, writeAt, removeAt,
 * indexOf, and copyBytes methods.
 */
public class HexEditor {

    private final UByteArrayOutputStream buffer;
    private int cursor;
    private int bytesPerLine;
    private boolean modified;
    private String currentFilePath;
    private final List<UndoEntry> undoStack;
    private final List<UndoEntry> redoStack;
    private static final int MAX_UNDO_STACK = 100;

    /**
     * Represents an undo/redo entry
     */
    private static class UndoEntry {
        final int offset;
        final byte[] oldData;
        final byte[] newData;
        final OperationType type;

        enum OperationType {
            MODIFY, INSERT, DELETE
        }

        UndoEntry(int offset, byte[] oldData, byte[] newData, OperationType type) {
            this.offset = offset;
            this.oldData = oldData;
            this.newData = newData;
            this.type = type;
        }
    }

    /**
     * Creates a new empty HexEditor
     */
    public HexEditor() {
        this.buffer = new UByteArrayOutputStream();
        this.cursor = 0;
        this.bytesPerLine = 16;
        this.modified = false;
        this.undoStack = new ArrayList<UndoEntry>();
        this.redoStack = new ArrayList<UndoEntry>();
    }

    /**
     * Creates a HexEditor with initial data
     *
     * @param data initial byte array data
     */
    public HexEditor(byte[] data) {
        this();
        if (data != null && data.length > 0) {
            buffer.write(data, 0, data.length);
        }
    }

    /**
     * Creates a HexEditor and loads a file
     *
     * @param file the file to load
     * @throws IOException if file cannot be read
     */
    public HexEditor(File file) throws IOException {
        this();
        loadFile(file);
    }

    // ==================== File Operations ====================

    /**
     * Loads a file into the buffer
     *
     * @param file the file to load
     * @throws IOException if file cannot be read
     */
    public void loadFile(File file) throws IOException {
        buffer.reset();
        
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] readBuffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = fis.read(readBuffer)) != -1) {
                buffer.write(readBuffer, 0, bytesRead);
            }
        }
        
        cursor = 0;
        modified = false;
        currentFilePath = file.getAbsolutePath();
        undoStack.clear();
        redoStack.clear();
    }

    /**
     * Loads a file from path
     *
     * @param path the file path
     * @throws IOException if file cannot be read
     */
    public void loadFile(String path) throws IOException {
        loadFile(new File(path));
    }

    /**
     * Saves the buffer to the current file
     *
     * @throws IOException if file cannot be written or no file path set
     */
    public void save() throws IOException {
        if (currentFilePath == null) {
            throw new IOException("No file path set. Use saveAs() instead.");
        }
        saveAs(currentFilePath);
    }

    /**
     * Saves the buffer to a specified file path
     *
     * @param path the file path to save to
     * @throws IOException if file cannot be written
     */
    public void saveAs(String path) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(path)) {
            fos.write(buffer.getInternalBuffer(), 0, buffer.size());
        }
        currentFilePath = path;
        modified = false;
    }

    /**
     * Saves the buffer to a specified file
     *
     * @param file the file to save to
     * @throws IOException if file cannot be written
     */
    public void saveAs(File file) throws IOException {
        saveAs(file.getAbsolutePath());
    }

    // ==================== Data Access ====================

    /**
     * Gets a copy of the buffer data as a byte array
     *
     * @return copy of all bytes in the buffer
     */
    public byte[] getBytes() {
        return buffer.toByteArray();
    }

    /**
     * Gets the size of the buffer
     *
     * @return number of bytes in buffer
     */
    public int size() {
        return buffer.size();
    }

    /**
     * Gets a byte at the specified offset using UByteArrayOutputStream's byteAt
     *
     * @param offset the byte offset
     * @return unsigned byte value (0-255)
     * @throws IndexOutOfBoundsException if offset is invalid
     */
    public int getByte(int offset) {
        if (offset < 0 || offset >= buffer.size()) {
            throw new IndexOutOfBoundsException("Offset " + offset + " out of bounds [0, " + buffer.size() + ")");
        }
        return buffer.byteAt(offset) & 0xFF;
    }

    /**
     * Gets a range of bytes using UByteArrayOutputStream's copyBytes
     *
     * @param offset start offset
     * @param length number of bytes
     * @return copy of the byte range
     * @throws IndexOutOfBoundsException if range is invalid
     */
    public byte[] getBytes(int offset, int length) {
        if (offset < 0 || offset + length > buffer.size()) {
            throw new IndexOutOfBoundsException("Range [" + offset + ", " + (offset + length) + ") out of bounds");
        }
        return buffer.copyBytes(offset, offset + length);
    }

    /**
     * Gets the underlying UByteArrayOutputStream buffer
     *
     * @return the buffer
     */
    public UByteArrayOutputStream getBuffer() {
        return buffer;
    }

    /**
     * Gets direct access to internal buffer array.
     * Use with caution - modifications bypass undo tracking.
     *
     * @return internal buffer array
     */
//    public byte[] getInternalBuffer() {
//        return buffer.getInternalBuffer();
//    }

    // ==================== Data Modification ====================

    /**
     * Sets a byte at the specified offset using UByteArrayOutputStream's writeAt
     *
     * @param offset the byte offset
     * @param value  the byte value (0-255)
     * @throws IndexOutOfBoundsException if offset is invalid
     */
    public void setByte(int offset, int value) {
        if (offset < 0 || offset >= buffer.size()) {
            throw new IndexOutOfBoundsException("Offset " + offset + " out of bounds");
        }

        byte[] oldData = new byte[]{buffer.byteAt(offset)};
        byte[] newData = new byte[]{(byte) value};

        // Use UByteArrayOutputStream's writeAt method
        buffer.writeAt(offset, (byte) value);
        modified = true;

        addUndoEntry(new UndoEntry(offset, oldData, newData, UndoEntry.OperationType.MODIFY));
    }

    /**
     * Sets a byte at the specified offset from a hex string (e.g., "FF")
     *
     * @param offset   the byte offset
     * @param hexValue hex string representing the byte
     */
    public void setByteHex(int offset, String hexValue) {
        int value = Integer.parseInt(hexValue, 16);
        setByte(offset, value);
    }

    /**
     * Sets multiple bytes starting at the specified offset
     *
     * @param offset start offset
     * @param data   bytes to write
     * @throws IndexOutOfBoundsException if range is invalid
     */
    public void setBytes(int offset, byte[] data) {
        if (offset < 0 || offset + data.length > buffer.size()) {
            throw new IndexOutOfBoundsException("Range out of bounds");
        }

        // Save old data for undo using copyBytes
        byte[] oldData = buffer.copyBytes(offset, offset + data.length);

        // Use writeAt for each byte
        for (int i = 0; i < data.length; i++) {
            buffer.writeAt(offset + i, data[i]);
        }
        modified = true;

        addUndoEntry(new UndoEntry(offset, oldData, data.clone(), UndoEntry.OperationType.MODIFY));
    }

    /**
     * Inserts bytes at the specified offset using UByteArrayOutputStream's insertAt
     *
     * @param offset insertion point
     * @param data   bytes to insert
     * @throws IndexOutOfBoundsException if offset is invalid
     */
    public void insertBytes(int offset, byte[] data) {
        if (offset < 0 || offset > buffer.size()) {
            throw new IndexOutOfBoundsException("Offset out of bounds");
        }

        // Use UByteArrayOutputStream's insertAt method
        buffer.insertAt(offset, data);
        modified = true;

        addUndoEntry(new UndoEntry(offset, new byte[0], data.clone(), UndoEntry.OperationType.INSERT));
    }

    /**
     * Inserts a single byte at the specified offset
     *
     * @param offset insertion point
     * @param value  byte value to insert
     */
    public void insertByte(int offset, int value) {
        insertBytes(offset, new byte[]{(byte) value});
    }

    /**
     * Deletes bytes at the specified offset using UByteArrayOutputStream's removeAt
     *
     * @param offset start offset
     * @param length number of bytes to delete
     * @throws IndexOutOfBoundsException if range is invalid
     */
    public void deleteBytes(int offset, int length) {
        if (offset < 0 || offset + length > buffer.size()) {
            throw new IndexOutOfBoundsException("Range out of bounds");
        }

        // Save deleted data for undo using copyBytes
        byte[] deletedData = buffer.copyBytes(offset, offset + length);

        // Use UByteArrayOutputStream's removeAt method
        buffer.removeAt(offset, length);
        modified = true;

        addUndoEntry(new UndoEntry(offset, deletedData, new byte[0], UndoEntry.OperationType.DELETE));
    }

    /**
     * Appends bytes to the end of the buffer
     *
     * @param data bytes to append
     */
    public void appendBytes(byte[] data) {
        int offset = buffer.size();
        buffer.write(data, 0, data.length);
        modified = true;
        addUndoEntry(new UndoEntry(offset, new byte[0], data.clone(), UndoEntry.OperationType.INSERT));
    }

    /**
     * Fills a range with a specific byte value
     *
     * @param offset start offset
     * @param length number of bytes to fill
     * @param value  fill value
     */
    public void fill(int offset, int length, int value) {
        if (offset < 0 || offset + length > buffer.size()) {
            throw new IndexOutOfBoundsException("Range out of bounds");
        }

        // Save old data for undo
        byte[] oldData = buffer.copyBytes(offset, offset + length);

        // Fill using writeAt
        for (int i = 0; i < length; i++) {
            buffer.writeAt(offset + i, (byte) value);
        }
        modified = true;

        byte[] fillData = new byte[length];
        java.util.Arrays.fill(fillData, (byte) value);
        addUndoEntry(new UndoEntry(offset, oldData, fillData, UndoEntry.OperationType.MODIFY));
    }

    // ==================== Undo/Redo ====================

    private void addUndoEntry(UndoEntry entry) {
        undoStack.add(entry);
        if (undoStack.size() > MAX_UNDO_STACK) {
            undoStack.remove(0);
        }
        redoStack.clear();
    }

    /**
     * Undoes the last operation
     *
     * @return true if undo was performed
     */
    public boolean undo() {
        if (undoStack.isEmpty()) {
            return false;
        }

        UndoEntry entry = undoStack.remove(undoStack.size() - 1);
        applyUndoEntry(entry, true);
        redoStack.add(entry);
        return true;
    }

    /**
     * Redoes the last undone operation
     *
     * @return true if redo was performed
     */
    public boolean redo() {
        if (redoStack.isEmpty()) {
            return false;
        }

        UndoEntry entry = redoStack.remove(redoStack.size() - 1);
        applyUndoEntry(entry, false);
        undoStack.add(entry);
        return true;
    }

    private void applyUndoEntry(UndoEntry entry, boolean isUndo) {
        byte[] dataToApply = isUndo ? entry.oldData : entry.newData;
        byte[] dataToRemove = isUndo ? entry.newData : entry.oldData;

        switch (entry.type) {
            case MODIFY:
                // Use writeAt for modifications
                for (int i = 0; i < dataToApply.length; i++) {
                    buffer.writeAt(entry.offset + i, dataToApply[i]);
                }
                break;

            case INSERT:
                if (isUndo) {
                    // Remove inserted data using removeAt
                    buffer.removeAt(entry.offset, dataToRemove.length);
                } else {
                    // Re-insert data using insertAt
                    buffer.insertAt(entry.offset, dataToApply);
                }
                break;

            case DELETE:
                if (isUndo) {
                    // Re-insert deleted data using insertAt
                    buffer.insertAt(entry.offset, dataToApply);
                } else {
                    // Re-delete data using removeAt
                    buffer.removeAt(entry.offset, dataToRemove.length);
                }
                break;
        }
    }

    // ==================== Search Operations ====================

    /**
     * Searches for a byte pattern using UByteArrayOutputStream's indexOf
     *
     * @param pattern    bytes to search for
     * @param startOffset starting position
     * @return offset of found pattern, or -1 if not found
     */
    public int find(byte[] pattern, int startOffset) {
        if (pattern == null || pattern.length == 0) {
            return -1;
        }

        // Use UByteArrayOutputStream's indexOf method
        return buffer.indexOf(startOffset, pattern);
    }

    /**
     * Searches for a hex pattern (e.g., "FF 00 AB")
     *
     * @param hexPattern hex string pattern
     * @param startOffset starting position
     * @return offset of found pattern, or -1 if not found
     */
    public int findHex(String hexPattern, int startOffset) {
        byte[] pattern = parseHexString(hexPattern);
        return find(pattern, startOffset);
    }

    /**
     * Searches for a text string
     *
     * @param text       text to search for
     * @param startOffset starting position
     * @return offset of found text, or -1 if not found
     */
    public int findText(String text, int startOffset) {
        return find(text.getBytes(), startOffset);
    }

    /**
     * Searches for a text string (case-insensitive) using indexOf
     *
     * @param text text to search for
     * @return offset of found text, or -1 if not found
     */
    public int findTextIgnoreCase(String text) {
        return buffer.indexOfIgnoreCase(text);
    }

    /**
     * Finds all occurrences of a pattern
     *
     * @param pattern bytes to search for
     * @return list of offsets where pattern was found
     */
    public List<Integer> findAll(byte[] pattern) {
        List<Integer> results = new ArrayList<Integer>();
        int offset = 0;
        while ((offset = find(pattern, offset)) != -1) {
            results.add(offset);
            offset++;
        }
        return results;
    }

    /**
     * Replaces first occurrence of a pattern
     *
     * @param search      bytes to find
     * @param replacement bytes to replace with
     * @param startOffset starting position
     * @return true if replacement was made
     */
    public boolean replace(byte[] search, byte[] replacement, int startOffset) {
        int offset = find(search, startOffset);
        if (offset == -1) {
            return false;
        }

        // Save old data for undo
        byte[] oldData = buffer.copyBytes(offset, offset + search.length);

        if (search.length == replacement.length) {
            // Same length - use writeAt
            for (int i = 0; i < replacement.length; i++) {
                buffer.writeAt(offset + i, replacement[i]);
            }
            addUndoEntry(new UndoEntry(offset, oldData, replacement.clone(), UndoEntry.OperationType.MODIFY));
        } else {
            // Different length - remove and insert
            buffer.removeAt(offset, search.length);
            buffer.insertAt(offset, replacement);
            addUndoEntry(new UndoEntry(offset, oldData, replacement.clone(), UndoEntry.OperationType.MODIFY));
        }

        modified = true;
        return true;
    }

    /**
     * Replaces all occurrences of a pattern
     *
     * @param search      bytes to find
     * @param replacement bytes to replace with
     * @return number of replacements made
     */
    public int replaceAll(byte[] search, byte[] replacement) {
        int count = 0;
        int offset = 0;
        while ((offset = find(search, offset)) != -1) {
            // Save old data
            byte[] oldData = buffer.copyBytes(offset, offset + search.length);

            if (search.length == replacement.length) {
                for (int i = 0; i < replacement.length; i++) {
                    buffer.writeAt(offset + i, replacement[i]);
                }
            } else {
                buffer.removeAt(offset, search.length);
                buffer.insertAt(offset, replacement);
            }

            addUndoEntry(new UndoEntry(offset, oldData, replacement.clone(), UndoEntry.OperationType.MODIFY));
            offset += replacement.length;
            count++;
        }

        if (count > 0) {
            modified = true;
        }
        return count;
    }

    // ==================== Display/Formatting ====================

    /**
     * Sets the number of bytes displayed per line
     *
     * @param bytes bytes per line (1-64)
     */
    public void setBytesPerLine(int bytes) {
        if (bytes < 1 || bytes > 64) {
            throw new IllegalArgumentException("Bytes per line must be between 1 and 64");
        }
        this.bytesPerLine = bytes;
    }

    /**
     * Gets a hex dump of the entire buffer
     *
     * @return formatted hex dump string
     */
    public String toHexDump() {
        return toHexDump(0, buffer.size());
    }

    /**
     * Gets a hex dump of a range
     *
     * @param offset start offset
     * @param length number of bytes
     * @return formatted hex dump string
     */
    public String toHexDump(int offset, int length) {
        StringBuilder sb = new StringBuilder();
        int end = Math.min(offset + length, buffer.size());

        for (int i = offset; i < end; i += bytesPerLine) {
            // Address
            sb.append(String.format("%08X  ", i));

            // Hex bytes
            StringBuilder ascii = new StringBuilder();
            for (int j = 0; j < bytesPerLine; j++) {
                if (i + j < end) {
                    int b = buffer.byteAt(i + j) & 0xFF;
                    sb.append(String.format("%02X ", b));
                    ascii.append(isPrintable(b) ? (char) b : '.');
                } else {
                    sb.append("   ");
                    ascii.append(' ');
                }

                // Add extra space in middle
                if (j == bytesPerLine / 2 - 1) {
                    sb.append(" ");
                }
            }

            // ASCII representation
            sb.append(" |").append(ascii).append("|\n");
        }

        return sb.toString();
    }

    /**
     * Gets a simple hex string of the entire buffer
     *
     * @return hex string
     */
    public String toHexString() {
        return toHexString(0, buffer.size());
    }

    /**
     * Gets a simple hex string of a range
     *
     * @param offset start offset
     * @param length number of bytes
     * @return hex string
     */
    public String toHexString(int offset, int length) {
        StringBuilder sb = new StringBuilder();
        int end = Math.min(offset + length, buffer.size());

        for (int i = offset; i < end; i++) {
            sb.append(String.format("%02X", buffer.byteAt(i) & 0xFF));
            if (i < end - 1) {
                sb.append(" ");
            }
        }
        return sb.toString();
    }

    private boolean isPrintable(int b) {
        return b >= 32 && b < 127;
    }

    // ==================== Cursor Operations ====================

    /**
     * Gets the current cursor position
     *
     * @return cursor offset
     */
    public int getCursor() {
        return cursor;
    }

    /**
     * Sets the cursor position
     *
     * @param position new cursor position
     */
    public void setCursor(int position) {
        if (position < 0) {
            position = 0;
        } else if (position >= buffer.size() && buffer.size() > 0) {
            position = buffer.size() - 1;
        }
        this.cursor = position;
    }

    /**
     * Moves the cursor by a relative amount
     *
     * @param delta amount to move
     */
    public void moveCursor(int delta) {
        setCursor(cursor + delta);
    }

    /**
     * Gets the byte at the current cursor position
     *
     * @return byte value, or -1 if buffer is empty
     */
    public int getByteAtCursor() {
        if (buffer.size() == 0) {
            return -1;
        }
        return getByte(cursor);
    }

    /**
     * Sets the byte at the current cursor position
     *
     * @param value byte value
     */
    public void setByteAtCursor(int value) {
        if (buffer.size() == 0) {
            throw new IllegalStateException("Buffer is empty");
        }
        setByte(cursor, value);
    }

    // ==================== Utility Methods ====================

    /**
     * Parses a hex string into bytes.
     * Accepts formats: "FF00AB", "FF 00 AB", "FF-00-AB"
     *
     * @param hex hex string
     * @return byte array
     */
    public static byte[] parseHexString(String hex) {
        hex = hex.replaceAll("[\\s\\-]", "");
        if (hex.length() % 2 != 0) {
            throw new IllegalArgumentException("Hex string must have even length");
        }

        byte[] result = new byte[hex.length() / 2];
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return result;
    }

    /**
     * Checks if the buffer has been modified since last save/load
     *
     * @return true if modified
     */
    public boolean isModified() {
        return modified;
    }

    /**
     * Gets the current file path
     *
     * @return file path or null
     */
    public String getCurrentFilePath() {
        return currentFilePath;
    }

    /**
     * Clears the buffer
     */
    public void clear() {
        byte[] oldData = buffer.toByteArray();
        buffer.reset();
        cursor = 0;
        modified = true;
        addUndoEntry(new UndoEntry(0, oldData, new byte[0], UndoEntry.OperationType.DELETE));
    }

    /**
     * Gets buffer statistics
     *
     * @return statistics string
     */
    public String getStatistics() {
        StringBuilder sb = new StringBuilder();
        sb.append("=== Buffer Statistics ===\n");
        sb.append(String.format("Size: %d bytes\n", buffer.size()));
        sb.append(String.format("Cursor: 0x%08X (%d)\n", cursor, cursor));
        sb.append(String.format("Modified: %s\n", modified));
        sb.append(String.format("File: %s\n", currentFilePath != null ? currentFilePath : "(none)"));
        sb.append(String.format("Undo stack: %d entries\n", undoStack.size()));
        sb.append(String.format("Redo stack: %d entries\n", redoStack.size()));

        if (buffer.size() > 0) {
            // Byte frequency analysis
            int[] freq = new int[256];
            byte[] data = buffer.getInternalBuffer();
            for (int i = 0; i < buffer.size(); i++) {
                freq[data[i] & 0xFF]++;
            }

            int nullBytes = freq[0];
            int printableBytes = 0;
            for (int i = 32; i < 127; i++) {
                printableBytes += freq[i];
            }

            sb.append(String.format("Null bytes: %d (%.1f%%)\n", nullBytes, 100.0 * nullBytes / buffer.size()));
            sb.append(String.format("Printable ASCII: %d (%.1f%%)\n", printableBytes, 100.0 * printableBytes / buffer.size()));
        }

        return sb.toString();
    }

    // ==================== Multi-byte Read Operations ====================

    /**
     * Reads a 16-bit integer (big-endian)
     *
     * @param offset byte offset
     * @return 16-bit value
     */
    public int readInt16BE(int offset) {
        return ((buffer.byteAt(offset) & 0xFF) << 8) | (buffer.byteAt(offset + 1) & 0xFF);
    }

    /**
     * Reads a 16-bit integer (little-endian)
     *
     * @param offset byte offset
     * @return 16-bit value
     */
    public int readInt16LE(int offset) {
        return (buffer.byteAt(offset) & 0xFF) | ((buffer.byteAt(offset + 1) & 0xFF) << 8);
    }

    /**
     * Reads a 32-bit integer (big-endian)
     *
     * @param offset byte offset
     * @return 32-bit value
     */
    public int readInt32BE(int offset) {
        return ((buffer.byteAt(offset) & 0xFF) << 24) |
               ((buffer.byteAt(offset + 1) & 0xFF) << 16) |
               ((buffer.byteAt(offset + 2) & 0xFF) << 8) |
               (buffer.byteAt(offset + 3) & 0xFF);
    }

    /**
     * Reads a 32-bit integer (little-endian)
     *
     * @param offset byte offset
     * @return 32-bit value
     */
    public int readInt32LE(int offset) {
        return (buffer.byteAt(offset) & 0xFF) |
               ((buffer.byteAt(offset + 1) & 0xFF) << 8) |
               ((buffer.byteAt(offset + 2) & 0xFF) << 16) |
               ((buffer.byteAt(offset + 3) & 0xFF) << 24);
    }

    /**
     * Reads a 64-bit integer (big-endian)
     *
     * @param offset byte offset
     * @return 64-bit value
     */
    public long readInt64BE(int offset) {
        return ((long) (buffer.byteAt(offset) & 0xFF) << 56) |
               ((long) (buffer.byteAt(offset + 1) & 0xFF) << 48) |
               ((long) (buffer.byteAt(offset + 2) & 0xFF) << 40) |
               ((long) (buffer.byteAt(offset + 3) & 0xFF) << 32) |
               ((long) (buffer.byteAt(offset + 4) & 0xFF) << 24) |
               ((long) (buffer.byteAt(offset + 5) & 0xFF) << 16) |
               ((long) (buffer.byteAt(offset + 6) & 0xFF) << 8) |
               (buffer.byteAt(offset + 7) & 0xFF);
    }

    /**
     * Reads a 64-bit integer (little-endian)
     *
     * @param offset byte offset
     * @return 64-bit value
     */
    public long readInt64LE(int offset) {
        return (buffer.byteAt(offset) & 0xFF) |
               ((long) (buffer.byteAt(offset + 1) & 0xFF) << 8) |
               ((long) (buffer.byteAt(offset + 2) & 0xFF) << 16) |
               ((long) (buffer.byteAt(offset + 3) & 0xFF) << 24) |
               ((long) (buffer.byteAt(offset + 4) & 0xFF) << 32) |
               ((long) (buffer.byteAt(offset + 5) & 0xFF) << 40) |
               ((long) (buffer.byteAt(offset + 6) & 0xFF) << 48) |
               ((long) (buffer.byteAt(offset + 7) & 0xFF) << 56);
    }

    // ==================== Multi-byte Write Operations ====================

    /**
     * Writes a 16-bit integer (big-endian)
     *
     * @param offset byte offset
     * @param value  16-bit value
     */
    public void writeInt16BE(int offset, int value) {
        byte[] oldData = buffer.copyBytes(offset, offset + 2);
        buffer.writeAt(offset, (byte) ((value >> 8) & 0xFF));
        buffer.writeAt(offset + 1, (byte) (value & 0xFF));
        modified = true;
        byte[] newData = new byte[]{(byte) ((value >> 8) & 0xFF), (byte) (value & 0xFF)};
        addUndoEntry(new UndoEntry(offset, oldData, newData, UndoEntry.OperationType.MODIFY));
    }

    /**
     * Writes a 16-bit integer (little-endian)
     *
     * @param offset byte offset
     * @param value  16-bit value
     */
    public void writeInt16LE(int offset, int value) {
        byte[] oldData = buffer.copyBytes(offset, offset + 2);
        buffer.writeAt(offset, (byte) (value & 0xFF));
        buffer.writeAt(offset + 1, (byte) ((value >> 8) & 0xFF));
        modified = true;
        byte[] newData = new byte[]{(byte) (value & 0xFF), (byte) ((value >> 8) & 0xFF)};
        addUndoEntry(new UndoEntry(offset, oldData, newData, UndoEntry.OperationType.MODIFY));
    }

    /**
     * Writes a 32-bit integer (big-endian)
     *
     * @param offset byte offset
     * @param value  32-bit value
     */
    public void writeInt32BE(int offset, int value) {
        byte[] oldData = buffer.copyBytes(offset, offset + 4);
        buffer.writeAt(offset, (byte) ((value >> 24) & 0xFF));
        buffer.writeAt(offset + 1, (byte) ((value >> 16) & 0xFF));
        buffer.writeAt(offset + 2, (byte) ((value >> 8) & 0xFF));
        buffer.writeAt(offset + 3, (byte) (value & 0xFF));
        modified = true;
        byte[] newData = new byte[]{
            (byte) ((value >> 24) & 0xFF),
            (byte) ((value >> 16) & 0xFF),
            (byte) ((value >> 8) & 0xFF),
            (byte) (value & 0xFF)
        };
        addUndoEntry(new UndoEntry(offset, oldData, newData, UndoEntry.OperationType.MODIFY));
    }

    /**
     * Writes a 32-bit integer (little-endian)
     *
     * @param offset byte offset
     * @param value  32-bit value
     */
    public void writeInt32LE(int offset, int value) {
        byte[] oldData = buffer.copyBytes(offset, offset + 4);
        buffer.writeAt(offset, (byte) (value & 0xFF));
        buffer.writeAt(offset + 1, (byte) ((value >> 8) & 0xFF));
        buffer.writeAt(offset + 2, (byte) ((value >> 16) & 0xFF));
        buffer.writeAt(offset + 3, (byte) ((value >> 24) & 0xFF));
        modified = true;
        byte[] newData = new byte[]{
            (byte) (value & 0xFF),
            (byte) ((value >> 8) & 0xFF),
            (byte) ((value >> 16) & 0xFF),
            (byte) ((value >> 24) & 0xFF)
        };
        addUndoEntry(new UndoEntry(offset, oldData, newData, UndoEntry.OperationType.MODIFY));
    }

    @Override
    public String toString() {
        return String.format("HexEditor[size=%d, cursor=%d, modified=%s, file=%s]",
                buffer.size(), cursor, modified, currentFilePath);
    }
}
