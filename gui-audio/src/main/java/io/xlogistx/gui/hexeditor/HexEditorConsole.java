package io.xlogistx.gui.hexeditor;

import java.io.*;
import java.util.List;
import java.util.Scanner;

/**
 * Interactive console-based UI for the HexEditor
 */
public class HexEditorConsole {
    
    private final HexEditor editor;
    private final Scanner scanner;
    private boolean running;
    private int viewOffset;
    private final int viewSize;
    
    public HexEditorConsole() {
        this.editor = new HexEditor();
        this.scanner = new Scanner(System.in);
        this.running = true;
        this.viewOffset = 0;
        this.viewSize = 256; // Show 256 bytes at a time (16 lines of 16 bytes)
    }
    
    public void run() {
        printWelcome();
        
        while (running) {
            printPrompt();
            String input = scanner.nextLine().trim();
            
            if (input.isEmpty()) {
                continue;
            }
            
            try {
                processCommand(input);
            } catch (Exception e) {
                System.out.println("Error: " + e.getMessage());
            }
        }
        
        System.out.println("Goodbye!");
    }
    
    private void printWelcome() {
        System.out.println("╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║           HexEditor - Using UByteArrayOutputStream           ║");
        System.out.println("║                   Type 'help' for commands                   ║");
        System.out.println("╚══════════════════════════════════════════════════════════════╝");
        System.out.println();
    }
    
    private void printPrompt() {
        String filename = editor.getCurrentFilePath();
        String modFlag = editor.isModified() ? "*" : "";
        if (filename != null) {
            filename = new File(filename).getName();
        } else {
            filename = "(new)";
        }
        System.out.printf("[%s%s @ 0x%08X] > ", filename, modFlag, editor.getCursor());
    }
    
    private void processCommand(String input) throws IOException {
        String[] parts = input.split("\\s+", 2);
        String cmd = parts[0].toLowerCase();
        String args = parts.length > 1 ? parts[1] : "";
        
        switch (cmd) {
            case "help":
            case "?":
                printHelp();
                break;
                
            case "open":
            case "load":
                cmdOpen(args);
                break;
                
            case "save":
                cmdSave(args);
                break;
                
            case "new":
                cmdNew();
                break;
                
            case "view":
            case "v":
                cmdView(args);
                break;
                
            case "dump":
            case "d":
                cmdDump(args);
                break;
                
            case "goto":
            case "g":
                cmdGoto(args);
                break;
                
            case "next":
            case "n":
                cmdNext();
                break;
                
            case "prev":
            case "p":
                cmdPrev();
                break;
                
            case "set":
            case "s":
                cmdSet(args);
                break;
                
            case "insert":
            case "i":
                cmdInsert(args);
                break;
                
            case "delete":
            case "del":
                cmdDelete(args);
                break;
                
            case "fill":
                cmdFill(args);
                break;
                
            case "find":
            case "f":
                cmdFind(args);
                break;
                
            case "findtext":
            case "ft":
                cmdFindText(args);
                break;
                
            case "findall":
                cmdFindAll(args);
                break;
                
            case "replace":
                cmdReplace(args);
                break;
                
            case "replaceall":
                cmdReplaceAll(args);
                break;
                
            case "undo":
            case "u":
                cmdUndo();
                break;
                
            case "redo":
            case "r":
                cmdRedo();
                break;
                
            case "stats":
                cmdStats();
                break;
                
            case "read":
                cmdRead(args);
                break;
                
            case "write":
                cmdWrite(args);
                break;
                
            case "ascii":
                cmdAscii(args);
                break;
                
            case "clear":
                cmdClear();
                break;
                
            case "quit":
            case "exit":
            case "q":
                cmdQuit();
                break;
                
            default:
                System.out.println("Unknown command: " + cmd + ". Type 'help' for available commands.");
        }
    }
    
    private void printHelp() {
        System.out.println("═══════════════════════════════════════════════════════════════");
        System.out.println("                        COMMANDS");
        System.out.println("═══════════════════════════════════════════════════════════════");
        System.out.println("FILE OPERATIONS:");
        System.out.println("  open <file>         Load a file");
        System.out.println("  save [file]         Save to file (current or new)");
        System.out.println("  new                 Create new empty buffer");
        System.out.println();
        System.out.println("NAVIGATION:");
        System.out.println("  view [offset] [len] View hex dump (default: current view)");
        System.out.println("  dump [offset] [len] Same as view");
        System.out.println("  goto <offset>       Go to offset (hex with 0x prefix, or decimal)");
        System.out.println("  next (n)            Next page");
        System.out.println("  prev (p)            Previous page");
        System.out.println();
        System.out.println("EDITING:");
        System.out.println("  set <offset> <hex>  Set bytes at offset (e.g., set 0x10 FF 00 AB)");
        System.out.println("  insert <off> <hex>  Insert bytes at offset");
        System.out.println("  delete <off> <len>  Delete bytes");
        System.out.println("  fill <off> <len> <val> Fill range with byte value");
        System.out.println("  ascii <off> <text>  Write ASCII text at offset");
        System.out.println("  clear               Clear the buffer");
        System.out.println();
        System.out.println("SEARCH:");
        System.out.println("  find <hex>          Find hex pattern (e.g., find FF 00)");
        System.out.println("  findtext <text>     Find text string");
        System.out.println("  findall <hex>       Find all occurrences");
        System.out.println("  replace <s> <r>     Replace first occurrence (hex)");
        System.out.println("  replaceall <s> <r>  Replace all occurrences");
        System.out.println();
        System.out.println("DATA INSPECTION:");
        System.out.println("  read <type> <off>   Read value (int8/16/32/64 + le/be)");
        System.out.println("  write <type> <off> <val>  Write value");
        System.out.println("  stats               Show buffer statistics");
        System.out.println();
        System.out.println("UNDO/REDO:");
        System.out.println("  undo (u)            Undo last change");
        System.out.println("  redo (r)            Redo last undone change");
        System.out.println();
        System.out.println("OTHER:");
        System.out.println("  help (?)            Show this help");
        System.out.println("  quit (q)            Exit the editor");
        System.out.println("═══════════════════════════════════════════════════════════════");
    }
    
    private void cmdOpen(String args) throws IOException {
        if (args.isEmpty()) {
            System.out.println("Usage: open <filename>");
            return;
        }
        
        if (editor.isModified()) {
            System.out.print("Buffer modified. Discard changes? (y/n): ");
            String response = scanner.nextLine().trim().toLowerCase();
            if (!response.equals("y") && !response.equals("yes")) {
                System.out.println("Cancelled.");
                return;
            }
        }
        
        editor.loadFile(args);
        viewOffset = 0;
        System.out.printf("Loaded %d bytes from %s%n", editor.size(), args);
    }
    
    private void cmdSave(String args) throws IOException {
        if (args.isEmpty() && editor.getCurrentFilePath() == null) {
            System.out.println("Usage: save <filename>");
            return;
        }
        
        if (args.isEmpty()) {
            editor.save();
            System.out.printf("Saved %d bytes to %s%n", editor.size(), editor.getCurrentFilePath());
        } else {
            editor.saveAs(args);
            System.out.printf("Saved %d bytes to %s%n", editor.size(), args);
        }
    }
    
    private void cmdNew() {
        if (editor.isModified()) {
            System.out.print("Buffer modified. Discard changes? (y/n): ");
            String response = scanner.nextLine().trim().toLowerCase();
            if (!response.equals("y") && !response.equals("yes")) {
                System.out.println("Cancelled.");
                return;
            }
        }
        
        editor.clear();
        viewOffset = 0;
        System.out.println("Created new empty buffer.");
    }
    
    private void cmdView(String args) {
        if (editor.size() == 0) {
            System.out.println("Buffer is empty.");
            return;
        }
        
        int offset = viewOffset;
        int length = viewSize;
        
        String[] parts = args.split("\\s+");
        if (parts.length >= 1 && !parts[0].isEmpty()) {
            offset = parseOffset(parts[0]);
        }
        if (parts.length >= 2) {
            length = parseOffset(parts[1]);
        }
        
        viewOffset = offset;
        System.out.println(editor.toHexDump(offset, length));
    }
    
    private void cmdDump(String args) {
        cmdView(args);
    }
    
    private void cmdGoto(String args) {
        if (args.isEmpty()) {
            System.out.println("Usage: goto <offset>");
            return;
        }
        
        int offset = parseOffset(args);
        editor.setCursor(offset);
        viewOffset = (offset / 16) * 16; // Align to 16-byte boundary
        System.out.printf("Cursor at 0x%08X%n", editor.getCursor());
        
        // Show surrounding context
        if (editor.size() > 0) {
            int start = Math.max(0, viewOffset);
            int len = Math.min(viewSize, editor.size() - start);
            System.out.println(editor.toHexDump(start, len));
        }
    }
    
    private void cmdNext() {
        viewOffset += viewSize;
        if (viewOffset >= editor.size()) {
            viewOffset = Math.max(0, editor.size() - viewSize);
        }
        cmdView("");
    }
    
    private void cmdPrev() {
        viewOffset -= viewSize;
        if (viewOffset < 0) {
            viewOffset = 0;
        }
        cmdView("");
    }
    
    private void cmdSet(String args) {
        String[] parts = args.split("\\s+", 2);
        if (parts.length < 2) {
            System.out.println("Usage: set <offset> <hex bytes>");
            return;
        }
        
        int offset = parseOffset(parts[0]);
        byte[] data = HexEditor.parseHexString(parts[1]);
        
        // Extend buffer if necessary
        while (offset + data.length > editor.size()) {
            editor.appendBytes(new byte[]{0});
        }
        
        editor.setBytes(offset, data);
        System.out.printf("Set %d bytes at 0x%08X%n", data.length, offset);
    }
    
    private void cmdInsert(String args) {
        String[] parts = args.split("\\s+", 2);
        if (parts.length < 2) {
            System.out.println("Usage: insert <offset> <hex bytes>");
            return;
        }
        
        int offset = parseOffset(parts[0]);
        byte[] data = HexEditor.parseHexString(parts[1]);
        
        editor.insertBytes(offset, data);
        System.out.printf("Inserted %d bytes at 0x%08X%n", data.length, offset);
    }
    
    private void cmdDelete(String args) {
        String[] parts = args.split("\\s+");
        if (parts.length < 2) {
            System.out.println("Usage: delete <offset> <length>");
            return;
        }
        
        int offset = parseOffset(parts[0]);
        int length = parseOffset(parts[1]);
        
        editor.deleteBytes(offset, length);
        System.out.printf("Deleted %d bytes at 0x%08X%n", length, offset);
    }
    
    private void cmdFill(String args) {
        String[] parts = args.split("\\s+");
        if (parts.length < 3) {
            System.out.println("Usage: fill <offset> <length> <value>");
            return;
        }
        
        int offset = parseOffset(parts[0]);
        int length = parseOffset(parts[1]);
        int value = parseOffset(parts[2]);
        
        editor.fill(offset, length, value);
        System.out.printf("Filled %d bytes at 0x%08X with 0x%02X%n", length, offset, value);
    }
    
    private void cmdFind(String args) {
        if (args.isEmpty()) {
            System.out.println("Usage: find <hex pattern>");
            return;
        }
        
        int result = editor.findHex(args, editor.getCursor() + 1);
        if (result == -1) {
            // Wrap around
            result = editor.findHex(args, 0);
        }
        
        if (result == -1) {
            System.out.println("Pattern not found.");
        } else {
            editor.setCursor(result);
            viewOffset = (result / 16) * 16;
            System.out.printf("Found at 0x%08X%n", result);
            cmdView("");
        }
    }
    
    private void cmdFindText(String args) {
        if (args.isEmpty()) {
            System.out.println("Usage: findtext <text>");
            return;
        }
        
        int result = editor.findText(args, editor.getCursor() + 1);
        if (result == -1) {
            result = editor.findText(args, 0);
        }
        
        if (result == -1) {
            System.out.println("Text not found.");
        } else {
            editor.setCursor(result);
            viewOffset = (result / 16) * 16;
            System.out.printf("Found at 0x%08X%n", result);
            cmdView("");
        }
    }
    
    private void cmdFindAll(String args) {
        if (args.isEmpty()) {
            System.out.println("Usage: findall <hex pattern>");
            return;
        }
        
        byte[] pattern = HexEditor.parseHexString(args);
        List<Integer> results = editor.findAll(pattern);
        
        if (results.isEmpty()) {
            System.out.println("Pattern not found.");
        } else {
            System.out.printf("Found %d occurrences:%n", results.size());
            for (int i = 0; i < Math.min(results.size(), 20); i++) {
                System.out.printf("  0x%08X%n", results.get(i));
            }
            if (results.size() > 20) {
                System.out.printf("  ... and %d more%n", results.size() - 20);
            }
        }
    }
    
    private void cmdReplace(String args) {
        String[] parts = args.split("\\s+", 2);
        if (parts.length < 2) {
            System.out.println("Usage: replace <search hex> <replacement hex>");
            System.out.println("Example: replace FF00 AABB");
            return;
        }
        
        byte[] search = HexEditor.parseHexString(parts[0]);
        byte[] replacement = HexEditor.parseHexString(parts[1]);
        
        if (editor.replace(search, replacement, 0)) {
            System.out.println("Replaced first occurrence.");
        } else {
            System.out.println("Pattern not found.");
        }
    }
    
    private void cmdReplaceAll(String args) {
        String[] parts = args.split("\\s+", 2);
        if (parts.length < 2) {
            System.out.println("Usage: replaceall <search hex> <replacement hex>");
            return;
        }
        
        byte[] search = HexEditor.parseHexString(parts[0]);
        byte[] replacement = HexEditor.parseHexString(parts[1]);
        
        int count = editor.replaceAll(search, replacement);
        System.out.printf("Replaced %d occurrences.%n", count);
    }
    
    private void cmdUndo() {
        if (editor.undo()) {
            System.out.println("Undone.");
        } else {
            System.out.println("Nothing to undo.");
        }
    }
    
    private void cmdRedo() {
        if (editor.redo()) {
            System.out.println("Redone.");
        } else {
            System.out.println("Nothing to redo.");
        }
    }
    
    private void cmdStats() {
        System.out.println(editor.getStatistics());
    }
    
    private void cmdRead(String args) {
        String[] parts = args.split("\\s+");
        if (parts.length < 2) {
            System.out.println("Usage: read <type> <offset>");
            System.out.println("Types: int8, int16le, int16be, int32le, int32be, int64le, int64be");
            return;
        }
        
        String type = parts[0].toLowerCase();
        int offset = parseOffset(parts[1]);
        
        switch (type) {
            case "int8":
            case "byte":
                int b = editor.getByte(offset);
                System.out.printf("int8 at 0x%X: %d (0x%02X)%n", offset, (byte)b, b);
                break;
            case "int16le":
            case "short16le":
                int s16le = editor.readInt16LE(offset);
                System.out.printf("int16le at 0x%X: %d (0x%04X)%n", offset, (short)s16le, s16le);
                break;
            case "int16be":
            case "short16be":
                int s16be = editor.readInt16BE(offset);
                System.out.printf("int16be at 0x%X: %d (0x%04X)%n", offset, (short)s16be, s16be);
                break;
            case "int32le":
                int i32le = editor.readInt32LE(offset);
                System.out.printf("int32le at 0x%X: %d (0x%08X)%n", offset, i32le, i32le);
                break;
            case "int32be":
                int i32be = editor.readInt32BE(offset);
                System.out.printf("int32be at 0x%X: %d (0x%08X)%n", offset, i32be, i32be);
                break;
            case "int64le":
                long l64le = editor.readInt64LE(offset);
                System.out.printf("int64le at 0x%X: %d (0x%016X)%n", offset, l64le, l64le);
                break;
            case "int64be":
                long l64be = editor.readInt64BE(offset);
                System.out.printf("int64be at 0x%X: %d (0x%016X)%n", offset, l64be, l64be);
                break;
            default:
                System.out.println("Unknown type: " + type);
        }
    }
    
    private void cmdWrite(String args) {
        String[] parts = args.split("\\s+");
        if (parts.length < 3) {
            System.out.println("Usage: write <type> <offset> <value>");
            System.out.println("Types: int16le, int16be, int32le, int32be");
            return;
        }
        
        String type = parts[0].toLowerCase();
        int offset = parseOffset(parts[1]);
        long value = Long.parseLong(parts[2]);
        
        switch (type) {
            case "int16le":
                editor.writeInt16LE(offset, (int) value);
                break;
            case "int16be":
                editor.writeInt16BE(offset, (int) value);
                break;
            case "int32le":
                editor.writeInt32LE(offset, (int) value);
                break;
            case "int32be":
                editor.writeInt32BE(offset, (int) value);
                break;
            default:
                System.out.println("Unknown type: " + type);
                return;
        }
        System.out.printf("Written %s value %d at 0x%X%n", type, value, offset);
    }
    
    private void cmdAscii(String args) {
        String[] parts = args.split("\\s+", 2);
        if (parts.length < 2) {
            System.out.println("Usage: ascii <offset> <text>");
            return;
        }
        
        int offset = parseOffset(parts[0]);
        byte[] data = parts[1].getBytes();
        
        // Extend buffer if necessary
        while (offset + data.length > editor.size()) {
            editor.appendBytes(new byte[]{0});
        }
        
        editor.setBytes(offset, data);
        System.out.printf("Written %d ASCII bytes at 0x%08X%n", data.length, offset);
    }
    
    private void cmdClear() {
        System.out.print("Clear buffer? (y/n): ");
        String response = scanner.nextLine().trim().toLowerCase();
        if (response.equals("y") || response.equals("yes")) {
            editor.clear();
            viewOffset = 0;
            System.out.println("Buffer cleared.");
        } else {
            System.out.println("Cancelled.");
        }
    }
    
    private void cmdQuit() {
        if (editor.isModified()) {
            System.out.print("Buffer modified. Save before quitting? (y/n/c): ");
            String response = scanner.nextLine().trim().toLowerCase();
            if (response.equals("c") || response.equals("cancel")) {
                return;
            }
            if (response.equals("y") || response.equals("yes")) {
                try {
                    if (editor.getCurrentFilePath() == null) {
                        System.out.print("Filename: ");
                        String filename = scanner.nextLine().trim();
                        editor.saveAs(filename);
                    } else {
                        editor.save();
                    }
                    System.out.println("Saved.");
                } catch (IOException e) {
                    System.out.println("Error saving: " + e.getMessage());
                    return;
                }
            }
        }
        running = false;
    }
    
    private int parseOffset(String s) {
        s = s.trim().toLowerCase();
        if (s.startsWith("0x")) {
            return Integer.parseInt(s.substring(2), 16);
        }
        return Integer.parseInt(s);
    }
    
    public static void main(String[] args) {
        HexEditorConsole console = new HexEditorConsole();
        
        // If a file is provided as argument, load it
        if (args.length > 0) {
            try {
                console.editor.loadFile(args[0]);
                System.out.printf("Loaded %d bytes from %s%n", console.editor.size(), args[0]);
            } catch (IOException e) {
                System.out.println("Error loading file: " + e.getMessage());
            }
        }
        
        console.run();
    }
}
