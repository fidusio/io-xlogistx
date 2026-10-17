package io.xlogistx.editor.hex;

import javax.swing.*;
import java.io.File;
import java.io.IOException;

public class HexMain {
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
