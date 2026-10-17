package io.xlogistx.editor.pdf;

import org.zoxweb.shared.app.AppVersionDAO;

import javax.swing.*;
import java.io.File;

/** The PDF editor application: its version and the standalone entry point around {@link PDFEditorFrame}. */
public class PDFMain {

    /** The application name and version. */
    public static final AppVersionDAO VERSION = new AppVersionDAO("PDFEditor::0.1.0");

    /**
     * Standalone entry point: {@code Main [file.pdf | file.md | image.png]}.
     *
     * @param args optional file to open
     */
    public static void main(String[] args) {
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception e) {
            // default look and feel
        }
        SwingUtilities.invokeLater(() -> {
            PDFEditorFrame frame = new PDFEditorFrame();
            frame.setExitOnClose(true);
            frame.getEditorPane().setEditable(true);
            if (args.length > 0)
                frame.getEditorPane().open(new File(args[0]));
            frame.getEditorPane().setActiveTool(PDFEditorPane.EditTool.SELECT);
            frame.setVisible(true);
        });
    }
}
