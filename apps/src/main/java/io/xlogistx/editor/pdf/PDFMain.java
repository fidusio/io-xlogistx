package io.xlogistx.editor.pdf;

import org.zoxweb.shared.app.AppVersion;

import javax.swing.*;
import java.io.File;

/** The PDF editor application: its version and the standalone entry point around {@link PDFEditorFrame}. */
public class PDFMain {

    /** The application name and version. */
    public static final AppVersion VERSION = new AppVersion("PDFEditor::0.1.0");

    /**
     * Standalone entry point: {@code Main [file.pdf | file.md | image.png ...]};
     * every file given opens in its own tab.
     *
     * @param args optional files to open
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
            frame.applySettings(EditorSettings.user());
            frame.getEditorPane().setEditable(true);
            frame.getEditorPane().setActiveTool(PDFEditorPane.EditTool.SELECT);
            for (String arg : args)
                frame.open(new File(arg));
            frame.getTabs().selectTab(frame.getTabs().getPanes().get(0));
            frame.setVisible(true);
        });
    }
}
