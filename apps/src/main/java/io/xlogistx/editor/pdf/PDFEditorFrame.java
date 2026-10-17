package io.xlogistx.editor.pdf;

import io.xlogistx.common.util.NVColor;
import io.xlogistx.gui.IconUtil;
import org.zoxweb.shared.app.AppVersionDAO;

import javax.swing.*;
import java.awt.*;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

/**
 * Standalone window around {@link PDFEditorPane}: title tracking, the pane's
 * menu bar with an added Exit item, and close handling. The JVM is exited only
 * when {@link #setExitOnClose(boolean)} is enabled (done by {@link PDFMain#main}), so a
 * host application can open this frame, or embed the pane, without its process
 * being terminated.
 */
public class PDFEditorFrame extends JFrame {

    private static final String TITLE = "PDF Editor";

    private final PDFEditorPane editorPane;
    private boolean exitOnClose;

    /** Creates a frame around a new, empty editor pane. */
    public PDFEditorFrame() {
        this(new PDFEditorPane());
    }

    /**
     * @param editorPane the pane to host
     */
    public PDFEditorFrame(PDFEditorPane editorPane) {
        super(TITLE);
        this.editorPane = editorPane;
        setLayout(new BorderLayout());
        add(editorPane, BorderLayout.CENTER);

        JMenuBar menuBar = editorPane.createMenuBar();
        JMenu fileMenu = menuBar.getMenu(0);
        fileMenu.addSeparator();
        JMenuItem exit = new JMenuItem("Exit", KeyEvent.VK_X);
        exit.addActionListener(e -> handleClose());
        fileMenu.add(exit);
        setJMenuBar(menuBar);

        editorPane.addChangeListener(e -> updateTitle());
        setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                handleClose();
            }
        });
        setIconImages(IconUtil.windowIcons(IconUtil.PDFIcon::new, Color.WHITE, NVColor.BOOTSTRAP_RED.getValue()));
        setSize(1000, 760);
        setLocationRelativeTo(null);
        updateTitle();
    }

    /** @return the application version ({@link PDFMain#VERSION}) */
    public AppVersionDAO getVersion() {
        return PDFMain.VERSION;
    }

    /** @return the embedded editor pane */
    public PDFEditorPane getEditorPane() {
        return editorPane;
    }

    /**
     * Controls whether closing the window terminates the JVM. Default false.
     *
     * @param exitOnClose true to {@code System.exit} on close
     */
    public void setExitOnClose(boolean exitOnClose) {
        this.exitOnClose = exitOnClose;
    }

    private void updateTitle() {
        String doc = editorPane.getDocumentTitle();
        setTitle(doc.isEmpty() ? TITLE : TITLE + " - " + doc);
    }

    private void handleClose() {
        if (!editorPane.confirmDiscard())
            return;
        editorPane.getViewer().close();
        dispose();
        if (exitOnClose)
            System.exit(0);
    }


}
