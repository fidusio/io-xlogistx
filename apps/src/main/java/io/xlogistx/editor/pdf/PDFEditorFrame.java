package io.xlogistx.editor.pdf;

import io.xlogistx.common.util.NVColor;
import io.xlogistx.gui.IconUtil;
import org.zoxweb.shared.app.AppVersion;

import javax.swing.*;
import java.awt.*;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;

/**
 * Standalone window around {@link PDFEditorTabs}: one tab per open document,
 * title tracking, the active tab's menu bar with an added Exit item, and close
 * handling that asks about every tab's unsaved changes. The JVM is exited only
 * when {@link #setExitOnClose(boolean)} is enabled (done by {@link PDFMain#main}), so a
 * host application can open this frame, or embed the pane, without its process
 * being terminated.
 */
public class PDFEditorFrame extends JFrame {

    private static final String TITLE = "PDF Editor";

    private final PDFEditorTabs tabs;
    private boolean exitOnClose;
    private EditorSettings settings;

    /** Creates a frame with one empty tab. */
    public PDFEditorFrame() {
        this(new PDFEditorPane());
    }

    /**
     * @param editorPane the pane of the first tab
     */
    public PDFEditorFrame(PDFEditorPane editorPane) {
        this(new PDFEditorTabs(editorPane));
    }

    /**
     * @param tabs the tabbed documents to host
     */
    public PDFEditorFrame(PDFEditorTabs tabs) {
        super(TITLE);
        this.tabs = tabs;
        setLayout(new BorderLayout());
        add(tabs, BorderLayout.CENTER);

        tabs.setMenuBarCustomizer(menuBar -> {
            JMenu fileMenu = menuBar.getMenu(0);
            fileMenu.addSeparator();
            JMenuItem exit = new JMenuItem("Exit", KeyEvent.VK_X);
            exit.addActionListener(e -> handleClose());
            fileMenu.add(exit);
        });
        setJMenuBar(tabs.getMenuBar());

        tabs.addChangeListener(e -> {
            JMenuBar bar = tabs.getMenuBar();
            if (bar != getJMenuBar()) {
                setJMenuBar(bar);
                revalidate();
                repaint();
            }
            updateTitle();
        });
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
    public AppVersion getVersion() {
        return PDFMain.VERSION;
    }

    /** @return the pane of the active tab */
    public PDFEditorPane getEditorPane() {
        return tabs.getActivePane();
    }

    /** @return the tabbed documents */
    public PDFEditorTabs getTabs() {
        return tabs;
    }

    /**
     * Shows a file in its own tab (the active tab when it is empty).
     *
     * @param file a PDF, Markdown file or image
     * @return the pane showing it
     */
    public PDFEditorPane open(File file) {
        return tabs.openInNewTab(file);
    }

    /**
     * Controls whether closing the window terminates the JVM. Default false.
     *
     * @param exitOnClose true to {@code System.exit} on close
     */
    public void setExitOnClose(boolean exitOnClose) {
        this.exitOnClose = exitOnClose;
    }

    /**
     * Installs the settings on the tabs (recent files, thumbnails, zoom, last
     * directory) and restores the window's bounds when they are still on a
     * screen; closing the window saves everything back.
     *
     * @param settings the settings, null for none
     * @return this frame
     */
    public PDFEditorFrame applySettings(EditorSettings settings) {
        this.settings = settings;
        tabs.setSettings(settings);
        if (settings == null)
            return this;
        Rectangle bounds = settings.getWindowBounds();
        if (bounds != null && onAScreen(bounds))
            setBounds(bounds);
        if (settings.isWindowMaximized())
            setExtendedState(getExtendedState() | MAXIMIZED_BOTH);
        return this;
    }

    /** @return true when a meaningful part of the rectangle lies on some screen (or there is no way to tell) */
    static boolean onAScreen(Rectangle r) {
        try {
            for (GraphicsDevice d : GraphicsEnvironment.getLocalGraphicsEnvironment().getScreenDevices()) {
                Rectangle screen = d.getDefaultConfiguration().getBounds();
                Rectangle common = screen.intersection(r);
                if (!common.isEmpty() && common.width >= 100 && common.height >= 60)
                    return true;
            }
            return false;
        } catch (HeadlessException e) {
            return true;
        }
    }

    private void saveSettings() {
        if (settings == null)
            return;
        boolean maximized = (getExtendedState() & MAXIMIZED_BOTH) != 0;
        settings.setWindowMaximized(maximized);
        if (!maximized)
            settings.setWindowBounds(getBounds());
        tabs.saveSettings();
    }

    private void updateTitle() {
        String doc = tabs.getActivePane().getDocumentTitle();
        setTitle(doc.isEmpty() ? TITLE : TITLE + " - " + doc);
    }

    private void handleClose() {
        if (!tabs.confirmDiscardAll())
            return;
        saveSettings();
        tabs.closeAll();
        dispose();
        if (exitOnClose)
            System.exit(0);
    }


}
