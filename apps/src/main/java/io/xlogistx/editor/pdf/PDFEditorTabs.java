package io.xlogistx.editor.pdf;

import io.xlogistx.gui.IconUtil;
import org.zoxweb.shared.util.SUS;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.event.MenuEvent;
import javax.swing.event.MenuListener;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * Several documents side by side: a tabbed pane holding one {@link PDFEditorPane}
 * per document, each with its own toolbar rows, undo history, selection and
 * status line. There is always at least one tab; a tab without a document is
 * titled {@value #EMPTY_TITLE}.
 *
 * <p>Files the user opens while the active tab already shows a document go to a
 * new tab, through the viewer's {@linkplain io.xlogistx.gui.PDFViewerPanel#setOpenHandler
 * open handler}: the File ▸ Open entry, the toolbar Open button, Open Recent and the
 * Open choice of a drop all behave that way; an empty active tab is filled in
 * place. The API calls on a pane ({@code open}, {@code setPDF}) never move to
 * another tab.
 *
 * <p>The clipboard is shared: an annotation copied in one tab can be pasted in any
 * other (an image stamp is re-embedded in the target document by
 * {@link AnnotationClipboard.Clip#create}).
 *
 * <p>{@link #getMenuBar()} is the menu bar for the active tab: the pane's own
 * menus plus a Tabs menu before Help (New tab Ctrl+T, Close tab Ctrl+W, Close
 * other tabs, Next / Previous tab Ctrl+Tab / Ctrl+Shift+Tab, then one entry per
 * open tab). Bars are built once per pane and cached, so a host swaps
 * {@code setJMenuBar(tabs.getMenuBar())} on every change event. Alt+1 .. Alt+9 jump
 * to a tab, a middle click on a tab closes it, and the close button on each tab
 * does too. Change listeners hear every pane change and every tab change.
 */
public class PDFEditorTabs extends JPanel {

    /** The title of a tab that shows no document. */
    public static final String EMPTY_TITLE = "New tab";
    /** Longer file names are shortened on the tab (the tooltip has the full path). */
    static final int MAX_TAB_TITLE = 32;

    private final JTabbedPane tabs = new JTabbedPane(JTabbedPane.TOP, JTabbedPane.SCROLL_TAB_LAYOUT);
    private final List<ChangeListener> listeners = new CopyOnWriteArrayList<>();
    private final Map<PDFEditorPane, ChangeListener> paneListeners = new HashMap<>();
    private final Map<PDFEditorPane, JMenuBar> menuBars = new HashMap<>();
    private Consumer<JMenuBar> menuBarCustomizer;
    private Supplier<PDFEditorPane> paneFactory = PDFEditorPane::new;
    private EditorSettings settings;
    private PDFEditorPane lastActive;

    /** Creates the component with one empty tab. */
    public PDFEditorTabs() {
        this(new PDFEditorPane());
    }

    /**
     * Creates the component with the given pane as its first tab.
     *
     * @param first the first pane, never null
     */
    public PDFEditorTabs(PDFEditorPane first) {
        SUS.checkIfNull("pane null", first);
        setLayout(new BorderLayout());
        tabs.setFocusable(false);
        add(tabs, BorderLayout.CENTER);
        tabs.addChangeListener(e -> activeChanged());
        tabs.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (SwingUtilities.isMiddleMouseButton(e)) {
                    int i = tabs.indexAtLocation(e.getX(), e.getY());
                    if (i >= 0)
                        closeTab(paneAt(i));
                }
            }
        });
        // Ctrl+Tab / Ctrl+Shift+Tab switch tabs here, so they must not traverse the focus
        Set<AWTKeyStroke> forward = new HashSet<>(Collections.singletonList(AWTKeyStroke.getAWTKeyStroke(KeyEvent.VK_TAB, 0)));
        Set<AWTKeyStroke> backward = new HashSet<>(Collections.singletonList(AWTKeyStroke.getAWTKeyStroke(KeyEvent.VK_TAB, InputEvent.SHIFT_DOWN_MASK)));
        setFocusTraversalKeys(KeyboardFocusManager.FORWARD_TRAVERSAL_KEYS, forward);
        setFocusTraversalKeys(KeyboardFocusManager.BACKWARD_TRAVERSAL_KEYS, backward);
        InputMap im = getInputMap(WHEN_IN_FOCUSED_WINDOW);
        ActionMap am = getActionMap();
        bind(im, am, KeyStroke.getKeyStroke(KeyEvent.VK_TAB, InputEvent.CTRL_DOWN_MASK), "nextTab", e -> nextTab());
        bind(im, am, KeyStroke.getKeyStroke(KeyEvent.VK_TAB, InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK), "previousTab", e -> previousTab());
        for (int n = 1; n <= 9; n++) {
            int index = n - 1;
            bind(im, am, KeyStroke.getKeyStroke(KeyEvent.VK_0 + n, InputEvent.ALT_DOWN_MASK), "tab" + n, e -> {
                if (index < tabs.getTabCount())
                    tabs.setSelectedIndex(index);
            });
        }
        addTab(first);
        lastActive = first;
    }

    private static void bind(InputMap im, ActionMap am, KeyStroke key, String name, ActionListener action) {
        im.put(key, name);
        am.put(name, new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                action.actionPerformed(e);
            }
        });
    }

    // ------------------------------------------------------------------ tabs

    /** @return the tabbed pane itself (tab order = {@link #getPanes()} order) */
    public JTabbedPane getTabbedPane() {
        return tabs;
    }

    /** @return the pane of the selected tab, never null */
    public PDFEditorPane getActivePane() {
        int i = tabs.getSelectedIndex();
        return paneAt(i < 0 ? 0 : i);
    }

    /** @return every pane, in tab order */
    public List<PDFEditorPane> getPanes() {
        List<PDFEditorPane> r = new ArrayList<>(tabs.getTabCount());
        for (int i = 0; i < tabs.getTabCount(); i++)
            r.add(paneAt(i));
        return r;
    }

    /** @return the number of tabs, at least one */
    public int getTabCount() {
        return tabs.getTabCount();
    }

    /** @return the tab index of the pane, -1 when it is not here */
    public int indexOf(PDFEditorPane pane) {
        return tabs.indexOfComponent(pane);
    }

    private PDFEditorPane paneAt(int index) {
        return (PDFEditorPane) tabs.getComponentAt(index);
    }

    /**
     * Adds an empty tab after the current ones and selects it. The new pane takes
     * the settings, the editing state of the active pane and, when editing, the
     * Select tool, like a fresh session.
     *
     * @return the new pane
     */
    public PDFEditorPane newTab() {
        return newTab(tabs.getTabCount() > 0 && getActivePane().isEditable());
    }

    private PDFEditorPane newTab(boolean editable) {
        PDFEditorPane pane = paneFactory.get();
        addTab(pane);
        if (editable) {
            pane.setEditable(true);
            pane.setActiveTool(PDFEditorPane.EditTool.SELECT);
        }
        tabs.setSelectedComponent(pane);
        return pane;
    }

    /**
     * Shows a file in its own tab: the active tab when it is empty, else a new
     * one. Loading runs off the EDT as {@link PDFEditorPane#open} does.
     *
     * @param file a PDF, Markdown file or image, never null
     * @return the pane that shows it
     */
    public PDFEditorPane openInNewTab(File file) {
        SUS.checkIfNull("file null", file);
        return openInNewTab(Collections.singletonList(file));
    }

    /**
     * Shows files in their own tab (several files are joined into one new document,
     * as the viewer's {@code openFiles} does): the active tab when it is empty,
     * else a new one.
     *
     * @param files the files, never null or empty
     * @return the pane that shows them
     */
    public PDFEditorPane openInNewTab(List<File> files) {
        SUS.checkIfNull("files null", files);
        if (files.isEmpty())
            throw new IllegalArgumentException("no files");
        PDFEditorPane target = getActivePane();
        if (target.getViewer().getDocument() != null)
            target = newTab();
        else
            tabs.setSelectedComponent(target);
        target.getViewer().openFiles(files);
        return target;
    }

    /**
     * Selects the pane's tab.
     *
     * @param pane a pane of this component
     * @return this component
     */
    public PDFEditorTabs selectTab(PDFEditorPane pane) {
        int i = indexOf(pane);
        if (i >= 0)
            tabs.setSelectedIndex(i);
        return this;
    }

    /** Selects the tab after the current one, wrapping round. @return this component */
    public PDFEditorTabs nextTab() {
        int n = tabs.getTabCount();
        if (n > 1)
            tabs.setSelectedIndex((tabs.getSelectedIndex() + 1) % n);
        return this;
    }

    /** Selects the tab before the current one, wrapping round. @return this component */
    public PDFEditorTabs previousTab() {
        int n = tabs.getTabCount();
        if (n > 1)
            tabs.setSelectedIndex((tabs.getSelectedIndex() + n - 1) % n);
        return this;
    }

    /**
     * Closes a tab after asking about unsaved changes (the tab is shown first, so
     * the question is about what is on screen) and closes its document. Closing
     * the last tab leaves one empty tab.
     *
     * @param pane the pane to close
     * @return true when the tab is gone, false when the user kept it or it is not here
     */
    public boolean closeTab(PDFEditorPane pane) {
        int i = indexOf(pane);
        if (i < 0)
            return false;
        if (pane.isModified()) {
            tabs.setSelectedIndex(i);
            if (!pane.confirmDiscard())
                return false;
        }
        boolean editable = pane.isEditable();
        detach(pane);
        tabs.remove(i);
        pane.getViewer().close();
        if (tabs.getTabCount() == 0)
            newTab(editable);
        return true;
    }

    /** Closes the active tab, see {@link #closeTab}. @return true when it is gone */
    public boolean closeActiveTab() {
        return closeTab(getActivePane());
    }

    /**
     * Closes every tab but the active one, asking about unsaved changes tab by
     * tab; a refused tab stays and the others are still closed.
     *
     * @return true when every other tab is gone
     */
    public boolean closeOtherTabs() {
        PDFEditorPane keep = getActivePane();
        boolean all = true;
        for (PDFEditorPane p : getPanes())
            if (p != keep && !closeTab(p))
                all = false;
        selectTab(keep);
        return all;
    }

    /**
     * Asks, tab by tab, whether unsaved changes may be discarded; what a host does
     * before closing its window. Stops at the first refusal, leaving that tab shown.
     *
     * @return true when nothing is modified or every change may go
     */
    public boolean confirmDiscardAll() {
        for (PDFEditorPane p : getPanes()) {
            if (!p.isModified())
                continue;
            selectTab(p);
            if (!p.confirmDiscard())
                return false;
        }
        return true;
    }

    /** Closes every pane's document without asking; the tabs stay, empty. A host calls this when its window goes. */
    public void closeAll() {
        for (PDFEditorPane p : getPanes())
            p.getViewer().close();
    }

    /**
     * @param factory makes the pane of a new tab; default {@code PDFEditorPane::new}
     * @return this component
     */
    public PDFEditorTabs setPaneFactory(Supplier<PDFEditorPane> factory) {
        SUS.checkIfNull("factory null", factory);
        paneFactory = factory;
        return this;
    }

    private void addTab(PDFEditorPane pane) {
        if (settings != null)
            pane.setSettings(settings);
        pane.getViewer().setOpenHandler(files -> {
            openInNewTab(files);
            return true;
        });
        ChangeListener l = e -> {
            updateTab(pane);
            changed();
        };
        paneListeners.put(pane, l);
        pane.addChangeListener(l);
        tabs.addTab(EMPTY_TITLE, pane);
        tabs.setTabComponentAt(tabs.indexOfComponent(pane), new TabHeader(pane));
        updateTab(pane);
    }

    private void detach(PDFEditorPane pane) {
        ChangeListener l = paneListeners.remove(pane);
        if (l != null)
            pane.removeChangeListener(l);
        menuBars.remove(pane);
        pane.getViewer().setOpenHandler(null);
    }

    private void updateTab(PDFEditorPane pane) {
        int i = indexOf(pane);
        if (i < 0)
            return;
        String title = tabTitle(pane);
        tabs.setTitleAt(i, title);
        File f = pane.getViewer().getFile();
        tabs.setToolTipTextAt(i, f != null ? f.getAbsolutePath() : null);
        Component header = tabs.getTabComponentAt(i);
        if (header instanceof TabHeader)
            ((TabHeader) header).update(title, f != null ? f.getAbsolutePath() : null);
    }

    /** @return the title shown on the pane's tab: the document title shortened to {@link #MAX_TAB_TITLE}, or {@value #EMPTY_TITLE} */
    public static String tabTitle(PDFEditorPane pane) {
        String title = pane.getDocumentTitle();
        if (title.isEmpty())
            return EMPTY_TITLE;
        if (title.length() <= MAX_TAB_TITLE)
            return title;
        boolean modified = title.endsWith(" *");
        String name = modified ? title.substring(0, title.length() - 2) : title;
        int keep = MAX_TAB_TITLE - 1 - (modified ? 2 : 0);
        int dot = name.lastIndexOf('.');
        String ext = dot > 0 && name.length() - dot <= 5 ? name.substring(dot) : "";
        String head = name.substring(0, Math.max(1, keep - ext.length()));
        return head + "…" + ext + (modified ? " *" : "");
    }

    private void activeChanged() {
        PDFEditorPane active = tabs.getTabCount() == 0 ? null : getActivePane();
        if (active != null && active != lastActive) {
            lastActive = active;
            active.refreshRecentMenu(); // another tab may have opened or saved a file meanwhile
        }
        changed();
    }

    // ------------------------------------------------------------------ settings

    /**
     * Installs the settings on every pane, now and on each new tab.
     *
     * @param settings the settings, null for none
     * @return this component
     */
    public PDFEditorTabs setSettings(EditorSettings settings) {
        this.settings = settings;
        for (PDFEditorPane p : getPanes())
            p.setSettings(settings);
        return this;
    }

    /** @return the settings installed with {@link #setSettings}, null when none */
    public EditorSettings getSettings() {
        return settings;
    }

    /** Writes the active pane's end-of-session state (zoom, thumbnails, text size) to the settings and flushes them. */
    public void saveSettings() {
        getActivePane().saveSettings();
    }

    // ------------------------------------------------------------------ menu bar

    /**
     * @param customizer called once on every menu bar this component builds (a
     *                   host adds its Exit entry, say); null for none
     * @return this component
     */
    public PDFEditorTabs setMenuBarCustomizer(Consumer<JMenuBar> customizer) {
        menuBarCustomizer = customizer;
        return this;
    }

    /**
     * The menu bar for the active tab: the pane's menus with the Tabs menu added
     * before Help, built once per pane. A host sets it on its window whenever a
     * change event arrives (the same bar comes back while the tab stays).
     *
     * @return the active pane's menu bar
     */
    public JMenuBar getMenuBar() {
        PDFEditorPane pane = getActivePane();
        JMenuBar bar = menuBars.get(pane);
        if (bar == null) {
            bar = pane.createMenuBar();
            int at = bar.getMenuCount();
            if (at > 0 && "Help".equals(bar.getMenu(at - 1).getText()))
                at--;
            bar.add(createTabsMenu(), at);
            if (menuBarCustomizer != null)
                menuBarCustomizer.accept(bar);
            menuBars.put(pane, bar);
        }
        return bar;
    }

    /** @return a new Tabs menu driving this component */
    public JMenu createTabsMenu() {
        JMenu menu = new JMenu("Tabs");
        menu.setMnemonic(KeyEvent.VK_T);
        menu.add(item("New tab", KeyEvent.VK_N, KeyStroke.getKeyStroke(KeyEvent.VK_T, InputEvent.CTRL_DOWN_MASK), e -> newTab()));
        JMenuItem close = item("Close tab", KeyEvent.VK_C, KeyStroke.getKeyStroke(KeyEvent.VK_W, InputEvent.CTRL_DOWN_MASK), e -> closeActiveTab());
        JMenuItem closeOthers = item("Close other tabs", KeyEvent.VK_O, null, e -> closeOtherTabs());
        menu.add(close);
        menu.add(closeOthers);
        menu.addSeparator();
        JMenuItem next = item("Next tab", KeyEvent.VK_X, KeyStroke.getKeyStroke(KeyEvent.VK_TAB, InputEvent.CTRL_DOWN_MASK), e -> nextTab());
        JMenuItem previous = item("Previous tab", KeyEvent.VK_P, KeyStroke.getKeyStroke(KeyEvent.VK_TAB, InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK), e -> previousTab());
        menu.add(next);
        menu.add(previous);
        int fixed = menu.getMenuComponentCount();
        menu.addMenuListener(new MenuListener() {
            @Override
            public void menuSelected(MenuEvent e) {
                boolean several = tabs.getTabCount() > 1;
                closeOthers.setEnabled(several);
                next.setEnabled(several);
                previous.setEnabled(several);
                while (menu.getMenuComponentCount() > fixed)
                    menu.remove(menu.getMenuComponentCount() - 1);
                menu.addSeparator();
                PDFEditorPane active = getActivePane();
                int n = 1;
                for (PDFEditorPane p : getPanes()) {
                    JRadioButtonMenuItem mi = new JRadioButtonMenuItem(tabTitle(p), p == active);
                    if (n <= 9) {
                        mi.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_0 + n, InputEvent.ALT_DOWN_MASK));
                        mi.setMnemonic(KeyEvent.VK_0 + n);
                    }
                    File f = p.getViewer().getFile();
                    if (f != null)
                        mi.setToolTipText(f.getAbsolutePath());
                    mi.addActionListener(ev -> selectTab(p));
                    menu.add(mi);
                    n++;
                }
            }

            @Override
            public void menuDeselected(MenuEvent e) {
            }

            @Override
            public void menuCanceled(MenuEvent e) {
            }
        });
        return menu;
    }

    private static JMenuItem item(String text, int mnemonic, KeyStroke accelerator, ActionListener action) {
        JMenuItem mi = new JMenuItem(text, mnemonic);
        if (accelerator != null)
            mi.setAccelerator(accelerator);
        mi.addActionListener(action);
        return mi;
    }

    // ------------------------------------------------------------------ listeners

    /** @param l notified on every change of any pane and on every tab change (selection, open, close); never null */
    public void addChangeListener(ChangeListener l) {
        SUS.checkIfNull("listener null", l);
        listeners.add(l);
    }

    /** @param l the listener to remove */
    public void removeChangeListener(ChangeListener l) {
        listeners.remove(l);
    }

    private void changed() {
        ChangeEvent e = new ChangeEvent(this);
        for (ChangeListener l : listeners)
            l.stateChanged(e);
    }

    // ------------------------------------------------------------------ tab header

    /** The component on a tab: the title and a close button. */
    final class TabHeader extends JPanel {
        private final JLabel label = new JLabel();
        private final JButton close = new JButton(new IconUtil.CancelIcon(10));

        TabHeader(PDFEditorPane pane) {
            super(new FlowLayout(FlowLayout.LEFT, 0, 0));
            setOpaque(false);
            label.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 6));
            close.setToolTipText("Close tab (Ctrl+W)");
            close.setBorderPainted(false);
            close.setContentAreaFilled(false);
            close.setFocusable(false);
            close.setMargin(new Insets(0, 0, 0, 0));
            close.setPreferredSize(new Dimension(14, 14));
            close.setRolloverEnabled(true);
            close.addActionListener(e -> closeTab(pane));
            // clicks on the header select the tab like clicks on a plain tab do
            MouseAdapter forward = new MouseAdapter() {
                @Override
                public void mousePressed(MouseEvent e) {
                    if (SwingUtilities.isLeftMouseButton(e))
                        selectTab(pane);
                    else if (SwingUtilities.isMiddleMouseButton(e))
                        closeTab(pane);
                }
            };
            addMouseListener(forward);
            label.addMouseListener(forward);
            add(label);
            add(close);
        }

        void update(String title, String tooltip) {
            label.setText(title);
            label.setToolTipText(tooltip);
            setToolTipText(tooltip);
        }

        JLabel getLabel() {
            return label;
        }

        JButton getCloseButton() {
            return close;
        }
    }
}
