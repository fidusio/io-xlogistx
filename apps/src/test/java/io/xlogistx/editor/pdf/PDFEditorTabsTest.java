package io.xlogistx.editor.pdf;

import io.xlogistx.gui.pdf.PageTransform;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotation;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.swing.JComponent;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;
import javax.swing.event.MenuEvent;
import javax.swing.event.MenuListener;
import java.awt.Component;
import java.awt.Container;
import java.awt.Point;
import java.awt.datatransfer.StringSelection;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.awt.geom.Rectangle2D;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BooleanSupplier;
import java.util.prefs.Preferences;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Headless tests of {@link PDFEditorTabs}: one empty tab to start with, new
 * tabs inheriting the editing state, files opened through the viewer's open
 * handler landing in a new tab (or filling an empty one), tab titles, closing
 * (the last tab leaves an empty one), next / previous, the Tabs menu and the
 * cached menu bars, the settings shared with every tab, and an annotation and
 * an image copied in one document and pasted into another.
 */
public class PDFEditorTabsTest {

    private static File dir, one, two;
    private PDFEditorTabs tabs;
    private Preferences node;
    private EditorSettings settings;

    @BeforeAll
    static void headless() throws Exception {
        System.setProperty("java.awt.headless", "true");
        dir = Files.createTempDirectory("pdf-editor-tabs").toFile();
        one = new File(dir, "first-document.pdf");
        two = new File(dir, "second-document.pdf");
        try (PDDocument doc = new PDDocument()) {
            doc.addPage(new PDPage(PDRectangle.A4));
            doc.save(one);
        }
        try (PDDocument doc = new PDDocument()) {
            doc.addPage(new PDPage(PDRectangle.A4));
            doc.addPage(new PDPage(PDRectangle.A4));
            doc.save(two);
        }
    }

    @AfterAll
    static void cleanUp() {
        for (File f : new File[]{one, two, dir})
            f.delete();
    }

    @BeforeEach
    void setUp() throws Exception {
        node = Preferences.userRoot().node("io/xlogistx/editor/pdf/test/" + UUID.randomUUID());
        settings = new EditorSettings(node);
        tabs = onEDT(() -> {
            PDFEditorTabs t = new PDFEditorTabs();
            t.setSize(900, 900);
            layoutTree(t);
            return t;
        });
        AnnotationClipboard.clipboard().setContents(new StringSelection(""), null);
    }

    @AfterEach
    void tearDown() throws Exception {
        onEDT(() -> {
            tabs.closeAll();
            return null;
        });
        node.removeNode();
    }

    @Test
    void startsWithOneEmptyTabAndNewTabsInheritEditing() throws Exception {
        assertEquals(1, tabs.getTabCount());
        PDFEditorPane first = tabs.getActivePane();
        assertSame(first, tabs.getPanes().get(0));
        assertEquals(PDFEditorTabs.EMPTY_TITLE, tabs.getTabbedPane().getTitleAt(0));
        assertFalse(first.isEditable());

        PDFEditorPane plain = onEDT(() -> tabs.newTab());
        assertEquals(2, tabs.getTabCount());
        assertSame(plain, tabs.getActivePane(), "a new tab is selected");
        assertFalse(plain.isEditable(), "editing off stays off");

        onEDT(() -> first.setEditable(true));
        onEDT(() -> tabs.selectTab(first));
        PDFEditorPane editing = onEDT(() -> tabs.newTab());
        assertTrue(editing.isEditable(), "the new tab edits like the one it was opened from");
        assertEquals(PDFEditorPane.EditTool.SELECT, editing.getActiveTool());
        assertEquals(3, tabs.getTabCount());
        assertEquals(2, tabs.indexOf(editing));
    }

    @Test
    void openingFillsAnEmptyTabAndOtherwiseAddsOne() throws Exception {
        PDFEditorPane first = tabs.getActivePane();
        PDFEditorPane shown = onEDT(() -> tabs.openInNewTab(one));
        assertSame(first, shown, "an empty active tab is used");
        waitFor(() -> first.getViewer().getDocument() != null, 10000);
        assertEquals(1, tabs.getTabCount());
        assertEquals(one.getName(), tabs.getTabbedPane().getTitleAt(0));
        assertEquals(one.getAbsolutePath(), tabs.getTabbedPane().getToolTipTextAt(0));

        // the viewer asks the handler while it has a document: the file goes to a new tab
        PDFEditorPane second = onEDT(() -> {
            assertTrue(first.getViewer().getOpenHandler().test(Arrays.asList(two)));
            return tabs.getActivePane();
        });
        assertNotSame(first, second);
        assertEquals(2, tabs.getTabCount());
        waitFor(() -> second.getViewer().getDocument() != null, 10000);
        assertEquals(2, second.getViewer().getPageCount());
        assertEquals(1, first.getViewer().getPageCount(), "the first tab keeps its document");
        assertEquals(two.getName(), tabs.getTabbedPane().getTitleAt(1));

        // Open Recent from a tab with a document goes to a new tab too
        onEDT(() -> tabs.setSettings(settings));
        onEDT(() -> tabs.selectTab(first));
        assertTrue(onEDT(() -> first.openRecent(two)));
        assertEquals(3, tabs.getTabCount());
        PDFEditorPane third = tabs.getActivePane();
        assertNotSame(first, third);
        assertNotSame(second, third);
        waitFor(() -> third.getViewer().getDocument() != null, 10000);

        // the API open on a pane never moves to another tab
        onEDT(() -> third.open(one));
        waitFor(() -> one.equals(third.getViewer().getFile()), 10000);
        assertEquals(3, tabs.getTabCount());
    }

    @Test
    void closingTabsAndMovingBetweenThem() throws Exception {
        PDFEditorPane a = tabs.getActivePane();
        onEDT(() -> a.setEditable(true));
        PDFEditorPane b = onEDT(() -> tabs.newTab());
        PDFEditorPane c = onEDT(() -> tabs.newTab());
        assertEquals(Arrays.asList(a, b, c), tabs.getPanes());
        assertSame(c, tabs.getActivePane());

        onEDT(() -> tabs.nextTab());
        assertSame(a, tabs.getActivePane(), "wraps round");
        onEDT(() -> tabs.previousTab());
        assertSame(c, tabs.getActivePane());
        onEDT(() -> tabs.previousTab());
        assertSame(b, tabs.getActivePane());

        onEDT(() -> b.open(one));
        waitFor(() -> b.getViewer().getDocument() != null, 10000);
        assertTrue(onEDT(() -> tabs.closeTab(b)), "an unmodified document closes without a question");
        assertEquals(Arrays.asList(a, c), tabs.getPanes());
        assertNull(b.getViewer().getDocument(), "the closed tab's document is released");
        assertFalse(onEDT(() -> tabs.closeTab(b)), "gone already");

        assertTrue(onEDT(() -> tabs.closeOtherTabs()));
        assertEquals(1, tabs.getTabCount());
        PDFEditorPane kept = tabs.getActivePane();
        assertTrue(kept == a || kept == c);

        assertTrue(onEDT(() -> tabs.closeActiveTab()));
        assertEquals(1, tabs.getTabCount(), "closing the last tab leaves an empty one");
        PDFEditorPane fresh = tabs.getActivePane();
        assertNotSame(kept, fresh);
        assertNull(fresh.getViewer().getDocument());
        assertEquals(PDFEditorTabs.EMPTY_TITLE, tabs.getTabbedPane().getTitleAt(0));
        assertTrue(fresh.isEditable(), "editing state survives");

        assertTrue(onEDT(() -> tabs.confirmDiscardAll()), "nothing modified: nothing to ask");
    }

    @Test
    void tabTitlesFollowTheDocumentAndAreShortened() throws Exception {
        PDFEditorPane pane = tabs.getActivePane();
        onEDT(() -> pane.open(two));
        waitFor(() -> pane.getViewer().getDocument() != null, 10000);
        assertEquals("second-document.pdf", PDFEditorTabs.tabTitle(pane));
        AtomicInteger events = new AtomicInteger();
        tabs.addChangeListener(e -> events.incrementAndGet());
        onEDT(() -> pane.rotatePages(new int[]{0}, 90));
        assertTrue(events.get() > 0, "pane changes reach the tabs' listeners");
        assertEquals("second-document.pdf *", tabs.getTabbedPane().getTitleAt(0));
        onEDT(() -> pane.undo());
        assertEquals("second-document.pdf", tabs.getTabbedPane().getTitleAt(0));

        File longName = new File(dir, "a-very-long-file-name-that-does-not-fit-on-a-tab.pdf");
        Files.copy(one.toPath(), longName.toPath());
        try {
            onEDT(() -> pane.open(longName));
            waitFor(() -> longName.equals(pane.getViewer().getFile()), 10000);
            String title = PDFEditorTabs.tabTitle(pane);
            assertTrue(title.length() <= PDFEditorTabs.MAX_TAB_TITLE, title);
            assertTrue(title.endsWith("….pdf"), title);
            assertTrue(title.startsWith("a-very-long"), title);
            assertEquals(longName.getAbsolutePath(), tabs.getTabbedPane().getToolTipTextAt(0));
        } finally {
            onEDT(() -> {
                pane.getViewer().close();
                return null;
            });
            longName.delete();
        }
    }

    @Test
    void menuBarPerTabWithTheTabsMenu() throws Exception {
        AtomicInteger customized = new AtomicInteger();
        onEDT(() -> tabs.setMenuBarCustomizer(bar -> customized.incrementAndGet()));
        PDFEditorPane a = tabs.getActivePane();
        JMenuBar barA = onEDT(() -> tabs.getMenuBar());
        assertSame(barA, onEDT(() -> tabs.getMenuBar()), "built once per pane");
        assertEquals(1, customized.get());
        List<String> names = new ArrayList<>();
        for (int i = 0; i < barA.getMenuCount(); i++)
            names.add(barA.getMenu(i).getText());
        int tabsAt = names.indexOf("Tabs");
        assertTrue(tabsAt > 0, names.toString());
        assertEquals("Help", names.get(names.size() - 1), "Help stays last");
        assertEquals(names.size() - 2, tabsAt, "Tabs sits right before Help");

        JMenu menu = barA.getMenu(tabsAt);
        assertEquals(KeyStroke.getKeyStroke(KeyEvent.VK_T, InputEvent.CTRL_DOWN_MASK), menuItem(menu, "New tab").getAccelerator());
        assertEquals(KeyStroke.getKeyStroke(KeyEvent.VK_W, InputEvent.CTRL_DOWN_MASK), menuItem(menu, "Close tab").getAccelerator());
        assertEquals(KeyStroke.getKeyStroke(KeyEvent.VK_TAB, InputEvent.CTRL_DOWN_MASK), menuItem(menu, "Next tab").getAccelerator());
        assertEquals(KeyStroke.getKeyStroke(KeyEvent.VK_TAB, InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK), menuItem(menu, "Previous tab").getAccelerator());

        // the menu lists the open tabs when it opens, with the active one ticked
        PDFEditorPane b = onEDT(() -> tabs.newTab());
        onEDT(() -> b.open(one));
        waitFor(() -> b.getViewer().getDocument() != null, 10000);
        JMenuBar barB = onEDT(() -> tabs.getMenuBar());
        assertNotSame(barA, barB, "each pane has its own bar");
        assertEquals(2, customized.get());
        JMenu menuB = barB.getMenu(tabsAt);
        onEDT(() -> {
            for (MenuListener l : menuB.getMenuListeners())
                l.menuSelected(new MenuEvent(menuB));
            return null;
        });
        List<JMenuItem> entries = tabEntries(menuB);
        assertEquals(2, entries.size(), labels(menuB).toString());
        assertEquals(PDFEditorTabs.EMPTY_TITLE, entries.get(0).getText());
        assertEquals(one.getName(), entries.get(1).getText());
        assertFalse(entries.get(0).isSelected());
        assertTrue(entries.get(1).isSelected());
        assertEquals(KeyStroke.getKeyStroke(KeyEvent.VK_1, InputEvent.ALT_DOWN_MASK), entries.get(0).getAccelerator());
        assertTrue(menuItem(menuB, "Close other tabs").isEnabled());
        onEDT(() -> {
            entries.get(0).doClick();
            return null;
        });
        assertSame(a, tabs.getActivePane());
        assertSame(barA, onEDT(() -> tabs.getMenuBar()), "back to the first pane's bar");

        // opening the menu again rebuilds the list, it does not grow
        onEDT(() -> {
            for (MenuListener l : menuB.getMenuListeners())
                l.menuSelected(new MenuEvent(menuB));
            return null;
        });
        assertEquals(2, tabEntries(menuB).size());

        // Ctrl+Tab and Alt+n are bound on the component
        assertEquals("nextTab", tabs.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).get(KeyStroke.getKeyStroke(KeyEvent.VK_TAB, InputEvent.CTRL_DOWN_MASK)));
        assertEquals("previousTab", tabs.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).get(KeyStroke.getKeyStroke(KeyEvent.VK_TAB, InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK)));
        assertEquals("tab2", tabs.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).get(KeyStroke.getKeyStroke(KeyEvent.VK_2, InputEvent.ALT_DOWN_MASK)));
        onEDT(() -> {
            tabs.getActionMap().get("tab2").actionPerformed(null);
            return null;
        });
        assertSame(b, tabs.getActivePane());

        // a closed tab's bar is forgotten
        assertTrue(onEDT(() -> tabs.closeTab(b)));
        assertSame(barA, onEDT(() -> tabs.getMenuBar()));
    }

    @Test
    void settingsReachEveryTabAndRecentFilesAreSharedAcrossTabs() throws Exception {
        onEDT(() -> tabs.setSettings(settings));
        PDFEditorPane a = tabs.getActivePane();
        assertSame(settings, a.getSettings());
        onEDT(() -> tabs.getMenuBar()); // builds a's menus, including Open Recent
        PDFEditorPane b = onEDT(() -> tabs.newTab());
        assertSame(settings, b.getSettings(), "a new tab gets the settings");
        onEDT(() -> tabs.getMenuBar());

        onEDT(() -> b.open(one));
        waitFor(() -> one.equals(b.getViewer().getFile()), 10000);
        assertEquals(Arrays.asList(one), settings.getRecentFiles());
        assertTrue(listsRecent(b, one), labels(b.getRecentMenu()).toString());
        assertFalse(listsRecent(a, one), "the other tab's menu is stale until shown");
        onEDT(() -> tabs.selectTab(a));
        assertTrue(listsRecent(a, one), "refreshed when the tab is shown");
        assertSame(settings, tabs.getSettings());
    }

    @Test
    void copyInOneDocumentPasteIntoAnother() throws Exception {
        PDFEditorPane a = tabs.getActivePane();
        onEDT(() -> a.open(one));
        waitFor(() -> a.getViewer().getDocument() != null, 10000);
        onEDT(() -> {
            layoutTree(tabs);
            a.setEditable(true);
            a.setActiveTool(PDFEditorPane.EditTool.SELECT);
            return null;
        });
        PDFEditorPane b = onEDT(() -> tabs.openInNewTab(two));
        assertNotSame(a, b);
        waitFor(() -> b.getViewer().getDocument() != null, 10000);
        onEDT(() -> {
            layoutTree(tabs);
            return null;
        });

        // a rectangle from the first document lands in the second, same size, centred on the point
        PDAnnotation square = onEDT(() -> {
            synchronized (a.getViewer().getDocumentLock()) {
                PDDocument doc = a.getViewer().getDocument();
                PDPage pg = doc.getPage(0);
                PDAnnotation s = AnnotationFactory.shape(doc, pg, PageTransform.of(pg), false, new Rectangle2D.Float(100, 100, 80, 50), AnnotationStyle.DRAWING);
                assertTrue(a.addAnnotation(0, s));
                return s;
            }
        });
        Rectangle2D.Float source = transform(a, 0).toViewRect(square.getRectangle()); // the handler pads Rect by the border
        onEDT(() -> a.selectAnnotation(0, square));
        assertTrue(onEDT(() -> a.copySelectedAnnotation()));
        onEDT(() -> tabs.selectTab(b));
        assertTrue(b.canPaste());
        Point at = onEDT(() -> b.getViewer().getToolContext().toPanelPoint(1, new java.awt.geom.Point2D.Float(300, 400)));
        PDAnnotation pasted = onEDT(() -> b.pasteAnnotation(at));
        assertNotNull(pasted);
        assertEquals("Square", AnnotationFactory.subtype(pasted));
        assertEquals(1, onEDT(() -> b.getAnnotations(1).size()));
        assertEquals(0, onEDT(() -> b.getAnnotations(0).size()));
        Rectangle2D.Float r = transform(b, 1).toViewRect(pasted.getRectangle());
        assertEquals(source.width, r.width, 0.01);
        assertEquals(source.height, r.height, 0.01);
        assertEquals(300, r.getCenterX(), 0.6);
        assertEquals(400, r.getCenterY(), 0.6);
        assertEquals("Paste rectangle", b.getEditModel().peekUndo().name());
        assertTrue(b.isModified());
        assertEquals(1, onEDT(() -> a.getAnnotations(0).size()), "the source document only has its own rectangle");

        // a picture is re-embedded in the other document, pixels intact
        BufferedImage picture = new BufferedImage(40, 20, BufferedImage.TYPE_INT_RGB);
        for (int x = 0; x < 40; x++)
            for (int y = 0; y < 20; y++)
                picture.setRGB(x, y, x < 20 ? 0xFF0000 : 0x0000FF);
        onEDT(() -> tabs.selectTab(a));
        PDAnnotation stamp = onEDT(() -> a.addImage(0, new Rectangle2D.Float(300, 300, 120, 60), picture));
        assertNotNull(stamp);
        onEDT(() -> a.selectAnnotation(0, stamp));
        assertTrue(onEDT(() -> a.copySelectedAnnotation()));
        onEDT(() -> tabs.selectTab(b));
        Point at2 = onEDT(() -> b.getViewer().getToolContext().toPanelPoint(0, new java.awt.geom.Point2D.Float(200, 200)));
        PDAnnotation pastedStamp = onEDT(() -> b.pasteAnnotation(at2));
        assertNotNull(pastedStamp);
        assertTrue(ImageStamp.isImage(pastedStamp));
        PDImageXObject sourceImage = onEDT(() -> ImageStamp.imageOf(stamp));
        PDImageXObject targetImage = onEDT(() -> ImageStamp.imageOf(pastedStamp));
        assertNotNull(targetImage);
        assertNotSame(sourceImage.getCOSObject(), targetImage.getCOSObject(), "its own copy in the other document");
        BufferedImage copy = onEDT(() -> {
            synchronized (b.getViewer().getDocumentLock()) {
                return targetImage.getImage();
            }
        });
        assertEquals(40, copy.getWidth());
        assertEquals(20, copy.getHeight());
        assertEquals(0xFF0000, copy.getRGB(5, 10) & 0xFFFFFF);
        assertEquals(0x0000FF, copy.getRGB(35, 10) & 0xFFFFFF);

        // the second document saves with both pastes inside
        File out = new File(dir, "pasted.pdf");
        try {
            onEDT(() -> {
                b.getViewer().save(out);
                return null;
            });
            waitFor(() -> !b.isModified(), 10000);
            try (PDDocument saved = Loader.loadPDF(out)) {
                assertEquals(1, saved.getPage(0).getAnnotations().size());
                assertEquals(1, saved.getPage(1).getAnnotations().size());
            }
        } finally {
            out.delete();
        }
    }

    // ------------------------------------------------------------------ helpers

    private static PageTransform transform(PDFEditorPane pane, int page) throws Exception {
        return onEDT(() -> {
            synchronized (pane.getViewer().getDocumentLock()) {
                return PageTransform.of(pane.getViewer().getDocument().getPage(page));
            }
        });
    }

    private static JMenuItem menuItem(JMenu menu, String text) {
        for (Component c : menu.getMenuComponents())
            if (c instanceof JMenuItem && text.equals(((JMenuItem) c).getText()))
                return (JMenuItem) c;
        throw new AssertionError("no item " + text + " in " + labels(menu));
    }

    /** Whether the pane's Open Recent menu has an entry for the file (entries read "1  name"). */
    private static boolean listsRecent(PDFEditorPane pane, File f) {
        for (String label : labels(pane.getRecentMenu()))
            if (label != null && label.endsWith(f.getName()))
                return true;
        return false;
    }

    private static List<String> labels(JMenu menu) {
        List<String> r = new ArrayList<>();
        for (Component c : menu.getMenuComponents())
            if (c instanceof JMenuItem)
                r.add(((JMenuItem) c).getText());
        return r;
    }

    /** The per-tab radio entries at the end of the Tabs menu. */
    private static List<JMenuItem> tabEntries(JMenu menu) {
        List<JMenuItem> r = new ArrayList<>();
        for (Component c : menu.getMenuComponents())
            if (c instanceof javax.swing.JRadioButtonMenuItem)
                r.add((JMenuItem) c);
        return r;
    }

    private static void layoutTree(Component c) {
        c.doLayout();
        if (c instanceof Container)
            for (Component child : ((Container) c).getComponents())
                layoutTree(child);
        if (c instanceof Container)
            c.doLayout();
    }

    private static <T> T onEDT(Callable<T> call) throws Exception {
        if (SwingUtilities.isEventDispatchThread())
            return call.call();
        Object[] result = new Object[1];
        Exception[] error = new Exception[1];
        SwingUtilities.invokeAndWait(() -> {
            try {
                result[0] = call.call();
            } catch (Exception e) {
                error[0] = e;
            }
        });
        if (error[0] != null)
            throw error[0];
        @SuppressWarnings("unchecked")
        T t = (T) result[0];
        return t;
    }

    private static void waitFor(BooleanSupplier condition, long timeoutMs) throws Exception {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < deadline) {
            if (onEDT(condition::getAsBoolean))
                return;
            Thread.sleep(20);
        }
        throw new IOException("timed out");
    }
}
