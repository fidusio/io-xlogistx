package io.xlogistx.editor.pdf;

import io.xlogistx.gui.pdf.PDFToolContext;
import io.xlogistx.gui.pdf.PDFViewerPanel;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotation;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.imageio.ImageIO;
import javax.swing.JCheckBoxMenuItem;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.SwingUtilities;
import javax.swing.TransferHandler;
import java.awt.Component;
import java.awt.Container;
import java.awt.Point;
import java.awt.Rectangle;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.awt.geom.Rectangle2D;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.function.BooleanSupplier;
import java.util.prefs.Preferences;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Headless tests of the workspace features: the thumbnail sidebar driving the
 * undo model and the View menu, files dropped on the window (a picture on a
 * page becomes an image stamp, PDFs are inserted as undoable edits), and the
 * settings (recent files, last directory, thumbnails, zoom, window bounds) on
 * a throwaway preferences node.
 */
public class WorkspaceTest {

    private static byte[] threePagePDF;
    private static File dir, pdfFile, pngFile, txtFile;
    private PDFEditorPane pane;
    private PDFViewerPanel viewer;
    private Preferences node;
    private EditorSettings settings;

    @BeforeAll
    static void headless() throws Exception {
        System.setProperty("java.awt.headless", "true");
        try (PDDocument doc = new PDDocument()) {
            doc.addPage(new PDPage(PDRectangle.A4));
            doc.addPage(new PDPage(new PDRectangle(PDRectangle.A4.getHeight(), PDRectangle.A4.getWidth())));
            doc.addPage(new PDPage(PDRectangle.LETTER));
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            doc.save(out);
            threePagePDF = out.toByteArray();
        }
        dir = Files.createTempDirectory("pdf-editor-workspace").toFile();
        pdfFile = new File(dir, "one-page.pdf");
        try (PDDocument doc = new PDDocument()) {
            doc.addPage(new PDPage(PDRectangle.A5));
            doc.save(pdfFile);
        }
        pngFile = new File(dir, "picture.png");
        BufferedImage img = new BufferedImage(40, 20, BufferedImage.TYPE_INT_RGB);
        ImageIO.write(img, "png", pngFile);
        txtFile = new File(dir, "notes.txt");
        Files.write(txtFile.toPath(), "not a source".getBytes("UTF-8"));
    }

    @AfterAll
    static void cleanUp() {
        for (File f : new File[]{pdfFile, pngFile, txtFile})
            f.delete();
        dir.delete();
    }

    @BeforeEach
    void setUp() throws Exception {
        node = Preferences.userRoot().node("io/xlogistx/editor/pdf/test/" + UUID.randomUUID());
        settings = new EditorSettings(node);
        pane = onEDT(() -> {
            PDFEditorPane p = new PDFEditorPane();
            p.setSize(900, 900);
            layoutTree(p);
            return p;
        });
        viewer = pane.getViewer();
        PDDocument doc = Loader.loadPDF(threePagePDF);
        onEDT(() -> {
            viewer.setDocument(doc, true);
            layoutTree(pane);
            pane.setEditable(true);
            pane.setActiveTool(PDFEditorPane.EditTool.SELECT);
            return null;
        });
    }

    @AfterEach
    void tearDown() throws Exception {
        onEDT(() -> {
            viewer.close();
            return null;
        });
        node.removeNode();
    }

    // ------------------------------------------------------------------ thumbnails

    @Test
    void thumbnailDragGoesThroughTheUndoModel() throws Exception {
        onEDT(() -> viewer.setThumbnailsVisible(true));
        onEDT(() -> {
            layoutTree(pane);
            return null;
        });
        assertEquals(3, viewer.getThumbnailPanel().getThumbnailCount());
        int depth = pane.getEditModel().getUndoDepth();
        // what a drag of the third thumbnail above the first does
        assertTrue(onEDT(() -> viewer.movePages(new int[]{2}, 0)));
        assertEquals(depth + 1, pane.getEditModel().getUndoDepth(), "the move is one undoable edit");
        assertEquals("Move 1 page", pane.getEditModel().peekUndo().name());
        assertEquals(PDRectangle.LETTER.getWidth(), pageWidth(0), 0.01);
        assertEquals(3, viewer.getThumbnailPanel().getThumbnailCount());
        assertTrue(pane.isModified());
        onEDT(pane::undo);
        assertEquals(PDRectangle.A4.getWidth(), pageWidth(0), 0.01);
        assertEquals(PDRectangle.LETTER.getWidth(), pageWidth(2), 0.01);

        // with editing off a drag turns it on
        onEDT(() -> pane.setEditable(false));
        assertTrue(onEDT(() -> viewer.movePages(new int[]{0}, 3)));
        assertTrue(pane.isEditable());
        assertEquals(PDRectangle.A4.getWidth(), pageWidth(2), 0.01, "page 1 went to the end");
    }

    @Test
    void viewMenuTogglesTheSidebar() throws Exception {
        JMenuBar bar = onEDT(() -> pane.createMenuBar());
        JMenu view = menu(bar, "View");
        JCheckBoxMenuItem item = (JCheckBoxMenuItem) menuItem(view, "Page thumbnails");
        assertFalse(item.isSelected());
        assertFalse(viewer.isThumbnailsVisible());
        onEDT(() -> {
            item.doClick();
            return null;
        });
        assertTrue(viewer.isThumbnailsVisible());
        assertTrue(item.isSelected());
        onEDT(() -> viewer.setThumbnailsVisible(false));
        assertFalse(item.isSelected(), "the menu follows the viewer");
    }

    // ------------------------------------------------------------------ drag and drop

    @Test
    void droppedFilesBecomeAStampOrPages() throws Exception {
        // a picture dropped on a page while editing: an image stamp at the drop point, selected
        int before = count(0);
        Point at = panelPoint(0, 200, 300);
        assertTrue(onEDT(() -> viewer.dropFiles(Collections.singletonList(pngFile), at)));
        assertEquals(before + 1, count(0));
        PDAnnotation stamp = pane.getSelectedAnnotation();
        assertNotNull(stamp);
        assertTrue(ImageStamp.isImage(stamp));
        Rectangle2D.Float r = transform(0).toViewRect(stamp.getRectangle());
        assertEquals(200, r.x, 0.6);
        assertEquals(300, r.y, 0.6);
        assertEquals(40, r.width, 0.01);
        assertEquals("Add image", pane.getEditModel().peekUndo().name());

        // a PDF dropped with a chosen outcome: its page inserted at the end as an undoable edit
        int depth = pane.getEditModel().getUndoDepth();
        onEDT(() -> {
            viewer.dropFiles(Collections.singletonList(pdfFile), PDFViewerPanel.DropAction.INSERT_AT_END);
            return null;
        });
        waitFor(() -> viewer.getPageCount() == 4, 10_000);
        assertEquals(depth + 1, pane.getEditModel().getUndoDepth());
        assertEquals(PDRectangle.A5.getWidth(), pageWidth(3), 0.01);
        onEDT(pane::undo);
        assertEquals(3, viewer.getPageCount());

        // a text file is refused by the drop target, a PDF or picture accepted
        TransferHandler h = viewer.getTransferHandler();
        assertNotNull(h);
        assertTrue(h.canImport(new TransferHandler.TransferSupport(viewer, files(pdfFile))));
        assertTrue(h.canImport(new TransferHandler.TransferSupport(viewer, files(pngFile, txtFile))));
        assertFalse(h.canImport(new TransferHandler.TransferSupport(viewer, files(txtFile))));
        assertFalse(onEDT(() -> viewer.dropFiles(Collections.singletonList(txtFile), at)));
        assertTrue(PDFViewerPanel.acceptsFile(new File("x.MD")));
        assertFalse(PDFViewerPanel.acceptsFile(new File("x.doc")));

        // the same picture dropped with editing off is not a stamp (the viewer would ask what to do)
        onEDT(() -> pane.setEditable(false));
        int n = count(0);
        assertFalse(onEDT(() -> viewer.dropFiles(Collections.singletonList(txtFile), at)));
        assertEquals(n, count(0));
    }

    // ------------------------------------------------------------------ saving

    @Test
    void savingOverTheOpenFileKeepsTheUndoHistory() throws Exception {
        File work = new File(dir, "work.pdf");
        Files.copy(pdfFile.toPath(), work.toPath());
        try {
            onEDT(() -> pane.open(work));
            waitFor(() -> work.equals(viewer.getFile()), 10_000);
            PDDocument doc = onEDT(viewer::getDocument);
            assertTrue(onEDT(() -> pane.rotatePages(new int[]{0}, 90)));
            assertTrue(pane.isModified());
            assertEquals(1, pane.getEditModel().getUndoDepth());

            onEDT(() -> pane.save());
            waitFor(() -> !pane.isModified(), 10_000);
            assertSame(doc, onEDT(viewer::getDocument), "no reload after saving over the open file");
            assertTrue(pane.canUndo(), "the history survives the save");
            assertEquals(0, viewer.getCurrentPage());
            try (PDDocument saved = Loader.loadPDF(work)) {
                assertEquals(90, saved.getPage(0).getRotation(), "the file holds the edit");
            }

            // undo past the saved state marks the document modified again, redo back to clean
            onEDT(pane::undo);
            assertTrue(pane.isModified());
            onEDT(pane::redo);
            assertFalse(pane.isModified());

            // a second save of the same document works too
            assertTrue(onEDT(() -> pane.rotatePages(new int[]{0}, 90)));
            onEDT(() -> pane.save());
            waitFor(() -> !pane.isModified(), 10_000);
            try (PDDocument saved = Loader.loadPDF(work)) {
                assertEquals(180, saved.getPage(0).getRotation());
            }
            assertEquals(2, pane.getEditModel().getUndoDepth());
        } finally {
            onEDT(() -> {
                viewer.close();
                return null;
            });
            work.delete();
        }
    }

    // ------------------------------------------------------------------ settings

    @Test
    void recentFilesAreOrderedDedupedAndCapped() {
        assertTrue(settings.getRecentFiles().isEmpty());
        for (int i = 0; i < EditorSettings.MAX_RECENT + 3; i++)
            settings.addRecentFile(new File(dir, "f" + i + ".pdf"));
        List<File> recent = settings.getRecentFiles();
        assertEquals(EditorSettings.MAX_RECENT, recent.size());
        assertEquals("f12.pdf", recent.get(0).getName(), "most recent first");
        assertEquals("f3.pdf", recent.get(recent.size() - 1).getName(), "the oldest fell off");
        settings.addRecentFile(new File(dir, "f5.pdf"));
        recent = settings.getRecentFiles();
        assertEquals("f5.pdf", recent.get(0).getName(), "re-adding moves to the front");
        assertEquals(EditorSettings.MAX_RECENT, recent.size());
        assertEquals(1, recent.stream().filter(f -> f.getName().equals("f5.pdf")).count(), "no duplicate");
        settings.removeRecentFile(new File(dir, "f5.pdf"));
        assertFalse(settings.getRecentFiles().stream().anyMatch(f -> f.getName().equals("f5.pdf")));
        settings.clearRecentFiles();
        assertTrue(settings.getRecentFiles().isEmpty());

        settings.setWindowBounds(new Rectangle(10, 20, 800, 600));
        assertEquals(new Rectangle(10, 20, 800, 600), settings.getWindowBounds());
        settings.setWindowMaximized(true);
        assertTrue(settings.isWindowMaximized());
        assertNull(settings.getLastDirectory());
        settings.setLastDirectory(dir);
        assertEquals(dir.getAbsoluteFile(), settings.getLastDirectory().getAbsoluteFile());
        settings.setLastDirectory(new File(dir, "gone"));
        assertNull(settings.getLastDirectory(), "a vanished directory is not offered");
        assertTrue(PDFEditorFrame.onAScreen(new Rectangle(0, 0, 100, 100)), "headless: no screens to check against");
    }

    @Test
    void controlTextSizeIsAppliedRememberedAndOnTheViewMenu() throws Exception {
        float base = io.xlogistx.gui.UIFontSize.getBase();
        try {
            settings.setUIFontSize(base + 4);
            onEDT(() -> pane.setSettings(settings));
            assertEquals(base + 4, io.xlogistx.gui.UIFontSize.get(), 0.01, "the remembered size is applied");
            assertEquals(base + 4, pane.getEditToolbar().getFont().getSize2D(), 0.01, "the pane was refreshed");
            assertEquals(base + 3, pane.getStatusBar().getComponent(0).getFont().getSize2D(), 0.01, "the status line stays one point smaller");
            assertEquals(Math.round(base + 4), ((Number) viewer.getFontSizeWidget().getSpinner().getValue()).intValue());

            JMenuBar bar = onEDT(() -> pane.createMenuBar());
            JMenu view = menu(bar, "View");
            JMenu size = null;
            for (Component c : view.getMenuComponents())
                if (c instanceof JMenu && "Control text size".equals(((JMenu) c).getText()))
                    size = (JMenu) c;
            assertNotNull(size);
            JMenuItem larger = menuItem(size, "Larger"), reset = menuItem(size, "Reset");
            onEDT(() -> {
                larger.doClick();
                return null;
            });
            assertEquals(base + 5, io.xlogistx.gui.UIFontSize.get(), 0.01);
            onEDT(() -> {
                pane.saveSettings();
                return null;
            });
            assertEquals(base + 5, settings.getUIFontSize(-1), 0.01, "saved with the rest");
            onEDT(() -> {
                reset.doClick();
                return null;
            });
            assertEquals(base, io.xlogistx.gui.UIFontSize.get(), 0.01);
            assertEquals(base - 1, pane.getStatusBar().getComponent(0).getFont().getSize2D(), 0.01);
        } finally {
            onEDT(io.xlogistx.gui.UIFontSize::reset);
        }
    }

    @Test
    void paneAppliesAndRecordsSettings() throws Exception {
        settings.setThumbnailsVisible(true);
        settings.setZoomMode("FIT_PAGE");
        onEDT(() -> pane.setSettings(settings));
        assertTrue(viewer.isThumbnailsVisible(), "the sidebar comes back");
        assertEquals(PDFViewerPanel.ZoomMode.FIT_PAGE, viewer.getZoomMode());
        onEDT(() -> viewer.setThumbnailsVisible(false));
        assertFalse(settings.isThumbnailsVisible(), "a toggle is recorded at once");

        // opening a file records it and its directory; the menu lists it
        JMenuBar bar = onEDT(() -> pane.createMenuBar());
        JMenu recent = pane.getRecentMenu();
        assertNotNull(recent);
        assertSame(recent, menuItemParent(bar));
        assertEquals("No recent files", ((JMenuItem) recent.getMenuComponent(0)).getText());
        onEDT(() -> pane.open(pdfFile));
        waitFor(() -> pdfFile.equals(viewer.getFile()), 10_000);
        assertEquals(pdfFile.getAbsoluteFile(), settings.getRecentFiles().get(0));
        assertEquals(dir.getAbsoluteFile(), settings.getLastDirectory().getAbsoluteFile());
        assertEquals(dir.getAbsoluteFile(), viewer.getDefaultDirectory().getAbsoluteFile());
        assertEquals("1  one-page.pdf", ((JMenuItem) recent.getMenuComponent(0)).getText());
        assertEquals("Clear list", ((JMenuItem) recent.getMenuComponent(recent.getMenuComponentCount() - 1)).getText());

        // a vanished file is dropped from the list when chosen
        File gone = new File(dir, "gone.pdf");
        settings.addRecentFile(gone);
        onEDT(() -> pane.setSettings(settings));
        assertEquals(2, settings.getRecentFiles().size());
        // (the error dialog cannot show headless, so the removal is checked through the settings after the guard)
        assertFalse(gone.isFile());
        settings.removeRecentFile(gone);
        assertEquals(1, settings.getRecentFiles().size());

        // the zoom is written at the end
        onEDT(() -> viewer.setZoom(1.5f));
        onEDT(() -> {
            pane.saveSettings();
            return null;
        });
        assertEquals("CUSTOM", settings.getZoomMode());
        assertEquals(1.5f, settings.getZoom(1f), 0.001);
        assertFalse(settings.isThumbnailsVisible());

        // a fresh pane with the same settings starts where this one left off
        PDFEditorPane other = onEDT(() -> new PDFEditorPane().setSettings(settings));
        assertEquals(1.5f, other.getViewer().getZoom(), 0.001);
        assertFalse(other.getViewer().isThumbnailsVisible());
        assertEquals(dir.getAbsoluteFile(), other.getViewer().getDefaultDirectory().getAbsoluteFile());
        onEDT(() -> {
            other.getViewer().close();
            return null;
        });

        // Clear list
        JMenuItem clear = (JMenuItem) recent.getMenuComponent(recent.getMenuComponentCount() - 1);
        onEDT(() -> {
            clear.doClick();
            return null;
        });
        assertTrue(settings.getRecentFiles().isEmpty());
        assertEquals("No recent files", ((JMenuItem) recent.getMenuComponent(0)).getText());
    }

    // ------------------------------------------------------------------ helpers

    private static JMenu menuItemParent(JMenuBar bar) {
        JMenu file = menu(bar, "File");
        for (Component c : file.getMenuComponents())
            if (c instanceof JMenu && "Open Recent".equals(((JMenu) c).getText()))
                return (JMenu) c;
        throw new AssertionError("no Open Recent menu");
    }

    private static JMenu menu(JMenuBar bar, String text) {
        for (int i = 0; i < bar.getMenuCount(); i++)
            if (text.equals(bar.getMenu(i).getText()))
                return bar.getMenu(i);
        throw new AssertionError("no menu " + text);
    }

    private static JMenuItem menuItem(JMenu menu, String text) {
        for (Component c : menu.getMenuComponents())
            if (c instanceof JMenuItem && text.equals(((JMenuItem) c).getText()))
                return (JMenuItem) c;
        throw new AssertionError("no item " + text);
    }

    private static Transferable files(File... files) {
        List<File> list = new ArrayList<>(Arrays.asList(files));
        return new Transferable() {
            @Override
            public DataFlavor[] getTransferDataFlavors() {
                return new DataFlavor[]{DataFlavor.javaFileListFlavor};
            }

            @Override
            public boolean isDataFlavorSupported(DataFlavor flavor) {
                return DataFlavor.javaFileListFlavor.equals(flavor);
            }

            @Override
            public Object getTransferData(DataFlavor flavor) throws UnsupportedFlavorException {
                if (!isDataFlavorSupported(flavor))
                    throw new UnsupportedFlavorException(flavor);
                return list;
            }
        };
    }

    private float pageWidth(int page) throws Exception {
        return onEDT(() -> {
            synchronized (viewer.getDocumentLock()) {
                return viewer.getDocument().getPage(page).getMediaBox().getWidth();
            }
        });
    }

    private int count(int page) throws Exception {
        return onEDT(() -> pane.getAnnotations(page).size());
    }

    private io.xlogistx.gui.pdf.PageTransform transform(int page) throws Exception {
        return onEDT(() -> {
            synchronized (viewer.getDocumentLock()) {
                return io.xlogistx.gui.pdf.PageTransform.of(viewer.getDocument().getPage(page));
            }
        });
    }

    private PDFToolContext ctx() {
        return viewer.getToolContext();
    }

    private Point panelPoint(int page, float x, float y) throws Exception {
        return onEDT(() -> ctx().toPanelPoint(page, new java.awt.geom.Point2D.Float(x, y)));
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

    private void waitFor(BooleanSupplier condition, long timeoutMs) throws Exception {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < deadline) {
            if (onEDT(condition::getAsBoolean))
                return;
            Thread.sleep(20);
        }
        throw new IOException("timed out");
    }
}
