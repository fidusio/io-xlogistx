package io.xlogistx.editor.pdf;

import io.xlogistx.editor.pdf.tools.SelectAnnotationTool;
import io.xlogistx.gui.pdf.PDFToolContext;
import io.xlogistx.gui.pdf.PDFViewerPanel;
import io.xlogistx.gui.pdf.PageTransform;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotation;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationText;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.swing.JComponent;
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;
import java.awt.Component;
import java.awt.Container;
import java.awt.Point;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.Transferable;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.awt.event.MouseEvent;
import java.awt.geom.Rectangle2D;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Headless tests of copy / cut / paste / duplicate of annotations: the clip on
 * the (JVM-local) clipboard, pasting on another spot and another page, images
 * keeping their picture and rotation, notes keeping their text and getting a
 * popup, text and pictures from other programs becoming text boxes and image
 * stamps, the keys, the Edit menu and the right-click entries.
 */
public class AnnotationClipboardTest {

    private static byte[] twoPagePDF;
    private PDFEditorPane pane;
    private PDFViewerPanel viewer;

    @BeforeAll
    static void headless() throws Exception {
        System.setProperty("java.awt.headless", "true");
        try (PDDocument doc = new PDDocument()) {
            doc.addPage(new PDPage(PDRectangle.A4));
            doc.addPage(new PDPage(PDRectangle.A4));
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            doc.save(out);
            twoPagePDF = out.toByteArray();
        }
    }

    @BeforeEach
    void setUp() throws Exception {
        pane = onEDT(() -> {
            PDFEditorPane p = new PDFEditorPane();
            p.setSize(700, 900);
            layoutTree(p);
            return p;
        });
        viewer = pane.getViewer();
        PDDocument doc = Loader.loadPDF(twoPagePDF);
        onEDT(() -> {
            viewer.setDocument(doc, true);
            layoutTree(pane);
            pane.setEditable(true);
            pane.setActiveTool(PDFEditorPane.EditTool.SELECT);
            return null;
        });
        clipboard().setContents(new StringSelection(""), null); // a clean slate (empty text reads as nothing)
    }

    @AfterEach
    void tearDown() throws Exception {
        onEDT(() -> {
            viewer.close();
            return null;
        });
    }

    @Test
    void copyThenPasteElsewhereAndOnAnotherPage() throws Exception {
        PDAnnotation square = addSquare(0, new Rectangle2D.Float(100, 100, 80, 50));
        Rectangle2D.Float source = transform(0).toViewRect(square.getRectangle());
        int before = count(0);
        assertFalse(onEDT(() -> pane.copySelectedAnnotation()), "nothing selected");
        assertFalse(pane.canPaste());

        onEDT(() -> pane.selectAnnotation(0, square));
        assertTrue(onEDT(() -> pane.copySelectedAnnotation()));
        assertTrue(pane.canPaste());
        assertTrue(clipboard().isDataFlavorAvailable(AnnotationClipboard.CLIP_FLAVOR));
        assertFalse(clipboard().isDataFlavorAvailable(DataFlavor.stringFlavor), "a rectangle has no text for other programs");
        AnnotationClipboard.Clip clip = (AnnotationClipboard.Clip) clipboard().getData(AnnotationClipboard.CLIP_FLAVOR);
        assertEquals("rectangle", clip.kind());
        assertEquals("Square", clip.subtype());
        assertEquals(source.width, clip.width(), 0.01);

        // paste centred on a point of the same page: a new rectangle of the same size, selected, one undo step
        Point at = panelPoint(0, 400, 600);
        PDAnnotation pasted = onEDT(() -> pane.pasteAnnotation(at));
        assertNotNull(pasted);
        assertNotSame(square.getCOSObject(), pasted.getCOSObject());
        assertEquals(before + 1, count(0));
        assertEquals("Square", AnnotationFactory.subtype(pasted));
        Rectangle2D.Float r = transform(0).toViewRect(pasted.getRectangle());
        assertEquals(400, r.getCenterX(), 0.6);
        assertEquals(600, r.getCenterY(), 0.6);
        assertEquals(source.width, r.width, 0.01);
        assertEquals(source.height, r.height, 0.01);
        assertSame(pasted.getCOSObject(), pane.getSelectedAnnotation().getCOSObject(), "the paste is selected");
        assertEquals("Paste rectangle", pane.getEditModel().peekUndo().name());
        assertEquals(source, transform(0).toViewRect(square.getRectangle()), "the original stays put");
        assertTrue(pane.isModified());

        // the clip can be pasted again, on another page, and is kept on the page when the point is at its edge
        Point edge = panelPoint(1, 5, 5);
        PDAnnotation second = onEDT(() -> pane.pasteAnnotation(edge));
        assertNotNull(second);
        assertEquals(1, count(1));
        Rectangle2D.Float r2 = transform(1).toViewRect(second.getRectangle());
        assertEquals(0, r2.x, 0.01);
        assertEquals(0, r2.y, 0.01);
        assertEquals(1, pane.getSelectedAnnotationPage());

        // undo takes the pastes back one at a time
        onEDT(pane::undo);
        assertEquals(0, count(1));
        onEDT(pane::undo);
        assertEquals(before, count(0));
        onEDT(pane::redo);
        assertEquals(before + 1, count(0));
    }

    @Test
    void repeatedPastesAtTheSameSpotCascade() throws Exception {
        PDAnnotation square = addSquare(0, new Rectangle2D.Float(100, 100, 80, 50));
        onEDT(() -> pane.selectAnnotation(0, square));
        assertTrue(onEDT(() -> pane.copySelectedAnnotation()));
        Point at = panelPoint(0, 300, 300);
        float step = SelectAnnotationTool.DUPLICATE_OFFSET_PT;
        for (int i = 0; i < 3; i++) {
            PDAnnotation p = onEDT(() -> pane.pasteAnnotation(at));
            Rectangle2D.Float r = transform(0).toViewRect(p.getRectangle());
            assertEquals(300 + i * step, r.getCenterX(), 0.6, "paste " + i);
            assertEquals(300 + i * step, r.getCenterY(), 0.6, "paste " + i);
        }
        // another spot, or another page, starts over; back at the first spot it starts over too
        Rectangle2D.Float other = transform(0).toViewRect(onEDT(() -> pane.pasteAnnotation(panelPoint(0, 400, 500))).getRectangle());
        assertEquals(400, other.getCenterX(), 0.6);
        Rectangle2D.Float page2 = transform(1).toViewRect(onEDT(() -> pane.pasteAnnotation(panelPoint(1, 300, 300))).getRectangle());
        assertEquals(300, page2.getCenterX(), 0.6);
        Rectangle2D.Float again = transform(0).toViewRect(onEDT(() -> pane.pasteAnnotation(at)).getRectangle());
        assertEquals(300, again.getCenterX(), 0.6);
        Rectangle2D.Float second = transform(0).toViewRect(onEDT(() -> pane.pasteAnnotation(at)).getRectangle());
        assertEquals(300 + step, second.getCenterX(), 0.6);
    }

    @Test
    void cutRemovesAndPastePutsBackDuplicateOffsets() throws Exception {
        PDAnnotation square = addSquare(0, new Rectangle2D.Float(100, 100, 80, 50));
        Rectangle2D.Float source = transform(0).toViewRect(square.getRectangle());
        int before = count(0);
        onEDT(() -> pane.selectAnnotation(0, square));

        assertTrue(onEDT(() -> pane.cutSelectedAnnotation()));
        assertEquals(before - 1, count(0));
        assertNull(pane.getSelectedAnnotation());
        assertEquals("Cut rectangle", pane.getEditModel().peekUndo().name());
        assertTrue(pane.canPaste());
        PDAnnotation back = onEDT(() -> pane.pasteAnnotation(panelPoint(0, 140, 125)));
        assertNotNull(back);
        assertEquals(before, count(0));
        Rectangle2D.Float r = transform(0).toViewRect(back.getRectangle());
        assertEquals(source.getCenterX(), r.getCenterX(), 0.6);
        assertEquals(source.getCenterY(), r.getCenterY(), 0.6);

        // duplicate: 10 pt right and down, selected, clipboard untouched
        clipboard().setContents(new StringSelection("untouched"), null);
        PDAnnotation dup = onEDT(() -> pane.duplicateSelectedAnnotation());
        assertNotNull(dup);
        assertEquals(before + 1, count(0));
        Rectangle2D.Float d = transform(0).toViewRect(dup.getRectangle());
        assertEquals(r.x + SelectAnnotationTool.DUPLICATE_OFFSET_PT, d.x, 0.6);
        assertEquals(r.y + SelectAnnotationTool.DUPLICATE_OFFSET_PT, d.y, 0.6);
        assertSame(dup.getCOSObject(), pane.getSelectedAnnotation().getCOSObject());
        assertEquals("Duplicate rectangle", pane.getEditModel().peekUndo().name());
        assertEquals("untouched", clipboard().getData(DataFlavor.stringFlavor));

        // nothing selected or editing off: nothing happens
        onEDT(() -> pane.clearAnnotationSelection());
        assertFalse(onEDT(() -> pane.cutSelectedAnnotation()));
        assertNull(onEDT(() -> pane.duplicateSelectedAnnotation()));
        onEDT(() -> pane.selectAnnotation(0, dup));
        onEDT(() -> pane.setEditable(false));
        assertFalse(onEDT(() -> pane.copySelectedAnnotation()));
        assertNull(onEDT(() -> pane.duplicateSelectedAnnotation()));
    }

    @Test
    void imagesKeepPictureAndTurnNotesKeepTextAndGetAPopup() throws Exception {
        BufferedImage picture = new BufferedImage(40, 20, BufferedImage.TYPE_INT_RGB);
        picture.setRGB(0, 0, 0xFF0000);
        PDAnnotation image = onEDT(() -> pane.addImage(0, new Rectangle2D.Float(300, 300, 120, 60), picture));
        assertNotNull(image);
        onEDT(() -> pane.selectAnnotation(0, image));
        assertTrue(onEDT(() -> pane.rotateSelectedImage(90)));
        Rectangle2D.Float turned = transform(0).toViewRect(image.getRectangle());
        assertEquals(60, turned.width, 0.01);
        assertEquals(120, turned.height, 0.01);

        assertTrue(onEDT(() -> pane.copySelectedAnnotation()));
        assertTrue(clipboard().isDataFlavorAvailable(DataFlavor.imageFlavor), "other programs get the picture");
        BufferedImage offered = (BufferedImage) clipboard().getData(DataFlavor.imageFlavor);
        assertEquals(40, offered.getWidth());
        assertEquals(20, offered.getHeight());

        PDAnnotation pasted = onEDT(() -> pane.pasteAnnotation(panelPoint(1, 200, 200)));
        assertNotNull(pasted);
        assertTrue(ImageStamp.isImage(pasted), "the paste is an image stamp with a picture");
        assertEquals(90, ImageStamp.rotationOf(pasted));
        Rectangle2D.Float r = transform(1).toViewRect(pasted.getRectangle());
        assertEquals(60, r.width, 0.01);
        assertEquals(120, r.height, 0.01);
        assertEquals(200, r.getCenterX(), 0.6);
        assertEquals("Paste image", pane.getEditModel().peekUndo().name());
        assertSame(ImageStamp.imageOf(image).getCOSObject(), ImageStamp.imageOf(pasted).getCOSObject(), "the same document shares the picture");
        assertEquals("Selected: image 60 × 120 pt, turned 90° on page 2", pane.getStatusDetail());

        PDAnnotation note = onEDT(() -> pane.addNote(0, new java.awt.geom.Point2D.Float(50, 500), "hello there"));
        onEDT(() -> pane.selectAnnotation(0, note));
        assertTrue(onEDT(() -> pane.copySelectedAnnotation()));
        assertEquals("hello there", clipboard().getData(DataFlavor.stringFlavor), "other programs get the text");
        int before = count(1);
        PDAnnotation pastedNote = onEDT(() -> pane.pasteAnnotation(panelPoint(1, 100, 100)));
        assertNotNull(pastedNote);
        assertEquals(before + 1, count(1));
        assertEquals("hello there", pastedNote.getContents());
        assertTrue(pastedNote instanceof PDAnnotationText);
        assertNotNull(((PDAnnotationText) pastedNote).getPopup(), "a pasted note has its own popup");
        assertNotSame(((PDAnnotationText) note).getPopup().getCOSObject(), ((PDAnnotationText) pastedNote).getPopup().getCOSObject());
        assertEquals("Paste note", pane.getEditModel().peekUndo().name());
    }

    @Test
    void textAndPicturesFromOtherProgramsBecomeTextBoxesAndImages() throws Exception {
        clipboard().setContents(new StringSelection("pasted words\nsecond line"), null);
        assertTrue(pane.canPaste());
        PDAnnotation box = onEDT(() -> pane.pasteAnnotation(panelPoint(0, 300, 400)));
        assertNotNull(box);
        assertEquals("FreeText", AnnotationFactory.subtype(box));
        assertEquals("pasted words\nsecond line", box.getContents());
        assertEquals("Paste text box", pane.getEditModel().peekUndo().name());
        Rectangle2D.Float r = transform(0).toViewRect(box.getRectangle());
        assertEquals(300, r.getCenterX(), 0.6);
        assertEquals(400, r.getCenterY(), 0.6);
        assertSame(box.getCOSObject(), pane.getSelectedAnnotation().getCOSObject());

        BufferedImage picture = new BufferedImage(30, 60, BufferedImage.TYPE_INT_ARGB);
        clipboard().setContents(new ImageSelection(picture), null);
        PDAnnotation stamp = onEDT(() -> pane.pasteAnnotation(panelPoint(1, 300, 300)));
        assertNotNull(stamp);
        assertTrue(ImageStamp.isImage(stamp));
        assertEquals("Paste image", pane.getEditModel().peekUndo().name());
        Rectangle2D.Float s = transform(1).toViewRect(stamp.getRectangle());
        assertEquals(30, s.width, 0.01);
        assertEquals(60, s.height, 0.01);
        assertEquals(300, s.getCenterX(), 0.6);
        assertEquals(300, s.getCenterY(), 0.6);

        // an empty clipboard pastes nothing; editing off is turned on by a paste
        clipboard().setContents(new StringSelection("   "), null);
        assertFalse(pane.canPaste() && onEDT(() -> pane.pasteAnnotation(panelPoint(0, 300, 400))) != null);
        clipboard().setContents(new StringSelection("again"), null);
        onEDT(() -> pane.setEditable(false));
        assertNotNull(onEDT(() -> pane.pasteAnnotation(panelPoint(0, 100, 100))));
        assertTrue(pane.isEditable());
    }

    @Test
    void keysMenuAndRightClickOfferCutCopyPasteDuplicate() throws Exception {
        // Ctrl+X / Ctrl+V / Ctrl+D are bound on the pane; Ctrl+C is the viewer's and goes to the annotation first
        assertEquals("cutAnnotation", pane.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT).get(KeyStroke.getKeyStroke(KeyEvent.VK_X, InputEvent.CTRL_DOWN_MASK)));
        assertEquals("paste", pane.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT).get(KeyStroke.getKeyStroke(KeyEvent.VK_V, InputEvent.CTRL_DOWN_MASK)));
        assertEquals("duplicateAnnotation", pane.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT).get(KeyStroke.getKeyStroke(KeyEvent.VK_D, InputEvent.CTRL_DOWN_MASK)));
        PDAnnotation square = addSquare(0, new Rectangle2D.Float(100, 100, 80, 50));
        onEDT(() -> pane.selectAnnotation(0, square));
        assertTrue(onEDT(() -> viewer.copySelection()), "the viewer's copy is taken over by the selected annotation");
        assertTrue(clipboard().isDataFlavorAvailable(AnnotationClipboard.CLIP_FLAVOR));

        // right click over the square
        Point onSquare = panelPoint(0, 140, 125), onEmpty = panelPoint(0, 400, 600);
        List<String> items = labels(onEDT(() -> viewer.buildContextMenu(mouse(onSquare))));
        assertTrue(items.contains("Cut this rectangle"), items.toString());
        assertTrue(items.contains("Copy this rectangle"), items.toString());
        assertTrue(items.contains("Duplicate this rectangle"), items.toString());
        assertFalse(items.contains("Paste here"), "Paste belongs to empty space");

        // right click over empty space: Paste here, enabled because the clipboard holds the square
        JPopupMenu menu = onEDT(() -> viewer.buildContextMenu(mouse(onEmpty)));
        JMenuItem paste = itemNamed(menu, "Paste here");
        assertTrue(paste.isEnabled());
        int before = count(0);
        onEDT(() -> {
            paste.doClick();
            return null;
        });
        assertEquals(before + 1, count(0));
        Rectangle2D.Float r = transform(0).toViewRect(pane.getSelectedAnnotation().getRectangle());
        assertEquals(400, r.getCenterX(), 0.6);
        assertEquals(600, r.getCenterY(), 0.6);

        // the Edit menu has the four entries, enabled as the state allows
        javax.swing.JMenuBar bar = onEDT(() -> pane.createMenuBar());
        javax.swing.JMenu edit = null;
        for (int i = 0; i < bar.getMenuCount(); i++)
            if ("Edit".equals(bar.getMenu(i).getText()))
                edit = bar.getMenu(i);
        assertNotNull(edit);
        javax.swing.JMenu menuEdit = edit;
        onEDT(() -> {
            for (javax.swing.event.MenuListener l : menuEdit.getMenuListeners())
                l.menuSelected(new javax.swing.event.MenuEvent(menuEdit));
            return null;
        });
        assertTrue(menuItem(edit, "Cut annotation").isEnabled());
        assertTrue(menuItem(edit, "Duplicate annotation").isEnabled());
        assertTrue(menuItem(edit, "Paste").isEnabled());
        assertTrue(menuItem(edit, "Copy").isEnabled());
        onEDT(() -> pane.clearAnnotationSelection());
        onEDT(() -> {
            for (javax.swing.event.MenuListener l : menuEdit.getMenuListeners())
                l.menuSelected(new javax.swing.event.MenuEvent(menuEdit));
            return null;
        });
        assertFalse(menuItem(edit, "Cut annotation").isEnabled());
        assertFalse(menuItem(edit, "Duplicate annotation").isEnabled());
        assertTrue(menuItem(edit, "Paste").isEnabled(), "the clipboard still holds the square");

        // editing off: no clipboard entries in the right-click menu
        onEDT(() -> pane.setEditable(false));
        items = labels(onEDT(() -> viewer.buildContextMenu(mouse(onEmpty))));
        assertFalse(items.contains("Paste here"));
    }

    // ------------------------------------------------------------------ helpers

    private static Clipboard clipboard() {
        return AnnotationClipboard.clipboard();
    }

    private PDAnnotation addSquare(int page, Rectangle2D viewRect) throws Exception {
        return onEDT(() -> {
            synchronized (viewer.getDocumentLock()) {
                PDDocument doc = viewer.getDocument();
                PDPage pg = doc.getPage(page);
                PDAnnotation a = AnnotationFactory.shape(doc, pg, PageTransform.of(pg), false, viewRect, AnnotationStyle.DRAWING);
                assertTrue(pane.addAnnotation(page, a));
                return a;
            }
        });
    }

    private int count(int page) throws Exception {
        return onEDT(() -> pane.getAnnotations(page).size());
    }

    private PageTransform transform(int page) throws Exception {
        return onEDT(() -> {
            synchronized (viewer.getDocumentLock()) {
                return PageTransform.of(viewer.getDocument().getPage(page));
            }
        });
    }

    private PDFToolContext ctx() {
        return viewer.getToolContext();
    }

    /** A pages-panel point for a view-space point (points, top-left origin) of a page. */
    private Point panelPoint(int page, float x, float y) throws Exception {
        return onEDT(() -> ctx().toPanelPoint(page, new java.awt.geom.Point2D.Float(x, y)));
    }

    private MouseEvent mouse(Point p) {
        return new MouseEvent(viewer, MouseEvent.MOUSE_RELEASED, System.currentTimeMillis(), 0, p.x, p.y, 1, true, MouseEvent.BUTTON3);
    }

    private static List<String> labels(JPopupMenu menu) {
        List<String> r = new ArrayList<>();
        for (Component c : menu.getComponents())
            if (c instanceof JMenuItem)
                r.add(((JMenuItem) c).getText());
        return r;
    }

    private static JMenuItem itemNamed(JPopupMenu menu, String text) {
        for (Component c : menu.getComponents())
            if (c instanceof JMenuItem && text.equals(((JMenuItem) c).getText()))
                return (JMenuItem) c;
        throw new AssertionError("no item " + text);
    }

    private static JMenuItem menuItem(javax.swing.JMenu menu, String text) {
        for (Component c : menu.getMenuComponents())
            if (c instanceof JMenuItem && text.equals(((JMenuItem) c).getText()))
                return (JMenuItem) c;
        throw new AssertionError("no item " + text);
    }

    /** A picture on the clipboard the way another program would put it. */
    private static final class ImageSelection implements Transferable {
        private final BufferedImage image;

        ImageSelection(BufferedImage image) {
            this.image = image;
        }

        @Override
        public DataFlavor[] getTransferDataFlavors() {
            return new DataFlavor[]{DataFlavor.imageFlavor};
        }

        @Override
        public boolean isDataFlavorSupported(DataFlavor flavor) {
            return DataFlavor.imageFlavor.equals(flavor);
        }

        @Override
        public Object getTransferData(DataFlavor flavor) throws UnsupportedFlavorException {
            if (!isDataFlavorSupported(flavor))
                throw new UnsupportedFlavorException(flavor);
            return image;
        }
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
            return call.call(); // a helper called from inside another onEDT block
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
}
