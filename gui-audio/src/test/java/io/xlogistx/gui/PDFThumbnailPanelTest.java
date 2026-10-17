package io.xlogistx.gui;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.swing.SwingUtilities;
import java.awt.Component;
import java.awt.Container;
import java.awt.Point;
import java.awt.Rectangle;
import java.awt.event.MouseEvent;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.concurrent.Callable;
import java.util.function.BooleanSupplier;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Headless tests of the thumbnail sidebar: one thumbnail per page in page
 * proportions, the current page tracked, a click jumping, a drag moving a page
 * (directly, or through the edit delegate), pictures rendered off the EDT and
 * dropped by {@code invalidatePage}.
 */
public class PDFThumbnailPanelTest {

    /** Portrait A4, landscape A4, Letter: distinguishable by size. */
    private static byte[] threePagePDF;
    private PDFViewerPanel panel;
    private PDFThumbnailPanel thumbs;

    @BeforeAll
    static void headless() throws Exception {
        System.setProperty("java.awt.headless", "true");
        try (PDDocument doc = new PDDocument()) {
            doc.addPage(new PDPage(PDRectangle.A4));
            doc.addPage(new PDPage(new PDRectangle(PDRectangle.A4.getHeight(), PDRectangle.A4.getWidth())));
            doc.addPage(new PDPage(PDRectangle.LETTER));
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            doc.save(out);
            threePagePDF = out.toByteArray();
        }
    }

    @BeforeEach
    void setUp() throws Exception {
        panel = onEDT(() -> {
            PDFViewerPanel p = new PDFViewerPanel();
            p.setSize(700, 800);
            layoutTree(p);
            return p;
        });
        PDDocument doc = Loader.loadPDF(threePagePDF);
        thumbs = onEDT(() -> {
            panel.setDocument(doc, true);
            panel.setThumbnailsVisible(true);
            layoutTree(panel);
            return panel.getThumbnailPanel();
        });
    }

    @AfterEach
    void tearDown() throws Exception {
        onEDT(() -> {
            panel.close();
            return null;
        });
    }

    @Test
    void oneThumbnailPerPageInPageProportions() throws Exception {
        assertTrue(panel.isThumbnailsVisible());
        assertTrue(SwingUtilities.isDescendingFrom(thumbs, panel));
        assertEquals(3, thumbs.getThumbnailCount());
        Rectangle portrait = thumbs.getThumbnailBounds(0), landscape = thumbs.getThumbnailBounds(1), letter = thumbs.getThumbnailBounds(2);
        assertTrue(landscape.y > portrait.y + portrait.height, "stacked top to bottom");
        assertTrue(letter.y > landscape.y + landscape.height);
        assertTrue(landscape.height < portrait.height, "a landscape page gives a flatter thumbnail");
        assertEquals(portrait.width, landscape.width, "all thumbnails share a width");
        assertEquals(0, thumbs.getCurrentIndex());

        // hide and show again
        onEDT(() -> panel.setThumbnailsVisible(false));
        assertFalse(panel.isThumbnailsVisible());
        assertFalse(SwingUtilities.isDescendingFrom(thumbs, panel));
        onEDT(() -> panel.setThumbnailsVisible(true));
        assertTrue(panel.isThumbnailsVisible());
        assertEquals(3, thumbs.getThumbnailCount());

        // closing empties it, loading fills it again
        onEDT(() -> {
            panel.close();
            return null;
        });
        assertEquals(0, thumbs.getThumbnailCount());
        PDDocument again = Loader.loadPDF(threePagePDF);
        onEDT(() -> panel.setDocument(again, true));
        assertEquals(3, thumbs.getThumbnailCount());
    }

    @Test
    void currentPageIsFramedAndAClickJumps() throws Exception {
        onEDT(() -> panel.gotoPage(2));
        assertEquals(2, thumbs.getCurrentIndex());
        Rectangle first = thumbs.getThumbnailBounds(0);
        Point centre = new Point(first.x + first.width / 2, first.y + first.height / 2);
        assertEquals(0, thumbs.indexAt(centre));
        assertEquals(-1, thumbs.indexAt(new Point(first.x + first.width + 3, 1)), "beside the column is nothing");
        onEDT(() -> {
            thumbs.dispatchEvent(mouse(MouseEvent.MOUSE_PRESSED, centre));
            thumbs.dispatchEvent(mouse(MouseEvent.MOUSE_RELEASED, centre));
            return null;
        });
        assertEquals(0, panel.getCurrentPage());
        assertEquals(0, thumbs.getCurrentIndex());
    }

    @Test
    void dropIndexFollowsThePointer() throws Exception {
        Rectangle a = thumbs.getThumbnailBounds(0), b = thumbs.getThumbnailBounds(1), c = thumbs.getThumbnailBounds(2);
        assertEquals(0, thumbs.dropIndexAt(new Point(a.x, a.y + 2)));
        assertEquals(1, thumbs.dropIndexAt(new Point(a.x, a.y + a.height - 2)), "the lower half means after it");
        assertEquals(1, thumbs.dropIndexAt(new Point(b.x, b.y + 2)));
        assertEquals(2, thumbs.dropIndexAt(new Point(c.x, c.y + 2)));
        assertEquals(3, thumbs.dropIndexAt(new Point(c.x, c.y + c.height + 50)), "below the last means the end");
    }

    @Test
    void dragMovesThePageDirectlyOrThroughTheDelegate() throws Exception {
        // drag the third page (Letter) above the first
        Rectangle first = thumbs.getThumbnailBounds(0), third = thumbs.getThumbnailBounds(2);
        Point from = new Point(third.x + third.width / 2, third.y + third.height / 2);
        Point to = new Point(first.x + first.width / 2, first.y + 1);
        onEDT(() -> {
            thumbs.dispatchEvent(mouse(MouseEvent.MOUSE_PRESSED, from));
            thumbs.dispatchEvent(mouse(MouseEvent.MOUSE_DRAGGED, new Point(from.x, from.y - 20)));
            assertTrue(thumbs.isDragging());
            thumbs.dispatchEvent(mouse(MouseEvent.MOUSE_DRAGGED, to));
            thumbs.dispatchEvent(mouse(MouseEvent.MOUSE_RELEASED, to));
            return null;
        });
        assertFalse(thumbs.isDragging());
        assertEquals(PDRectangle.LETTER.getWidth(), pageWidth(0), 0.01, "Letter is first now");
        assertEquals(PDRectangle.A4.getWidth(), pageWidth(1), 0.01);
        assertEquals(PDRectangle.A4.getHeight(), pageWidth(2), 0.01, "the landscape page is last");
        assertTrue(panel.isModified());
        assertEquals(3, thumbs.getThumbnailCount(), "the sidebar was rebuilt");
        assertEquals(0, panel.getCurrentPage(), "the moved page is shown");

        // a drop on its own place or just after it changes nothing
        int edits = onEDT(() -> panel.getPageCount());
        Rectangle second = thumbs.getThumbnailBounds(1);
        Point own = new Point(second.x + 2, second.y + 2);
        onEDT(() -> {
            thumbs.dispatchEvent(mouse(MouseEvent.MOUSE_PRESSED, new Point(second.x + 10, second.y + second.height / 2)));
            thumbs.dispatchEvent(mouse(MouseEvent.MOUSE_DRAGGED, own));
            thumbs.dispatchEvent(mouse(MouseEvent.MOUSE_RELEASED, own));
            return null;
        });
        assertEquals(PDRectangle.A4.getWidth(), pageWidth(1), 0.01);
        assertEquals(edits, panel.getPageCount());

        // with a delegate the move is handed over and the document is left alone
        int[][] asked = new int[1][];
        int[] target = new int[1];
        onEDT(() -> panel.setEditDelegate(new PDFViewerPanel.EditDelegate() {
            @Override
            public boolean insertDocument(PDDocument source, int at) {
                return false;
            }

            @Override
            public boolean deletePages(int[] pages) {
                return false;
            }

            @Override
            public boolean movePages(int[] pages, int t) {
                asked[0] = pages;
                target[0] = t;
                return true;
            }

            @Override
            public void documentReplaced() {
            }

            @Override
            public void documentSaved() {
            }

            @Override
            public boolean isModified() {
                return false;
            }
        }));
        assertTrue(onEDT(() -> panel.movePages(new int[]{2, 0, 0}, 9)));
        assertArrayEquals(new int[]{0, 2}, asked[0], "sorted, distinct");
        assertEquals(3, target[0], "clamped to the page count");
        assertEquals(PDRectangle.LETTER.getWidth(), pageWidth(0), 0.01, "untouched");
        assertThrows(IllegalArgumentException.class, () -> onEDT(() -> panel.movePages(new int[]{5}, 0)));
    }

    @Test
    void picturesRenderOffTheEDTAndInvalidateDropsThem() throws Exception {
        assertNull(thumbs.getThumbnailImage(0));
        onEDT(() -> {
            thumbs.requestThumbnail(0);
            return null;
        });
        waitFor(() -> thumbs.getThumbnailImage(0) != null, 10_000);
        BufferedImage img = thumbs.getThumbnailImage(0);
        assertEquals(PDFThumbnailPanel.THUMB_WIDTH, img.getWidth());
        assertTrue(img.getHeight() > img.getWidth(), "portrait");
        onEDT(() -> panel.invalidatePage(0));
        assertNull(thumbs.getThumbnailImage(0), "a changed page is rendered again");
        onEDT(() -> {
            thumbs.requestThumbnail(0);
            return null;
        });
        waitFor(() -> thumbs.getThumbnailImage(0) != null, 10_000);
        assertNotSame(img, thumbs.getThumbnailImage(0));
    }

    // ------------------------------------------------------------------ helpers

    private float pageWidth(int page) throws Exception {
        return onEDT(() -> {
            synchronized (panel.getDocumentLock()) {
                return panel.getDocument().getPage(page).getMediaBox().getWidth();
            }
        });
    }

    private MouseEvent mouse(int id, Point p) {
        return new MouseEvent(thumbs, id, System.currentTimeMillis(), id == MouseEvent.MOUSE_DRAGGED ? MouseEvent.BUTTON1_DOWN_MASK : 0,
                p.x, p.y, 1, false, MouseEvent.BUTTON1);
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
