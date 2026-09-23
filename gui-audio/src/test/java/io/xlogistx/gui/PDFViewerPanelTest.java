package io.xlogistx.gui;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.swing.*;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.File;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BooleanSupplier;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Headless tests for {@link PDFViewerPanel}. The panel is never displayed; its
 * component tree is laid out by hand so the viewport has a size and the lazy
 * renderer has something to do.
 */
public class PDFViewerPanelTest {

    private static final String PAGE_BREAK = "\n\n<div style=\"page-break-before: always\"></div>\n\n";
    private static final String THREE_PAGES =
            "# Page One\n\nfirst page text" + PAGE_BREAK +
            "# Page Two\n\nneedle-two lives here" + PAGE_BREAK +
            "# Page Three\n\nlast page";

    private static byte[] threePagePDF;
    private PDFViewerPanel panel;

    @BeforeAll
    static void headless() throws Exception {
        System.setProperty("java.awt.headless", "true");
        threePagePDF = MDToPDF.mdToPDF(THREE_PAGES).toByteArray();
    }

    @BeforeEach
    void setUp() throws Exception {
        panel = onEDT(() -> {
            PDFViewerPanel p = new PDFViewerPanel();
            p.setSize(600, 800);
            layoutTree(p);
            return p;
        });
    }

    @AfterEach
    void tearDown() throws Exception {
        onEDT(() -> {
            panel.close();
            return null;
        });
    }

    // ------------------------------------------------------------------ tests

    @Test
    public void loadsAndClampsNavigation() throws Exception {
        load(threePagePDF);
        assertEquals(3, onEDT(panel::getPageCount));
        assertEquals(0, onEDT(panel::getCurrentPage));

        onEDT(() -> panel.gotoPage(10));
        assertEquals(2, onEDT(panel::getCurrentPage));
        onEDT(() -> panel.gotoPage(-5));
        assertEquals(0, onEDT(panel::getCurrentPage));
        onEDT(panel::nextPage);
        assertEquals(1, onEDT(panel::getCurrentPage));
        onEDT(panel::previousPage);
        assertEquals(0, onEDT(panel::getCurrentPage));
    }

    @Test
    public void rendersVisiblePageOffTheEDT() throws Exception {
        load(threePagePDF);
        waitFor(() -> panel.getPageImage(0) != null, 10_000);

        BufferedImage img = onEDT(() -> panel.getPageImage(0));
        assertTrue(img.getWidth() > 100 && img.getHeight() > 100);
        assertTrue(hasDarkPixel(img), "rendered page should contain text pixels");

        // custom zoom re-renders at a different size
        int w1 = img.getWidth();
        onEDT(() -> panel.setZoom(0.5f));
        assertEquals(PDFViewerPanel.ZoomMode.CUSTOM, onEDT(panel::getZoomMode));
        waitFor(() -> panel.getPageImage(0) != null, 10_000);
        BufferedImage half = onEDT(() -> panel.getPageImage(0));
        assertTrue(half.getWidth() < w1, "0.5 zoom should render narrower than fit width");
    }

    @Test
    public void findLocatesTextOnSecondPage() throws Exception {
        load(threePagePDF);
        List<Integer> hits = panel.find("needle-two");
        assertEquals(1, hits.size());
        assertEquals(1, hits.get(0).intValue());
        assertEquals(3, panel.find("page").size());
        assertTrue(panel.find("").isEmpty());
        assertTrue(panel.find(null).isEmpty());
        assertTrue(panel.find("no such text").isEmpty());
    }

    @Test
    public void searchReturnsGlyphRectanglesOnTheRightPage() throws Exception {
        load(threePagePDF);
        List<PDFViewerPanel.Match> hits = panel.search("needle-two");
        assertEquals(1, hits.size());
        PDFViewerPanel.Match m = hits.get(0);
        assertEquals(1, m.getPage());
        assertTrue(m.getEnd() - m.getStart() == "needle-two".length());
        assertEquals(1, m.getRects().size(), "single-line match should yield one rectangle");
        java.awt.geom.Rectangle2D.Float r = m.getRects().get(0);
        // A4 is 595 x 842 pt with 2cm (~57pt) margins: the hit must sit inside the text area
        assertTrue(r.x >= 50 && r.x + r.width <= 545, "x range " + r);
        assertTrue(r.y >= 50 && r.y + r.height <= 792, "y range " + r);
        assertTrue(r.width > 30 && r.height > 5 && r.height < 30, "size " + r);

        // case-insensitive, multiple hits in document order
        List<PDFViewerPanel.Match> pages = panel.search("PAGE");
        assertTrue(pages.size() >= 3, "expected a hit on every page, got " + pages);
        for (int i = 1; i < pages.size(); i++)
            assertTrue(pages.get(i).getPage() >= pages.get(i - 1).getPage());
        assertTrue(panel.search("").isEmpty());
        assertTrue(panel.search(null).isEmpty());
    }

    @Test
    public void highlightsNavigateAndWrap() throws Exception {
        load(threePagePDF);
        List<PDFViewerPanel.Match> hits = panel.search("page");
        int n = hits.size();
        assertTrue(n >= 3);

        onEDT(() -> panel.setHighlights(hits));
        assertEquals(n, onEDT(() -> panel.getHighlights().size()));
        assertEquals(0, onEDT(panel::getCurrentMatch));
        assertEquals(hits.get(0).getPage(), onEDT(panel::getCurrentPage));

        onEDT(() -> panel.gotoMatch(n - 1));
        assertEquals(n - 1, onEDT(panel::getCurrentMatch));
        assertEquals(hits.get(n - 1).getPage(), onEDT(panel::getCurrentPage), "current page follows the match");

        onEDT(panel::nextMatch);
        assertEquals(0, onEDT(panel::getCurrentMatch), "next wraps to the first match");
        onEDT(panel::previousMatch);
        assertEquals(n - 1, onEDT(panel::getCurrentMatch), "previous wraps to the last match");

        onEDT(panel::clearHighlights);
        assertTrue(onEDT(() -> panel.getHighlights().isEmpty()));
        assertEquals(-1, onEDT(panel::getCurrentMatch));
        // navigation on empty highlights is a no-op
        onEDT(panel::nextMatch);
        assertEquals(-1, onEDT(panel::getCurrentMatch));
    }

    @Test
    public void highlightAsyncInstallsMatches() throws Exception {
        load(threePagePDF);
        java.util.concurrent.atomic.AtomicReference<List<PDFViewerPanel.Match>> got = new java.util.concurrent.atomic.AtomicReference<>();
        onEDT(() -> {
            panel.highlightAsync("needle-two", got::set);
            return null;
        });
        waitFor(() -> got.get() != null, 10_000);
        assertEquals(1, got.get().size());
        assertEquals(1, onEDT(() -> panel.getHighlights().size()));
        assertEquals(1, onEDT(panel::getCurrentPage));
    }

    @Test
    public void highlightsAreClearedOnClose() throws Exception {
        load(threePagePDF);
        onEDT(() -> panel.setHighlights(panel.search("page")));
        assertFalse(onEDT(() -> panel.getHighlights().isEmpty()));
        onEDT(() -> {
            panel.close();
            return null;
        });
        assertTrue(onEDT(() -> panel.getHighlights().isEmpty()));
        assertNull(onEDT(panel::getFile));
    }

    @Test
    public void fileLoadingRecordsTheFile() throws Exception {
        File dir = java.nio.file.Files.createTempDirectory("pdfviewer").toFile();
        File f = new File(dir, "three.pdf");
        java.nio.file.Files.write(f.toPath(), threePagePDF);
        onEDT(() -> {
            panel.setPDF(f);
            return null;
        });
        waitFor(() -> panel.getPageCount() == 3, 10_000);
        assertEquals(f, onEDT(panel::getFile));
        // a document installed from bytes afterwards is not file-backed
        load(threePagePDF);
        assertNull(onEDT(panel::getFile));
    }

    @Test
    public void saveWritesLoadablePDF() throws Exception {
        load(threePagePDF);
        File dir = java.nio.file.Files.createTempDirectory("pdfsave").toFile();
        File out = new File(dir, "copy.pdf");
        onEDT(() -> {
            panel.save(out);
            return null;
        });
        waitFor(() -> out.length() > 0 && out.equals(panel.getFile()), 10_000);
        try (PDDocument doc = Loader.loadPDF(out)) {
            assertEquals(3, doc.getNumberOfPages());
        }
        assertEquals(3, onEDT(panel::getPageCount), "viewer keeps showing the document");

        // save over the source file: document is written, closed, replaced and reloaded
        onEDT(() -> panel.gotoPage(2));
        PDDocument before = onEDT(panel::getDocument);
        onEDT(() -> {
            panel.save(out);
            return null;
        });
        waitFor(() -> panel.getDocument() != null && panel.getDocument() != before
                && panel.getPageCount() == 3 && panel.getCurrentPage() == 2, 10_000);
        assertTrue(before.getDocument().isClosed(), "source document released before the file was replaced");
        try (PDDocument doc = Loader.loadPDF(out)) {
            assertEquals(3, doc.getNumberOfPages());
        }
        assertEquals(out, onEDT(panel::getFile));
        assertEquals(1, dir.listFiles().length, "no temp file left behind");

        // nothing loaded: save is a no-op
        onEDT(() -> {
            panel.close();
            panel.save(new File(dir, "never.pdf"));
            return null;
        });
        Thread.sleep(300);
        assertFalse(new File(dir, "never.pdf").exists());
    }

    @Test
    public void pageableCoversAllPagesAndPrintNeedsADocument() throws Exception {
        assertNull(onEDT(panel::createPageable));
        boolean started = onEDT(panel::print);
        assertFalse(started, "print without a document is a no-op");

        load(threePagePDF);
        java.awt.print.Pageable pageable = onEDT(panel::createPageable);
        assertNotNull(pageable);
        assertEquals(3, pageable.getNumberOfPages());
        // render page two through the print path into an image: same code the printer runs
        java.awt.print.PageFormat pf = pageable.getPageFormat(1);
        BufferedImage img = new BufferedImage((int) pf.getWidth(), (int) pf.getHeight(), BufferedImage.TYPE_INT_RGB);
        Graphics2D g = img.createGraphics();
        g.setColor(Color.WHITE);
        g.fillRect(0, 0, img.getWidth(), img.getHeight());
        int status = pageable.getPrintable(1).print(g, pf, 1);
        g.dispose();
        assertEquals(java.awt.print.Printable.PAGE_EXISTS, status);
        assertTrue(hasDarkPixel(img), "printed page should contain text pixels");

        // after close the pageable of the old document prints nothing
        onEDT(() -> {
            panel.close();
            return null;
        });
        assertEquals(java.awt.print.Printable.NO_SUCH_PAGE, pageable.getPrintable(0).print(img.createGraphics(), pf, 0));
    }

    @Test
    public void zoomToAreaFillsViewportAndCenters() throws Exception {
        load(threePagePDF);
        int vw = onEDT(() -> viewport().getWidth());
        int vh = onEDT(() -> viewport().getHeight());
        // a 100 x 50 pt area on page two, 200 pt from the top
        java.awt.geom.Rectangle2D.Float area = new java.awt.geom.Rectangle2D.Float(100, 200, 100, 50);
        onEDT(() -> panel.zoomTo(1, area));
        assertEquals(PDFViewerPanel.ZoomMode.CUSTOM, onEDT(panel::getZoomMode));
        float zoom = onEDT(panel::getZoom);
        float expected = Math.min(vw / 100f, vh / 50f);
        assertEquals(expected, zoom, 0.05f, "zoom fills the viewport with the area");
        assertEquals(1, onEDT(panel::getCurrentPage));

        // the area's center is at the viewport center (page 2 is now huge, so scrolling is possible)
        Rectangle view = onEDT(() -> viewport().getViewRect());
        int pageY = onEDT(() -> ((Container) viewport().getView()).getComponent(2).getY()); // page views sit at 0, 2, 4 (struts between)
        int pageX = onEDT(() -> ((Container) viewport().getView()).getComponent(2).getX());
        int centerX = pageX + Math.round(150 * zoom), centerY = pageY + Math.round(225 * zoom);
        assertTrue(Math.abs(view.x + view.width / 2 - centerX) < 40, "x center off by " + (view.x + view.width / 2 - centerX));
        assertTrue(Math.abs(view.y + view.height / 2 - centerY) < 40, "y center off by " + (view.y + view.height / 2 - centerY));

        // tiny area clamps at MAX_ZOOM, bad page ignored
        onEDT(() -> panel.zoomTo(0, new java.awt.geom.Rectangle2D.Float(10, 10, 1, 1)));
        assertEquals(PDFViewerPanel.MAX_ZOOM, onEDT(panel::getZoom), 0.0001f);
        onEDT(() -> panel.zoomTo(7, area));
        assertEquals(PDFViewerPanel.MAX_ZOOM, onEDT(panel::getZoom), 0.0001f);
        assertThrows(NullPointerException.class, () -> panel.zoomTo(0, null));
    }

    @Test
    public void toolsToggleAndSetTheCursor() throws Exception {
        assertEquals(PDFViewerPanel.Tool.PAN, onEDT(panel::getTool));
        assertFalse(onEDT(panel::isZoomToSelectionMode));
        onEDT(() -> panel.setZoomToSelectionMode(true));
        assertTrue(onEDT(panel::isZoomToSelectionMode));
        assertEquals(PDFViewerPanel.Tool.ZOOM_TO_SELECTION, onEDT(panel::getTool));
        assertEquals(Cursor.CROSSHAIR_CURSOR, onEDT(() -> viewport().getView().getCursor().getType()));
        onEDT(() -> panel.setTool(PDFViewerPanel.Tool.SELECT_TEXT));
        assertFalse(onEDT(panel::isZoomToSelectionMode));
        assertEquals(Cursor.TEXT_CURSOR, onEDT(() -> viewport().getView().getCursor().getType()));
        onEDT(() -> panel.setZoomToSelectionMode(false));
        assertEquals(PDFViewerPanel.Tool.PAN, onEDT(panel::getTool));
        assertEquals(Cursor.DEFAULT_CURSOR, onEDT(() -> viewport().getView().getCursor().getType()));
        assertThrows(NullPointerException.class, () -> panel.setTool(null));
    }

    @Test
    public void textSelectionKeepsCaseAndSpansPages() throws Exception {
        load(threePagePDF);
        assertFalse(onEDT(panel::hasSelection));
        assertEquals("", onEDT(panel::getSelectedText));

        PDFViewerPanel.Match m = panel.search("page two").get(0);
        assertEquals(1, m.getPage());
        onEDT(() -> panel.select(1, m.getStart(), 1, m.getEnd()));
        assertTrue(onEDT(panel::hasSelection));
        assertEquals("Page Two", onEDT(panel::getSelectedText), "selection keeps the original case");

        // reversed ends normalize to the same selection
        onEDT(() -> panel.select(1, m.getEnd(), 1, m.getStart()));
        assertEquals("Page Two", onEDT(panel::getSelectedText));

        // hit testing: the middle of the match rectangle maps back into the match
        java.awt.geom.Rectangle2D.Float r = m.getRects().get(0);
        int idx = panel.charIndexAt(1, r.x + 1, r.y + r.height / 2);
        assertTrue(idx >= m.getStart() && idx <= m.getStart() + 1, "index " + idx + " vs match start " + m.getStart());
        assertEquals(0, panel.charIndexAt(1, 10, 1), "above the first line");
        assertTrue(panel.charIndexAt(1, 10, 830) > m.getEnd(), "below the last line = end of page text");
        assertEquals(-1, panel.charIndexAt(9, 1, 1));

        // multi-page selection and select all
        onEDT(() -> panel.select(0, 0, 2, Integer.MAX_VALUE));
        String all = onEDT(panel::getSelectedText);
        assertTrue(all.contains("Page One") && all.contains("needle-two") && all.contains("Page Three"), all);
        onEDT(panel::selectAll);
        assertEquals(all, onEDT(panel::getSelectedText));

        onEDT(panel::clearSelection);
        assertFalse(onEDT(panel::hasSelection));
        onEDT(() -> panel.select(0, 5, 0, 5));
        assertFalse(onEDT(panel::hasSelection), "empty range clears");
        onEDT(() -> {
            panel.close();
            return null;
        });
        assertEquals("", onEDT(panel::getSelectedText));
    }

    @Test
    public void scrollByClampsToContent() throws Exception {
        load(threePagePDF);
        onEDT(() -> panel.setZoom(2f));
        onEDT(() -> {
            viewport().setViewPosition(new Point(0, 0));
            return null;
        });
        onEDT(() -> panel.scrollBy(0, 300));
        assertEquals(300, onEDT(() -> viewport().getViewPosition().y));
        onEDT(() -> panel.scrollBy(0, -1000));
        assertEquals(0, onEDT(() -> viewport().getViewPosition().y));
        onEDT(() -> panel.scrollBy(0, 1_000_000));
        int maxY = onEDT(() -> viewport().getView().getHeight() - viewport().getHeight());
        assertEquals(maxY, onEDT(() -> viewport().getViewPosition().y));
    }

    @Test
    public void closeIsIdempotentAndReusable() throws Exception {
        load(threePagePDF);
        onEDT(() -> {
            panel.close();
            panel.close();
            return null;
        });
        assertEquals(0, onEDT(panel::getPageCount));
        assertEquals(-1, onEDT(panel::getCurrentPage));
        assertNull(onEDT(panel::getDocument));
        assertTrue(panel.find("needle-two").isEmpty());

        load(threePagePDF);
        assertEquals(3, onEDT(panel::getPageCount));
    }

    @Test
    public void closesOwnedDocumentOnly() throws Exception {
        PDDocument owned = Loader.loadPDF(threePagePDF);
        onEDT(() -> panel.setDocument(owned, true));
        onEDT(() -> panel.setDocument(null, false));
        assertTrue(owned.getDocument().isClosed(), "owned document should be closed");

        PDDocument borrowed = Loader.loadPDF(threePagePDF);
        onEDT(() -> panel.setDocument(borrowed, false));
        onEDT(() -> {
            panel.close();
            return null;
        });
        assertFalse(borrowed.getDocument().isClosed(), "borrowed document must stay open");
        borrowed.close();
    }

    @Test
    public void cacheEvictsUnderBudget() throws Exception {
        onEDT(() -> panel.setCacheBytes(1)); // room for exactly one image
        load(threePagePDF);
        onEDT(() -> panel.setZoom(0.2f));    // all three pages fit the viewport
        waitFor(() -> panel.getCachedPageCount() >= 1, 10_000);
        // give the other pages a chance to render, cache must still hold at most one
        Thread.sleep(500);
        assertEquals(1, onEDT(panel::getCachedPageCount));
        assertThrows(IllegalArgumentException.class, () -> panel.setCacheBytes(0));
    }

    @Test
    public void zoomClampsAndFitWidthTracksViewport() throws Exception {
        load(threePagePDF);
        onEDT(() -> panel.setZoom(100f));
        assertEquals(PDFViewerPanel.MAX_ZOOM, onEDT(panel::getZoom), 0.0001f);
        onEDT(() -> panel.setZoom(0f));
        assertEquals(PDFViewerPanel.MIN_ZOOM, onEDT(panel::getZoom), 0.0001f);

        onEDT(panel::fitWidth);
        assertEquals(PDFViewerPanel.ZoomMode.FIT_WIDTH, onEDT(panel::getZoomMode));
        float zoom = onEDT(panel::getZoom);
        // A4 page is 595pt wide; the fit zoom scales it into the viewport width
        int viewportWidth = onEDT(() -> viewport().getWidth());
        assertTrue(zoom > 0.5f && zoom * 595 <= viewportWidth, "zoom " + zoom + " viewport " + viewportWidth);
    }

    @Test
    public void pageChangeListenerFires() throws Exception {
        AtomicInteger lastPage = new AtomicInteger(-99);
        AtomicInteger lastCount = new AtomicInteger(-99);
        onEDT(() -> panel.addPageChangeListener((page, count) -> {
            lastPage.set(page);
            lastCount.set(count);
        }));
        load(threePagePDF);
        assertEquals(0, lastPage.get());
        assertEquals(3, lastCount.get());
        onEDT(() -> panel.gotoPage(2));
        assertEquals(2, lastPage.get());
        onEDT(() -> {
            panel.close();
            return null;
        });
        assertEquals(-1, lastPage.get());
        assertEquals(0, lastCount.get());
    }

    @Test
    public void rejectsNulls() {
        assertThrows(NullPointerException.class, () -> panel.setPDF((byte[]) null));
        assertThrows(NullPointerException.class, () -> panel.setZoomMode(null));
        assertThrows(NullPointerException.class, () -> panel.addPageChangeListener(null));
    }

    // ---------------------------------------------------------------- helpers

    private void load(byte[] pdf) throws Exception {
        PDDocument doc = Loader.loadPDF(pdf);
        onEDT(() -> {
            panel.setDocument(doc, true);
            layoutTree(panel);
            return null;
        });
    }

    private JViewport viewport() {
        for (Component c : panel.getComponents())
            if (c instanceof JScrollPane)
                return ((JScrollPane) c).getViewport();
        throw new IllegalStateException("no scroll pane");
    }

    /** Sizes and lays out an undisplayed component tree (validate() needs a peer). */
    private static void layoutTree(Component c) {
        c.doLayout();
        if (c instanceof Container)
            for (Component child : ((Container) c).getComponents())
                layoutTree(child);
        if (c instanceof Container)
            c.doLayout();
    }

    private static <T> T onEDT(Callable<T> call) throws Exception {
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
            Thread.sleep(50);
        }
        fail("condition not met within " + timeoutMs + " ms");
    }

    private static boolean hasDarkPixel(BufferedImage img) {
        for (int y = 0; y < img.getHeight(); y += 2)
            for (int x = 0; x < img.getWidth(); x += 2)
                if ((img.getRGB(x, y) & 0xff) < 128)
                    return true;
        return false;
    }
}
