package io.xlogistx.gui;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.printing.PDFPageable;
import org.apache.pdfbox.rendering.ImageType;
import org.apache.pdfbox.rendering.PDFRenderer;
import org.apache.pdfbox.text.PDFTextStripper;
import org.apache.pdfbox.text.TextPosition;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.shared.util.SUS;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.awt.event.*;
import java.awt.geom.AffineTransform;
import java.awt.geom.Rectangle2D;
import java.awt.print.Pageable;
import java.awt.print.PrinterJob;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

/**
 * A Swing PDF viewer backed by Apache PDFBox. Pages are stacked vertically
 * inside a scroll pane — the panel scrolls on its own, do not wrap it in
 * another scroll pane — and rendered lazily: only pages near the viewport are
 * rasterized, on a background thread, and kept in a byte-bounded LRU cache.
 *
 * <h2>Loading</h2>
 * {@link #setPDF(byte[])}, {@link #setPDF(File)} and {@link #setPDF(InputStream)}
 * parse the document off the EDT via {@link BackgroundTask} and return
 * immediately; an error dialog is shown if parsing fails. {@link #setDocument(PDDocument, boolean)}
 * installs an already parsed document synchronously. {@link #close()} releases
 * the current document; the panel can be reused afterwards.
 *
 * <h2>Navigation and zoom</h2>
 * Page indexes in the API are zero-based (PDFBox convention); the toolbar shows
 * them one-based. Zoom is either a fixed factor ({@link ZoomMode#CUSTOM}) or
 * recomputed on resize ({@link ZoomMode#FIT_WIDTH}, {@link ZoomMode#FIT_PAGE}).
 * Keyboard: Page Up/Down scroll by a screen, Ctrl+Page Up/Down jump pages,
 * Ctrl+Home/End first/last page, Ctrl+Plus/Minus zoom, Ctrl+0 fit width,
 * Ctrl+A select all text, Ctrl+C copy the selection, Esc clears the
 * selection or returns to the pan tool. Mouse: Ctrl+wheel zooms around the
 * pointer; what a plain drag does depends on the {@link Tool}:
 * {@link Tool#PAN} scrolls, {@link Tool#SELECT_TEXT} selects text (double
 * click selects a word, right click offers copy/select all) and
 * {@link Tool#ZOOM_TO_SELECTION} zooms so the dragged rectangle fills the
 * viewport (Shift+drag does this with any tool; a click zooms one step).
 * {@link #zoomTo(int, Rectangle2D)} and {@link #select(int, int, int, int)} /
 * {@link #getSelectedText()} are the programmatic forms.
 *
 * <h2>Search</h2>
 * {@link #search(String)} returns {@link Match}es with glyph rectangles;
 * {@link #setHighlights(List)} paints them over the pages (current match in a
 * stronger color) and {@link #nextMatch()}/{@link #previousMatch()} step through
 * them. {@link #highlightAsync(String, Consumer)} does search + highlight off the
 * EDT, which is what the toolbar search field uses. {@link #openFile()} shows a
 * PDF file chooser (toolbar "Open" button); {@link #saveAs()} / {@link #save(File)}
 * write the current document out (toolbar "Save" button); {@link #print()} shows
 * the system print dialog and prints off the EDT (toolbar "Print" button).
 *
 * <h2>Threading</h2>
 * Like any Swing component the public API must be called on the EDT, except
 * {@link #find(String)} and {@link #search(String)} which block and may be
 * called from a worker thread. PDFBox documents are not thread-safe; all
 * document access is serialized.
 *
 * <h2>Usage</h2>
 * <pre>{@code
 * PDFViewerPanel viewer = new PDFViewerPanel();
 * viewer.setPDF(MDToPDF.mdToPDF("# Hello").toByteArray());
 * frame.add(viewer);
 * }</pre>
 */
public class PDFViewerPanel extends JPanel {

    /** How the zoom factor is determined. */
    public enum ZoomMode {
        /** Fixed factor set via {@link #setZoom(float)}. */
        CUSTOM,
        /** Widest page fills the viewport width. */
        FIT_WIDTH,
        /** Whole page visible (width and height). */
        FIT_PAGE
    }

    /** What a plain left-button drag over the pages does. */
    public enum Tool {
        /** Drag scrolls the view. */
        PAN,
        /** Drag selects text; Ctrl+C / right click copies it. */
        SELECT_TEXT,
        /** Drag a rectangle to zoom so it fills the viewport. */
        ZOOM_TO_SELECTION
    }

    /** Fill color of the text selection. */
    public static final Color SELECTION_COLOR = new Color(40, 110, 220, 80);

    /** Notified when the page under the viewport changes or a document is (un)loaded. */
    @FunctionalInterface
    public interface PageChangeListener {
        /**
         * @param page      zero-based current page, -1 when no document is loaded
         * @param pageCount number of pages, 0 when no document is loaded
         */
        void pageChanged(int page, int pageCount);
    }

    /**
     * One search hit: the page, the character range in that page's extracted
     * text and the glyph rectangles covering it (one per text line), in PDF
     * points with the origin at the page's top-left corner.
     */
    public static final class Match {
        private final int page;
        private final int start;
        private final int end;
        private final List<Rectangle2D.Float> rects;

        Match(int page, int start, int end, List<Rectangle2D.Float> rects) {
            this.page = page;
            this.start = start;
            this.end = end;
            this.rects = Collections.unmodifiableList(rects);
        }

        /** @return zero-based page index */
        public int getPage() {
            return page;
        }

        /** @return start offset (inclusive) in the page text */
        public int getStart() {
            return start;
        }

        /** @return end offset (exclusive) in the page text */
        public int getEnd() {
            return end;
        }

        /** @return glyph rectangles in points, top-left origin, one per line */
        public List<Rectangle2D.Float> getRects() {
            return rects;
        }

        @Override
        public String toString() {
            return "Match{page=" + page + ", " + start + "-" + end + ", rects=" + rects.size() + "}";
        }
    }

    /** Fill color of search highlights. */
    public static final Color HIGHLIGHT_COLOR = new Color(255, 230, 0, 100);
    /** Fill color of the current search highlight. */
    public static final Color CURRENT_HIGHLIGHT_COLOR = new Color(255, 140, 0, 150);

    /** Default cache budget for rendered page images. */
    public static final long DEFAULT_CACHE_BYTES = 64L * 1024 * 1024;
    /** Smallest zoom factor. */
    public static final float MIN_ZOOM = 0.1f;
    /** Largest zoom factor. */
    public static final float MAX_ZOOM = 8f;

    private static final int PAGE_GAP = 12;
    private static final int PAGE_MARGIN = 10;
    private static final float ZOOM_STEP = 1.2f;
    private static final float[] ZOOM_PRESETS = {0.5f, 0.75f, 1f, 1.25f, 1.5f, 2f, 3f};
    private static final String FIT_WIDTH_LABEL = "Fit width";
    private static final String FIT_PAGE_LABEL = "Fit page";

    /** One shared daemon thread renders for every viewer; document access is serialized anyway. */
    private static final ExecutorService RENDER_EXECUTOR = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "PDFViewerPanel-render");
        t.setDaemon(true);
        return t;
    });

    private final Object docLock = new Object();
    private PDDocument document;
    private boolean ownsDocument;
    private PDFRenderer renderer;
    /** Per page extracted text, filled lazily (under docLock); volatile so painting can peek without the lock. */
    private volatile PageText[] pageTexts;

    private final PagesPanel pagesPanel = new PagesPanel();
    private final List<PageView> pages = new ArrayList<>();
    private final PageCache cache = new PageCache(DEFAULT_CACHE_BYTES);
    private final AtomicInteger generation = new AtomicInteger();
    private final List<PageChangeListener> listeners = new CopyOnWriteArrayList<>();

    private JScrollPane scrollPane;
    private JToolBar toolbar;
    private JTextField pageField;
    private JLabel pageCountLabel;
    private JComboBox<String> zoomCombo;
    private JTextField searchField;
    private JLabel matchLabel;
    private JButton saveButton;
    private JButton printButton;
    private JToggleButton panButton;
    private JToggleButton selectButton;
    private JToggleButton zoomSelectButton;
    private JButton copyButton;
    private JPopupMenu selectionMenu;
    private Tool tool = Tool.PAN;
    /** Text selection, normalized (start before end); start page -1 when empty. Indexes are clamped on use. EDT only. */
    private int selStartPage = -1, selStartIdx, selEndPage = -1, selEndIdx;
    /** Selection anchor while dragging: {page, index}; null when idle. */
    private int[] selAnchor;
    /** Rubber band being dragged, in pages panel coordinates; null when idle. */
    private Rectangle marquee;
    private boolean updatingToolbar;
    private JFileChooser fileChooser;
    private File currentFile;

    /** Highlighted matches, EDT only. */
    private List<Match> matches = new ArrayList<>();
    private int currentMatch = -1;
    private String lastQuery;

    private float zoom = 1f;
    private ZoomMode zoomMode = ZoomMode.FIT_WIDTH;
    private int currentPage = -1;

    /**
     * Creates an empty viewer with the toolbar visible.
     */
    public PDFViewerPanel() {
        this(true);
    }

    /**
     * Creates an empty viewer.
     *
     * @param toolbarVisible whether the navigation/zoom toolbar is shown
     */
    public PDFViewerPanel(boolean toolbarVisible) {
        setLayout(new BorderLayout());
        scrollPane = new JScrollPane(pagesPanel);
        scrollPane.getVerticalScrollBar().setUnitIncrement(20);
        scrollPane.getHorizontalScrollBar().setUnitIncrement(20);
        scrollPane.getViewport().addChangeListener(this::onViewportChanged);
        scrollPane.getViewport().addComponentListener(new ComponentAdapter() {
            @Override
            public void componentResized(ComponentEvent e) {
                if (zoomMode != ZoomMode.CUSTOM)
                    applyZoomMode();
            }
        });
        add(scrollPane, BorderLayout.CENTER);

        toolbar = buildToolbar();
        add(toolbar, BorderLayout.NORTH);
        toolbar.setVisible(toolbarVisible);

        installInputHandlers();
        applyTheme();
        updateToolbar();
    }

    // ------------------------------------------------------------------ loading

    /**
     * Parses the PDF bytes off the EDT and shows the document once ready.
     *
     * @param pdf the PDF content, never null
     */
    public void setPDF(byte[] pdf) {
        SUS.checkIfNull("pdf null", pdf);
        BackgroundTask.run(this, null, () -> Loader.loadPDF(pdf), doc -> setDocument(doc, true));
    }

    /**
     * Parses the PDF file off the EDT and shows the document once ready.
     *
     * @param pdf the PDF file, never null
     */
    public void setPDF(File pdf) {
        SUS.checkIfNull("pdf null", pdf);
        BackgroundTask.run(this, null, () -> Loader.loadPDF(pdf), doc -> install(doc, true, pdf));
    }

    /**
     * Reads the stream fully, parses it off the EDT and shows the document once
     * ready. The stream is closed.
     *
     * @param pdf the PDF content, never null
     */
    public void setPDF(InputStream pdf) {
        SUS.checkIfNull("pdf null", pdf);
        BackgroundTask.run(this, null,
                () -> Loader.loadPDF(IOUtil.inputStreamToByteArray(pdf, true).toByteArray()),
                doc -> setDocument(doc, true));
    }

    /**
     * Installs an already parsed document, replacing (and closing, if owned) the
     * current one. Must be called on the EDT.
     *
     * @param doc          the document, null clears the viewer
     * @param ownsDocument if true the viewer closes {@code doc} when it is replaced or
     *                     {@link #close()} is called
     * @return this panel, for chaining
     */
    public PDFViewerPanel setDocument(PDDocument doc, boolean ownsDocument) {
        return install(doc, ownsDocument, null);
    }

    /** Installs {@code doc}, remembering {@code file} as its origin (null when not file-backed). */
    private PDFViewerPanel install(PDDocument doc, boolean ownsDocument, File file) {
        close();
        currentFile = file;
        if (doc == null)
            return this;

        synchronized (docLock) {
            document = doc;
            this.ownsDocument = ownsDocument;
            renderer = new PDFRenderer(doc);
            renderer.setSubsamplingAllowed(true);
            pageTexts = new PageText[doc.getNumberOfPages()];
            for (int i = 0; i < doc.getNumberOfPages(); i++)
                pages.add(new PageView(i, doc.getPage(i)));
        }
        pagesPanel.rebuild();
        currentPage = pages.isEmpty() ? -1 : 0;
        if (zoomMode == ZoomMode.CUSTOM)
            applyZoom(zoom, null, null);
        else
            applyZoomMode();
        scrollPane.getViewport().setViewPosition(new Point(0, 0));
        updateToolbar();
        firePageChanged();
        updateVisiblePages();
        return this;
    }

    /**
     * Releases the current document (closing it if owned), cancels pending renders
     * and clears the view. Safe to call repeatedly; the panel can load a new
     * document afterwards.
     */
    public void close() {
        generation.incrementAndGet();
        synchronized (docLock) {
            if (document != null && ownsDocument) {
                try {
                    document.close();
                } catch (IOException e) {
                    // nothing useful to do, the document is being discarded
                }
            }
            document = null;
            renderer = null;
            pageTexts = null;
        }
        cache.clear();
        pages.clear();
        pagesPanel.rebuild();
        currentPage = -1;
        currentFile = null;
        matches = new ArrayList<>();
        currentMatch = -1;
        lastQuery = null;
        selStartPage = selEndPage = -1;
        selAnchor = null;
        updateToolbar();
        firePageChanged();
    }

    /**
     * Shows a PDF file chooser and loads the selected file via {@link #setPDF(File)}.
     *
     * @return the chosen file, or null if the dialog was cancelled
     */
    public File openFile() {
        JFileChooser fc = fileChooser();
        fc.setDialogTitle("Open PDF");
        if (fc.showOpenDialog(this) != JFileChooser.APPROVE_OPTION)
            return null;
        File f = fc.getSelectedFile();
        setPDF(f);
        return f;
    }

    /**
     * @return the file the current document was loaded from via {@link #setPDF(File)}
     *         or {@link #openFile()}, null for documents from bytes/streams or when empty
     */
    public File getFile() {
        return currentFile;
    }

    /**
     * Shows a "Save PDF" file chooser (pre-filled with the current file name) and
     * writes the document there via {@link #save(File)}; asks before overwriting.
     *
     * @return the chosen file, or null if nothing is loaded or the dialog was cancelled
     */
    public File saveAs() {
        if (getDocument() == null)
            return null;
        JFileChooser fc = fileChooser();
        fc.setDialogTitle("Save PDF");
        fc.setSelectedFile(currentFile != null ? currentFile : new File(fc.getCurrentDirectory(), "document.pdf"));
        if (fc.showSaveDialog(this) != JFileChooser.APPROVE_OPTION)
            return null;
        File f = fc.getSelectedFile();
        if (!f.getName().toLowerCase().endsWith(".pdf"))
            f = new File(f.getParentFile(), f.getName() + ".pdf");
        if (f.exists() && !f.equals(currentFile)) {
            int choice = JOptionPane.showConfirmDialog(this, f.getName() + " exists. Overwrite?",
                    "Save PDF", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
            if (choice != JOptionPane.YES_OPTION)
                return null;
        }
        save(f);
        return f;
    }

    /**
     * Writes the current document to {@code target} off the EDT (error dialog on
     * failure). Saving over the file the document was loaded from is supported:
     * the document is written to a temporary file first, then closed, the file
     * replaced and reloaded, so the page is kept but highlights are cleared.
     * Must be called on the EDT.
     *
     * @param target the file to write, never null
     */
    public void save(File target) {
        SUS.checkIfNull("target null", target);
        if (getDocument() == null)
            return;
        final boolean overSource = currentFile != null && target.getAbsoluteFile().equals(currentFile.getAbsoluteFile());
        final int page = currentPage;
        BackgroundTask.run(this, saveButton, () -> {
            File dir = target.getAbsoluteFile().getParentFile();
            File tmp = File.createTempFile("pdfviewer", ".pdf", dir != null && dir.isDirectory() ? dir : null);
            boolean ok = false;
            try {
                synchronized (docLock) {
                    if (document == null)
                        throw new IOException("no document loaded");
                    document.save(tmp);
                }
                if (!overSource)
                    Files.move(tmp.toPath(), target.toPath(), StandardCopyOption.REPLACE_EXISTING);
                ok = true;
            } finally {
                if (!ok || !overSource)
                    tmp.delete();
            }
            return tmp;
        }, tmp -> {
            if (!overSource) {
                currentFile = target;
                return;
            }
            // release the source before replacing it, then reload from the new content
            close();
            try {
                Files.move(tmp.toPath(), target.toPath(), StandardCopyOption.REPLACE_EXISTING);
            } catch (IOException e) {
                tmp.delete();
                JOptionPane.showMessageDialog(this, "Unexpected error: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
            BackgroundTask.run(this, saveButton, () -> Loader.loadPDF(target), doc -> {
                install(doc, true, target);
                gotoPage(page);
            });
        });
    }

    /**
     * Shows the system print dialog for the current document and, if confirmed,
     * prints it off the EDT (error dialog on failure). Pages are scaled to the
     * printable area by PDFBox's {@link PDFPageable}. Must be called on the EDT.
     *
     * @return true if a print job was started, false if nothing is loaded or the
     *         dialog was cancelled
     */
    public boolean print() {
        Pageable pageable = createPageable();
        if (pageable == null)
            return false;
        PrinterJob job = PrinterJob.getPrinterJob();
        job.setJobName(currentFile != null ? currentFile.getName() : "PDF");
        job.setPageable(pageable);
        if (!job.printDialog())
            return false;
        BackgroundTask.run(this, printButton, () -> {
            job.print(); // each page locks the document via the pageable
            return null;
        }, v -> {
        });
        return true;
    }

    /**
     * Creates a {@link Pageable} over the current document for hosts that run
     * their own print flow (e.g. a preset {@link PrinterJob} without a dialog).
     * Each page is printed while holding the document lock, so printing never
     * overlaps with the background page renderer; after {@link #close()} the
     * pageable reports {@link java.awt.print.Printable#NO_SUCH_PAGE}.
     *
     * @return the pageable, or null if nothing is loaded
     */
    public Pageable createPageable() {
        final PDDocument doc;
        final PDFPageable delegate;
        synchronized (docLock) {
            if (document == null)
                return null;
            doc = document;
            delegate = new PDFPageable(document);
        }
        return new Pageable() {
            @Override
            public int getNumberOfPages() {
                return delegate.getNumberOfPages();
            }

            @Override
            public java.awt.print.PageFormat getPageFormat(int pageIndex) {
                return delegate.getPageFormat(pageIndex);
            }

            @Override
            public java.awt.print.Printable getPrintable(int pageIndex) {
                java.awt.print.Printable printable = delegate.getPrintable(pageIndex);
                return (graphics, pageFormat, index) -> {
                    synchronized (docLock) {
                        if (document != doc)
                            return java.awt.print.Printable.NO_SUCH_PAGE;
                        return printable.print(graphics, pageFormat, index);
                    }
                };
            }
        };
    }

    private JFileChooser fileChooser() {
        if (fileChooser == null) {
            fileChooser = new JFileChooser();
            fileChooser.setFileFilter(new FileNameExtensionFilter("PDF files (*.pdf)", "pdf"));
        }
        if (currentFile != null)
            fileChooser.setCurrentDirectory(currentFile.getAbsoluteFile().getParentFile());
        return fileChooser;
    }

    /**
     * @return the loaded document, or null; do not close it, the viewer owns its lifecycle
     */
    public PDDocument getDocument() {
        synchronized (docLock) {
            return document;
        }
    }

    // --------------------------------------------------------------- navigation

    /**
     * @return number of pages, 0 when no document is loaded
     */
    public int getPageCount() {
        return pages.size();
    }

    /**
     * @return zero-based page currently under the viewport, -1 when empty
     */
    public int getCurrentPage() {
        return currentPage;
    }

    /**
     * Scrolls so the given page starts at the top of the viewport. Out of range
     * values are clamped.
     *
     * @param page zero-based page index
     * @return this panel, for chaining
     */
    public PDFViewerPanel gotoPage(int page) {
        if (pages.isEmpty())
            return this;
        page = Math.max(0, Math.min(pages.size() - 1, page));
        layoutPages();
        Point view = scrollPane.getViewport().getViewPosition();
        scrollPane.getViewport().setViewPosition(new Point(view.x, Math.max(0, pages.get(page).getY() - PAGE_GAP / 2)));
        setCurrentPage(page);
        return this;
    }

    /** Goes to the next page. @return this panel */
    public PDFViewerPanel nextPage() {
        return gotoPage(currentPage + 1);
    }

    /** Goes to the previous page. @return this panel */
    public PDFViewerPanel previousPage() {
        return gotoPage(currentPage - 1);
    }

    /**
     * @param listener notified of page changes and document (un)loads, never null
     * @return this panel, for chaining
     */
    public PDFViewerPanel addPageChangeListener(PageChangeListener listener) {
        SUS.checkIfNull("listener null", listener);
        listeners.add(listener);
        return this;
    }

    /**
     * @param listener the listener to remove
     * @return this panel, for chaining
     */
    public PDFViewerPanel removePageChangeListener(PageChangeListener listener) {
        listeners.remove(listener);
        return this;
    }

    // --------------------------------------------------------------------- zoom

    /**
     * @return the current zoom factor (1 = 72 dpi)
     */
    public float getZoom() {
        return zoom;
    }

    /**
     * @return the current zoom mode
     */
    public ZoomMode getZoomMode() {
        return zoomMode;
    }

    /**
     * Sets a fixed zoom factor (switches to {@link ZoomMode#CUSTOM}). Clamped to
     * [{@link #MIN_ZOOM}, {@link #MAX_ZOOM}]. The page under the viewport is kept in view.
     *
     * @param zoom the factor, 1 = 72 dpi
     * @return this panel, for chaining
     */
    public PDFViewerPanel setZoom(float zoom) {
        zoomMode = ZoomMode.CUSTOM;
        applyZoom(zoom, null, null);
        updateToolbar();
        return this;
    }

    /**
     * Sets the zoom mode; fit modes recompute the factor now and on every resize.
     *
     * @param mode the mode, never null
     * @return this panel, for chaining
     */
    public PDFViewerPanel setZoomMode(ZoomMode mode) {
        SUS.checkIfNull("mode null", mode);
        zoomMode = mode;
        if (mode == ZoomMode.CUSTOM)
            applyZoom(zoom, null, null);
        else
            applyZoomMode();
        updateToolbar();
        return this;
    }

    /** Zooms in one step. @return this panel */
    public PDFViewerPanel zoomIn() {
        return setZoom(zoom * ZOOM_STEP);
    }

    /** Zooms out one step. @return this panel */
    public PDFViewerPanel zoomOut() {
        return setZoom(zoom / ZOOM_STEP);
    }

    /** Fits the widest page to the viewport width. @return this panel */
    public PDFViewerPanel fitWidth() {
        return setZoomMode(ZoomMode.FIT_WIDTH);
    }

    /** Fits the largest page entirely into the viewport. @return this panel */
    public PDFViewerPanel fitPage() {
        return setZoomMode(ZoomMode.FIT_PAGE);
    }

    /**
     * Turns "zoom to selection" mode on or off. While on, dragging a rectangle
     * over the pages zooms so it fills the viewport (instead of panning) and a
     * click zooms in one step around the pointer. The mode stays on until turned
     * off (toolbar toggle or Esc). Shift+drag does the same without the mode.
     *
     * @param on whether the mode is active
     * @return this panel, for chaining
     */
    public PDFViewerPanel setZoomToSelectionMode(boolean on) {
        return setTool(on ? Tool.ZOOM_TO_SELECTION : Tool.PAN);
    }

    /**
     * @return whether "zoom to selection" mode is active
     */
    public boolean isZoomToSelectionMode() {
        return tool == Tool.ZOOM_TO_SELECTION;
    }

    /**
     * Selects what a plain drag does (see {@link Tool}); the toolbar toggles mirror it.
     *
     * @param tool the tool, never null
     * @return this panel, for chaining
     */
    public PDFViewerPanel setTool(Tool tool) {
        SUS.checkIfNull("tool null", tool);
        this.tool = tool;
        pagesPanel.setCursor(cursorFor(tool));
        JToggleButton b = tool == Tool.PAN ? panButton : tool == Tool.SELECT_TEXT ? selectButton : zoomSelectButton;
        if (b != null && !b.isSelected())
            b.setSelected(true);
        return this;
    }

    /**
     * @return the active tool
     */
    public Tool getTool() {
        return tool;
    }

    private static Cursor cursorFor(Tool tool) {
        switch (tool) {
            case SELECT_TEXT:
                return Cursor.getPredefinedCursor(Cursor.TEXT_CURSOR);
            case ZOOM_TO_SELECTION:
                return Cursor.getPredefinedCursor(Cursor.CROSSHAIR_CURSOR);
            default:
                return Cursor.getDefaultCursor();
        }
    }

    /**
     * Scrolls the view by the given amount, clamped to the content. Page Up/Down
     * scroll by a viewport height this way.
     *
     * @param dx horizontal pixels (positive = right)
     * @param dy vertical pixels (positive = down)
     * @return this panel, for chaining
     */
    public PDFViewerPanel scrollBy(int dx, int dy) {
        JViewport vp = scrollPane.getViewport();
        Point pos = vp.getViewPosition();
        int maxX = Math.max(0, pagesPanel.getWidth() - vp.getWidth());
        int maxY = Math.max(0, pagesPanel.getHeight() - vp.getHeight());
        pos.x = Math.max(0, Math.min(maxX, pos.x + dx));
        pos.y = Math.max(0, Math.min(maxY, pos.y + dy));
        vp.setViewPosition(pos);
        return this;
    }

    // ---------------------------------------------------------- text selection

    /**
     * @return whether some text is selected
     */
    public boolean hasSelection() {
        return selStartPage >= 0;
    }

    /** Clears the text selection. @return this panel */
    public PDFViewerPanel clearSelection() {
        selStartPage = selEndPage = -1;
        selStartIdx = selEndIdx = 0;
        pagesPanel.repaint();
        updateToolbar();
        return this;
    }

    /**
     * Selects the text between two positions given as page index plus character
     * offset into that page's extracted text (see {@link #charIndexAt(int, float, float)}).
     * The two ends may be given in either order; offsets are clamped to the page
     * text. An empty range clears the selection.
     *
     * @param startPage  zero-based page of one end
     * @param startIndex character offset of that end
     * @param endPage    zero-based page of the other end
     * @param endIndex   character offset of that end ({@code Integer.MAX_VALUE} = end of page)
     * @return this panel, for chaining
     */
    public PDFViewerPanel select(int startPage, int startIndex, int endPage, int endIndex) {
        if (pages.isEmpty())
            return clearSelection();
        int last = pages.size() - 1;
        startPage = Math.max(0, Math.min(last, startPage));
        endPage = Math.max(0, Math.min(last, endPage));
        startIndex = Math.max(0, startIndex);
        endIndex = Math.max(0, endIndex);
        if (endPage < startPage || (endPage == startPage && endIndex < startIndex)) {
            int p = startPage, i = startIndex;
            startPage = endPage;
            startIndex = endIndex;
            endPage = p;
            endIndex = i;
        }
        if (startPage == endPage && startIndex == endIndex)
            return clearSelection();
        selStartPage = startPage;
        selStartIdx = startIndex;
        selEndPage = endPage;
        selEndIdx = endIndex;
        pagesPanel.repaint();
        updateToolbar();
        return this;
    }

    /** Selects the text of every page. @return this panel */
    public PDFViewerPanel selectAll() {
        if (pages.isEmpty())
            return this;
        return select(0, 0, pages.size() - 1, Integer.MAX_VALUE);
    }

    /**
     * Returns the selected text, pages joined by a blank line. Extracts text for
     * the selected pages on first use, so this may block briefly.
     *
     * @return the selected text, empty when nothing is selected
     */
    public String getSelectedText() {
        if (!hasSelection())
            return "";
        StringBuilder sb = new StringBuilder();
        for (int p = selStartPage; p <= selEndPage; p++) {
            PageText pt = ensurePageText(p);
            if (pt == null)
                continue;
            int len = pt.text.length();
            int s = Math.min(len, p == selStartPage ? selStartIdx : 0);
            int e = Math.min(len, p == selEndPage ? selEndIdx : len);
            if (e <= s)
                continue;
            if (sb.length() > 0)
                sb.append("\n\n");
            sb.append(pt.text, s, e);
        }
        return sb.toString();
    }

    /**
     * Copies the selected text to the system clipboard.
     *
     * @return true if something was copied
     */
    public boolean copySelection() {
        String text = getSelectedText();
        if (text.isEmpty())
            return false;
        GUIUtil.copyToClipboard(text);
        return true;
    }

    /**
     * Maps a point on a page to a character offset in that page's extracted
     * text: the character under the point, else the nearest one on the closest
     * line (before the line for points left of it, after it for points right of
     * it); above the first line gives 0, below the last line the text length.
     *
     * @param page zero-based page index
     * @param xPt  x in PDF points from the page's left edge
     * @param yPt  y in PDF points from the page's top edge
     * @return the character offset, or -1 if the page is out of range or has no text
     */
    public int charIndexAt(int page, float xPt, float yPt) {
        PageText pt = ensurePageText(page);
        return pt == null ? -1 : pt.hit(xPt, yPt);
    }

    /** Extracts (once) and returns the page text; null when nothing is loaded, out of range or extraction fails. */
    private PageText ensurePageText(int page) {
        synchronized (docLock) {
            PageText[] texts = pageTexts;
            if (document == null || texts == null || page < 0 || page >= texts.length)
                return null;
            if (texts[page] == null) {
                try {
                    texts[page] = PageText.extract(document, page);
                } catch (IOException e) {
                    return null;
                }
            }
            return texts[page];
        }
    }

    /** Lock-free peek for painting: the page text if already extracted, else null. */
    private PageText pageTextIfExtracted(int page) {
        PageText[] texts = pageTexts;
        return texts != null && page >= 0 && page < texts.length ? texts[page] : null;
    }

    /** {page, index} under a pages-panel point (nearest page/char), null when empty. */
    private int[] hitTest(Point p) {
        PageView pv = nearestPage(p.y);
        if (pv == null)
            return null;
        int idx = charIndexAt(pv.index, (p.x - pv.getX()) / zoom, (p.y - pv.getY()) / zoom);
        return idx < 0 ? null : new int[]{pv.index, idx};
    }

    private void selectWordAt(int page, int index) {
        PageText pt = ensurePageText(page);
        if (pt == null || pt.text.isEmpty())
            return;
        String t = pt.text;
        int s = Math.min(index, t.length()), e = s;
        while (s > 0 && Character.isLetterOrDigit(t.charAt(s - 1)))
            s--;
        while (e < t.length() && Character.isLetterOrDigit(t.charAt(e)))
            e++;
        if (e > s)
            select(page, s, page, e);
    }

    private void showSelectionMenu(MouseEvent e) {
        if (selectionMenu == null) {
            selectionMenu = new JPopupMenu();
            JMenuItem copy = new JMenuItem("Copy");
            copy.addActionListener(a -> copySelection());
            selectionMenu.add(copy);
            JMenuItem all = new JMenuItem("Select all");
            all.addActionListener(a -> selectAll());
            selectionMenu.add(all);
            JMenuItem clear = new JMenuItem("Clear selection");
            clear.addActionListener(a -> clearSelection());
            selectionMenu.add(clear);
        }
        selectionMenu.getComponent(0).setEnabled(hasSelection());
        selectionMenu.getComponent(2).setEnabled(hasSelection());
        selectionMenu.getComponent(1).setEnabled(!pages.isEmpty());
        selectionMenu.show(pagesPanel, e.getX(), e.getY());
    }

    /**
     * Zooms so that the given area of a page fills the viewport (switches to
     * {@link ZoomMode#CUSTOM}) and centers it. Useful for zooming to a search
     * {@link Match} rectangle.
     *
     * @param page zero-based page index
     * @param area rectangle in PDF points, origin at the page's top-left corner
     * @return this panel, for chaining
     */
    public PDFViewerPanel zoomTo(int page, Rectangle2D area) {
        SUS.checkIfNull("area null", area);
        if (page < 0 || page >= pages.size())
            return this;
        PageView pv = pages.get(page);
        layoutPages();
        Rectangle r = new Rectangle(
                pv.getX() + Math.round((float) area.getX() * zoom),
                pv.getY() + Math.round((float) area.getY() * zoom),
                Math.max(1, Math.round((float) area.getWidth() * zoom)),
                Math.max(1, Math.round((float) area.getHeight() * zoom)));
        return zoomToViewRect(r);
    }

    /**
     * Zooms so that {@code r}, given in pages-panel pixel coordinates at the
     * current zoom, fills the viewport and is centered.
     */
    private PDFViewerPanel zoomToViewRect(Rectangle r) {
        if (pages.isEmpty() || r.width <= 0 || r.height <= 0)
            return this;
        JViewport vp = scrollPane.getViewport();
        int vw = vp.getWidth(), vh = vp.getHeight();
        if (vw <= 0 || vh <= 0)
            return this;
        float factor = Math.min((float) vw / r.width, (float) vh / r.height);
        zoomMode = ZoomMode.CUSTOM;
        Point center = new Point(r.x + r.width / 2, r.y + r.height / 2);
        applyZoom(zoom * factor, center, new Point(vw / 2, vh / 2));
        updateToolbar();
        return this;
    }

    /**
     * Sets the byte budget of the rendered page cache; exceeding it evicts the
     * least recently painted pages.
     *
     * @param bytes the budget, must be positive
     * @return this panel, for chaining
     */
    public PDFViewerPanel setCacheBytes(long bytes) {
        if (bytes <= 0)
            throw new IllegalArgumentException("cache bytes must be positive");
        cache.setMaxBytes(bytes);
        return this;
    }

    /**
     * @return number of page images currently cached
     */
    public int getCachedPageCount() {
        return cache.size();
    }

    /**
     * Returns the rendered image of a page if it is currently cached (it is
     * rendered lazily when scrolled into view). Do not modify the image.
     *
     * @param page zero-based page index
     * @return the cached image, or null if the page has not been rendered
     */
    public BufferedImage getPageImage(int page) {
        PageCache.Entry e = cache.get(page);
        return e != null ? e.image : null;
    }

    // ------------------------------------------------------------------- search

    /**
     * Returns the zero-based pages whose text contains {@code text}
     * (case-insensitive). Blocks while extracting; safe to call from a worker
     * thread. Does not change the highlights.
     *
     * @param text the text to look for, null or empty matches nothing
     * @return the matching pages, never null
     * @throws IOException if text extraction fails
     */
    public List<Integer> find(String text) throws IOException {
        List<Integer> ret = new ArrayList<>();
        for (Match m : search(text))
            if (ret.isEmpty() || ret.get(ret.size() - 1) != m.page)
                ret.add(m.page);
        return ret;
    }

    /**
     * Finds every occurrence of {@code text} (case-insensitive) with the glyph
     * rectangles covering it. Text and glyph positions are extracted on first
     * use and cached per page. Blocks while extracting; safe to call from a
     * worker thread. Does not change the highlights.
     *
     * @param text the text to look for, null or empty matches nothing
     * @return the matches in document order, never null
     * @throws IOException if text extraction fails
     */
    public List<Match> search(String text) throws IOException {
        List<Match> ret = new ArrayList<>();
        if (text == null || text.isEmpty())
            return ret;
        String needle = lower(text);
        synchronized (docLock) {
            PageText[] texts = pageTexts;
            if (document == null || texts == null)
                return ret;
            for (int i = 0; i < texts.length; i++) {
                if (texts[i] == null)
                    texts[i] = PageText.extract(document, i);
                texts[i].search(i, needle, ret);
            }
        }
        return ret;
    }

    /**
     * Runs {@link #find(String)} on the render thread and delivers the result on
     * the EDT.
     *
     * @param text   the text to look for
     * @param onDone receives the matching pages on the EDT, never null
     */
    public void findAsync(String text, Consumer<List<Integer>> onDone) {
        SUS.checkIfNull("onDone null", onDone);
        RENDER_EXECUTOR.submit(() -> {
            List<Integer> result;
            try {
                result = find(text);
            } catch (IOException e) {
                result = new ArrayList<>();
            }
            List<Integer> r = result;
            SwingUtilities.invokeLater(() -> onDone.accept(r));
        });
    }

    /**
     * Runs {@link #search(String)} on the render thread, then installs the result
     * as highlights (scrolling to the first match) and reports it on the EDT.
     *
     * @param text   the text to look for
     * @param onDone receives the matches on the EDT, may be null
     */
    public void highlightAsync(String text, Consumer<List<Match>> onDone) {
        RENDER_EXECUTOR.submit(() -> {
            List<Match> result;
            try {
                result = search(text);
            } catch (IOException e) {
                result = new ArrayList<>();
            }
            List<Match> r = result;
            SwingUtilities.invokeLater(() -> {
                lastQuery = text;
                setHighlights(r);
                if (onDone != null)
                    onDone.accept(r);
            });
        });
    }

    /**
     * Paints the given matches over the pages and scrolls to the first one.
     * Must be called on the EDT.
     *
     * @param found matches from {@link #search(String)}, null or empty clears the highlights
     * @return this panel, for chaining
     */
    public PDFViewerPanel setHighlights(List<Match> found) {
        matches = found == null ? new ArrayList<>() : new ArrayList<>(found);
        currentMatch = -1;
        pagesPanel.repaint();
        if (!matches.isEmpty())
            gotoMatch(0);
        else
            updateToolbar();
        return this;
    }

    /** Removes all highlights. @return this panel */
    public PDFViewerPanel clearHighlights() {
        lastQuery = null;
        return setHighlights(null);
    }

    /**
     * @return the highlighted matches, never null, read-only
     */
    public List<Match> getHighlights() {
        return Collections.unmodifiableList(matches);
    }

    /**
     * @return index into {@link #getHighlights()} of the current match, -1 if none
     */
    public int getCurrentMatch() {
        return currentMatch;
    }

    /**
     * Makes the given match current and scrolls it into view (upper third of the
     * viewport). Out of range values wrap around.
     *
     * @param index index into {@link #getHighlights()}
     * @return this panel, for chaining
     */
    public PDFViewerPanel gotoMatch(int index) {
        if (matches.isEmpty())
            return this;
        int n = matches.size();
        index = ((index % n) + n) % n;
        currentMatch = index;
        Match m = matches.get(index);
        if (m.page >= 0 && m.page < pages.size()) {
            layoutPages();
            PageView pv = pages.get(m.page);
            JViewport vp = scrollPane.getViewport();
            Point view = vp.getViewPosition();
            Rectangle2D.Float first = m.rects.isEmpty() ? new Rectangle2D.Float() : m.rects.get(0);
            int y = pv.getY() + Math.round(first.y * zoom) - vp.getHeight() / 3;
            int maxY = Math.max(0, pagesPanel.getPreferredSize().height - vp.getHeight());
            vp.setViewPosition(new Point(view.x, Math.max(0, Math.min(maxY, y))));
            setCurrentPage(m.page);
        }
        updateToolbar();
        pagesPanel.repaint();
        return this;
    }

    /** Steps to the next match (wraps). @return this panel */
    public PDFViewerPanel nextMatch() {
        return gotoMatch(currentMatch + 1);
    }

    /** Steps to the previous match (wraps). @return this panel */
    public PDFViewerPanel previousMatch() {
        return gotoMatch(currentMatch - 1);
    }

    /** Lowercases char by char so offsets stay aligned with the original. */
    private static String lower(String s) {
        char[] c = s.toCharArray();
        for (int i = 0; i < c.length; i++)
            c[i] = Character.toLowerCase(c[i]);
        return new String(c);
    }

    // ------------------------------------------------------------------ toolbar

    /**
     * @param visible whether the toolbar is shown
     * @return this panel, for chaining
     */
    public PDFViewerPanel setToolbarVisible(boolean visible) {
        toolbar.setVisible(visible);
        return this;
    }

    /**
     * @return the toolbar, so callers can add their own controls
     */
    public JToolBar getToolbar() {
        return toolbar;
    }

    /**
     * Replaces the internal scroll pane, e.g. to customize scroll bar policies
     * or borders. Must be called on the EDT.
     *
     * @param external the replacement scroll pane, never null
     * @return this panel, for chaining
     */
    public PDFViewerPanel overrideScrollPane(JScrollPane external) {
        SUS.checkIfNull("scrollPane null", external);
        remove(scrollPane);
        scrollPane = external;
        scrollPane.setViewportView(pagesPanel);
        scrollPane.getVerticalScrollBar().setUnitIncrement(20);
        scrollPane.getHorizontalScrollBar().setUnitIncrement(20);
        scrollPane.getViewport().addChangeListener(this::onViewportChanged);
        scrollPane.getViewport().addComponentListener(new ComponentAdapter() {
            @Override
            public void componentResized(ComponentEvent e) {
                if (zoomMode != ZoomMode.CUSTOM)
                    applyZoomMode();
            }
        });
        add(scrollPane, BorderLayout.CENTER);
        revalidate();
        repaint();
        return this;
    }

    @Override
    public void updateUI() {
        super.updateUI();
        if (pagesPanel != null)
            applyTheme();
    }

    // ================================================================ internals

    private JToolBar buildToolbar() {
        JToolBar tb = new JToolBar();
        tb.setFloatable(false);

        JButton open = GUIUtil.iconButton(new IconUtil.FolderIcon(16));
        open.setToolTipText("Open PDF file");
        open.addActionListener(e -> openFile());
        tb.add(open);
        saveButton = GUIUtil.iconButton(new IconUtil.SaveIcon(16));
        saveButton.setToolTipText("Save PDF as...");
        saveButton.addActionListener(e -> saveAs());
        tb.add(saveButton);
        printButton = GUIUtil.iconButton(new IconUtil.PrintIcon(16));
        printButton.setToolTipText("Print...");
        printButton.addActionListener(e -> print());
        tb.add(printButton);
        tb.addSeparator();

        JButton prev = GUIUtil.iconButton(new IconUtil.BackIcon(16));
        prev.setToolTipText("Previous page");
        prev.addActionListener(e -> previousPage());
        tb.add(prev);

        pageField = new JTextField(4);
        pageField.setHorizontalAlignment(JTextField.CENTER);
        pageField.setMaximumSize(pageField.getPreferredSize());
        pageField.addActionListener(e -> {
            try {
                gotoPage(Integer.parseInt(pageField.getText().trim()) - 1);
            } catch (NumberFormatException ex) {
                updateToolbar();
            }
        });
        tb.add(pageField);
        pageCountLabel = new JLabel(" / 0 ");
        tb.add(pageCountLabel);

        JButton next = GUIUtil.iconButton(new IconUtil.NextIcon(16));
        next.setToolTipText("Next page");
        next.addActionListener(e -> nextPage());
        tb.add(next);

        tb.addSeparator();

        JButton out = GUIUtil.iconButton(new IconUtil.MinusIcon(16));
        out.setToolTipText("Zoom out (Ctrl+-)");
        out.addActionListener(e -> zoomOut());
        tb.add(out);

        zoomCombo = new JComboBox<>();
        for (float z : ZOOM_PRESETS)
            zoomCombo.addItem(percent(z));
        zoomCombo.addItem(FIT_WIDTH_LABEL);
        zoomCombo.addItem(FIT_PAGE_LABEL);
        zoomCombo.setEditable(true);
        zoomCombo.setMaximumSize(new Dimension(110, zoomCombo.getPreferredSize().height));
        zoomCombo.addActionListener(e -> {
            if (updatingToolbar)
                return;
            Object sel = zoomCombo.getSelectedItem();
            if (sel == null)
                return;
            String s = sel.toString().trim();
            if (FIT_WIDTH_LABEL.equals(s))
                fitWidth();
            else if (FIT_PAGE_LABEL.equals(s))
                fitPage();
            else {
                try {
                    setZoom(Float.parseFloat(s.replace("%", "").trim()) / 100f);
                } catch (NumberFormatException ex) {
                    updateToolbar();
                }
            }
        });
        tb.add(zoomCombo);

        JButton in = GUIUtil.iconButton(new IconUtil.PlusIcon(16));
        in.setToolTipText("Zoom in (Ctrl++)");
        in.addActionListener(e -> zoomIn());
        tb.add(in);

        tb.addSeparator();

        ButtonGroup tools = new ButtonGroup();
        panButton = new JToggleButton(new IconUtil.PanIcon(16), true);
        panButton.setToolTipText("Pan: drag to scroll");
        panButton.addActionListener(e -> setTool(Tool.PAN));
        tools.add(panButton);
        tb.add(panButton);
        selectButton = new JToggleButton(new IconUtil.SelectIcon(16));
        selectButton.setToolTipText("Select text: drag to select, double click a word, Ctrl+C or right click to copy");
        selectButton.addActionListener(e -> setTool(Tool.SELECT_TEXT));
        tools.add(selectButton);
        tb.add(selectButton);
        zoomSelectButton = new JToggleButton(new IconUtil.AreaIcon(16));
        zoomSelectButton.setToolTipText("Zoom to selection: drag a rectangle (Shift+drag works with any tool, Esc exits)");
        zoomSelectButton.addActionListener(e -> setTool(Tool.ZOOM_TO_SELECTION));
        tools.add(zoomSelectButton);
        tb.add(zoomSelectButton);
        copyButton = GUIUtil.iconButton(new IconUtil.CopyIcon(16));
        copyButton.setToolTipText("Copy selected text (Ctrl+C)");
        copyButton.addActionListener(e -> copySelection());
        copyButton.setEnabled(false);
        tb.add(copyButton);

        tb.addSeparator();

        searchField = new JTextField(12);
        searchField.setToolTipText("Search (Enter: next, Shift+Enter: previous, Esc: clear)");
        searchField.setMaximumSize(new Dimension(160, searchField.getPreferredSize().height));
        searchField.addActionListener(e -> runSearch((e.getModifiers() & ActionEvent.SHIFT_MASK) != 0));
        searchField.getInputMap().put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), "clearSearch");
        searchField.getActionMap().put("clearSearch", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                searchField.setText("");
                clearHighlights();
            }
        });
        tb.add(searchField);
        JButton searchButton = GUIUtil.iconButton(new IconUtil.SearchIcon(16));
        searchButton.setToolTipText("Find next (Shift+click: previous)");
        searchButton.addActionListener(e -> runSearch((e.getModifiers() & ActionEvent.SHIFT_MASK) != 0));
        tb.add(searchButton);
        matchLabel = new JLabel(" ");
        tb.add(matchLabel);

        return tb;
    }

    /** Toolbar search: new query searches, repeated query steps through the matches. */
    private void runSearch(boolean backwards) {
        String q = searchField.getText();
        if (q.isEmpty()) {
            clearHighlights();
            return;
        }
        if (q.equals(lastQuery) && !matches.isEmpty()) {
            if (backwards)
                previousMatch();
            else
                nextMatch();
            return;
        }
        highlightAsync(q, null);
    }

    private static String percent(float zoom) {
        return Math.round(zoom * 100) + "%";
    }

    private void updateToolbar() {
        if (pageField == null)
            return;
        updatingToolbar = true;
        try {
            pageField.setText(currentPage >= 0 ? String.valueOf(currentPage + 1) : "");
            pageField.setEnabled(!pages.isEmpty());
            saveButton.setEnabled(!pages.isEmpty());
            printButton.setEnabled(!pages.isEmpty());
            if (copyButton != null)
                copyButton.setEnabled(hasSelection());
            pageCountLabel.setText(" / " + pages.size() + " ");
            if (matches.isEmpty())
                matchLabel.setText(lastQuery != null && !lastQuery.isEmpty() && !pages.isEmpty() ? " no match " : " ");
            else
                matchLabel.setText(" " + (currentMatch + 1) + " / " + matches.size() + " ");
            switch (zoomMode) {
                case FIT_WIDTH:
                    zoomCombo.setSelectedItem(FIT_WIDTH_LABEL);
                    break;
                case FIT_PAGE:
                    zoomCombo.setSelectedItem(FIT_PAGE_LABEL);
                    break;
                default:
                    zoomCombo.setSelectedItem(percent(zoom));
            }
        } finally {
            updatingToolbar = false;
        }
    }

    private void applyTheme() {
        Color bg = UIManager.getColor("Panel.background");
        Color fg = UIManager.getColor("Panel.foreground");
        if (bg == null) bg = Color.LIGHT_GRAY;
        if (fg == null) fg = Color.BLACK;
        pagesPanel.setBackground(GUIUtil.interpolateColors(bg, fg, 0.12f));
        pagesPanel.repaint();
    }

    private void installInputHandlers() {
        pagesPanel.setFocusable(true);

        InputMap im = getInputMap(WHEN_ANCESTOR_OF_FOCUSED_COMPONENT);
        ActionMap am = getActionMap();
        bind(im, am, KeyStroke.getKeyStroke(KeyEvent.VK_PAGE_DOWN, 0), "screenDown",
                () -> scrollBy(0, Math.max(20, scrollPane.getViewport().getHeight() - 20)));
        bind(im, am, KeyStroke.getKeyStroke(KeyEvent.VK_PAGE_UP, 0), "screenUp",
                () -> scrollBy(0, -Math.max(20, scrollPane.getViewport().getHeight() - 20)));
        bind(im, am, KeyStroke.getKeyStroke(KeyEvent.VK_PAGE_DOWN, InputEvent.CTRL_DOWN_MASK), "nextPage", this::nextPage);
        bind(im, am, KeyStroke.getKeyStroke(KeyEvent.VK_PAGE_UP, InputEvent.CTRL_DOWN_MASK), "prevPage", this::previousPage);
        bind(im, am, KeyStroke.getKeyStroke(KeyEvent.VK_C, InputEvent.CTRL_DOWN_MASK), "copySelection", this::copySelection);
        bind(im, am, KeyStroke.getKeyStroke(KeyEvent.VK_A, InputEvent.CTRL_DOWN_MASK), "selectAll", this::selectAll);
        bind(im, am, KeyStroke.getKeyStroke(KeyEvent.VK_HOME, InputEvent.CTRL_DOWN_MASK), "firstPage", () -> gotoPage(0));
        bind(im, am, KeyStroke.getKeyStroke(KeyEvent.VK_END, InputEvent.CTRL_DOWN_MASK), "lastPage", () -> gotoPage(pages.size() - 1));
        bind(im, am, KeyStroke.getKeyStroke(KeyEvent.VK_PLUS, InputEvent.CTRL_DOWN_MASK), "zoomIn", this::zoomIn);
        bind(im, am, KeyStroke.getKeyStroke(KeyEvent.VK_EQUALS, InputEvent.CTRL_DOWN_MASK), "zoomIn", this::zoomIn);
        bind(im, am, KeyStroke.getKeyStroke(KeyEvent.VK_ADD, InputEvent.CTRL_DOWN_MASK), "zoomIn", this::zoomIn);
        bind(im, am, KeyStroke.getKeyStroke(KeyEvent.VK_MINUS, InputEvent.CTRL_DOWN_MASK), "zoomOut", this::zoomOut);
        bind(im, am, KeyStroke.getKeyStroke(KeyEvent.VK_SUBTRACT, InputEvent.CTRL_DOWN_MASK), "zoomOut", this::zoomOut);
        bind(im, am, KeyStroke.getKeyStroke(KeyEvent.VK_0, InputEvent.CTRL_DOWN_MASK), "fitWidth", this::fitWidth);
        bind(im, am, KeyStroke.getKeyStroke(KeyEvent.VK_NUMPAD0, InputEvent.CTRL_DOWN_MASK), "fitWidth", this::fitWidth);
        bind(im, am, KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), "escape", () -> {
            marquee = null;
            selAnchor = null;
            pagesPanel.repaint();
            if (hasSelection())
                clearSelection();
            else
                setTool(Tool.PAN);
        });

        // ctrl+wheel zooms around the pointer; plain wheel is left to the scroll pane
        pagesPanel.addMouseWheelListener(e -> {
            if (!e.isControlDown())
                return;
            e.consume();
            if (pages.isEmpty())
                return;
            float factor = e.getWheelRotation() < 0 ? ZOOM_STEP : 1f / ZOOM_STEP;
            Point inView = e.getPoint();
            Point inViewport = SwingUtilities.convertPoint(pagesPanel, inView, scrollPane.getViewport());
            zoomMode = ZoomMode.CUSTOM;
            applyZoom(zoom * factor, inView, inViewport);
            updateToolbar();
        });

        // plain drag: pan, select text or rubber-band a zoom rectangle depending on the tool
        MouseAdapter drag = new MouseAdapter() {
            private Point origin;
            private Point marqueeStart;

            @Override
            public void mousePressed(MouseEvent e) {
                pagesPanel.requestFocusInWindow();
                if (e.isPopupTrigger()) {
                    showSelectionMenu(e);
                    return;
                }
                if (!SwingUtilities.isLeftMouseButton(e))
                    return;
                if (tool == Tool.ZOOM_TO_SELECTION || e.isShiftDown()) {
                    marqueeStart = e.getPoint();
                    marquee = new Rectangle(marqueeStart);
                    pagesPanel.setCursor(Cursor.getPredefinedCursor(Cursor.CROSSHAIR_CURSOR));
                    return;
                }
                if (tool == Tool.SELECT_TEXT) {
                    int[] hit = hitTest(e.getPoint());
                    if (hit != null && e.getClickCount() == 2) {
                        selAnchor = null;
                        selectWordAt(hit[0], hit[1]);
                        return;
                    }
                    selAnchor = hit;
                    clearSelection();
                    return;
                }
                origin = SwingUtilities.convertPoint(pagesPanel, e.getPoint(), scrollPane.getViewport());
                pagesPanel.setCursor(Cursor.getPredefinedCursor(Cursor.MOVE_CURSOR));
            }

            @Override
            public void mouseDragged(MouseEvent e) {
                if (selAnchor != null) {
                    int[] hit = hitTest(e.getPoint());
                    if (hit != null)
                        select(selAnchor[0], selAnchor[1], hit[0], hit[1]);
                    pagesPanel.scrollRectToVisible(new Rectangle(e.getX(), e.getY(), 1, 1));
                    return;
                }
                if (marqueeStart != null) {
                    Rectangle old = marquee;
                    marquee = new Rectangle(marqueeStart);
                    marquee.add(e.getPoint());
                    pagesPanel.scrollRectToVisible(new Rectangle(e.getX(), e.getY(), 1, 1));
                    pagesPanel.repaint(old.union(marquee).getBounds());
                    pagesPanel.repaint(marquee);
                    return;
                }
                if (origin == null)
                    return;
                Point now = SwingUtilities.convertPoint(pagesPanel, e.getPoint(), scrollPane.getViewport());
                JViewport vp = scrollPane.getViewport();
                Point pos = vp.getViewPosition();
                int maxX = Math.max(0, pagesPanel.getWidth() - vp.getWidth());
                int maxY = Math.max(0, pagesPanel.getHeight() - vp.getHeight());
                pos.x = Math.max(0, Math.min(maxX, pos.x - (now.x - origin.x)));
                pos.y = Math.max(0, Math.min(maxY, pos.y - (now.y - origin.y)));
                vp.setViewPosition(pos);
                origin = now;
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                selAnchor = null;
                if (e.isPopupTrigger()) {
                    showSelectionMenu(e);
                    return;
                }
                if (marqueeStart != null) {
                    Rectangle r = marquee;
                    marqueeStart = null;
                    marquee = null;
                    pagesPanel.repaint();
                    if (r != null && r.width > 4 && r.height > 4)
                        zoomToViewRect(r);
                    else if (!pages.isEmpty()) {
                        // plain click: zoom in one step around the pointer
                        zoomMode = ZoomMode.CUSTOM;
                        applyZoom(zoom * ZOOM_STEP, e.getPoint(),
                                SwingUtilities.convertPoint(pagesPanel, e.getPoint(), scrollPane.getViewport()));
                        updateToolbar();
                    }
                }
                origin = null;
                pagesPanel.setCursor(cursorFor(tool));
            }
        };
        pagesPanel.addMouseListener(drag);
        pagesPanel.addMouseMotionListener(drag);
    }

    private static void bind(InputMap im, ActionMap am, KeyStroke key, String name, Runnable action) {
        im.put(key, name);
        am.put(name, new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                action.run();
            }
        });
    }

    private void onViewportChanged(ChangeEvent e) {
        updateVisiblePages();
    }

    /** Recomputes the fit zoom from the viewport size (no-op for CUSTOM). */
    private void applyZoomMode() {
        if (pages.isEmpty() || zoomMode == ZoomMode.CUSTOM)
            return;
        JViewport vp = scrollPane.getViewport();
        int vw = vp.getWidth(), vh = vp.getHeight();
        if (vw <= 0 || vh <= 0)
            return; // not laid out yet, the resize listener will call again
        float maxW = 1, maxH = 1;
        for (PageView pv : pages) {
            maxW = Math.max(maxW, pv.widthPt);
            maxH = Math.max(maxH, pv.heightPt);
        }
        float z = (vw - 2f * PAGE_MARGIN) / maxW;
        if (zoomMode == ZoomMode.FIT_PAGE)
            z = Math.min(z, (vh - 2f * PAGE_MARGIN) / maxH);
        applyZoom(z, null, null);
    }

    /**
     * Applies a new zoom factor. The document point at {@code anchorView} (pages
     * panel pixels, defaults to the viewport center) stays at {@code anchorViewport}
     * (viewport pixels, defaults to the viewport center). The anchor is tracked
     * relative to its page in points, so the constant gaps between pages do not
     * make it drift.
     */
    private void applyZoom(float newZoom, Point anchorView, Point anchorViewport) {
        newZoom = Math.max(MIN_ZOOM, Math.min(MAX_ZOOM, newZoom));
        if (Math.abs(newZoom - zoom) < 0.0005f) {
            updateVisiblePages();
            return;
        }

        JViewport vp = scrollPane.getViewport();
        Point view = vp.getViewPosition();
        Point anchorVp = anchorViewport != null ? anchorViewport : new Point(vp.getWidth() / 2, vp.getHeight() / 2);
        Point anchor = anchorView != null ? anchorView : new Point(view.x + anchorVp.x, view.y + anchorVp.y);
        PageView ref = nearestPage(anchor.y);
        float offXpt = ref != null ? (anchor.x - ref.getX()) / zoom : 0;
        float offYpt = ref != null ? (anchor.y - ref.getY()) / zoom : 0;

        zoom = newZoom;
        generation.incrementAndGet();
        cache.clear();
        for (PageView pv : pages)
            pv.updateSize();
        layoutPages();

        Point target;
        if (ref != null)
            target = new Point(ref.getX() + Math.round(offXpt * zoom) - anchorVp.x,
                    ref.getY() + Math.round(offYpt * zoom) - anchorVp.y);
        else
            target = new Point(0, 0);
        int maxX = Math.max(0, pagesPanel.getPreferredSize().width - vp.getWidth());
        int maxY = Math.max(0, pagesPanel.getPreferredSize().height - vp.getHeight());
        target.x = Math.max(0, Math.min(maxX, target.x));
        target.y = Math.max(0, Math.min(maxY, target.y));
        vp.setViewPosition(target);
        pagesPanel.repaint();
        updateVisiblePages();
    }

    /**
     * Re-lays out the page stack after sizes changed. {@code doLayout} positions
     * the pages without needing a peer (headless/undisplayed); the validate calls
     * let the scroll pane pick the new size up when on screen.
     */
    private void layoutPages() {
        Dimension pref = pagesPanel.getPreferredSize();
        JViewport vp = scrollPane.getViewport();
        pagesPanel.setSize(Math.max(pref.width, vp.getWidth()), pref.height);
        pagesPanel.doLayout();
        pagesPanel.revalidate();
        pagesPanel.validate();
        scrollPane.validate();
    }

    /** The page whose vertical span contains {@code y}, else the closest one; null when empty. */
    private PageView nearestPage(int y) {
        PageView best = null;
        int bestDist = Integer.MAX_VALUE;
        for (PageView pv : pages) {
            int top = pv.getY(), bottom = top + pv.getHeight();
            int dist = y < top ? top - y : (y > bottom ? y - bottom : 0);
            if (dist < bestDist) {
                bestDist = dist;
                best = pv;
            }
            if (dist == 0)
                break;
        }
        return best;
    }

    /** Requests renders for pages near the viewport and updates the current page. */
    private void updateVisiblePages() {
        if (pages.isEmpty())
            return;
        JViewport vp = scrollPane.getViewport();
        Rectangle view = vp.getViewRect();
        if (view.isEmpty())
            return;
        Rectangle ahead = new Rectangle(view.x, view.y - view.height, view.width, view.height * 3);

        int best = currentPage < 0 ? 0 : currentPage;
        int bestOverlap = -1;
        for (PageView pv : pages) {
            Rectangle b = pv.getBounds();
            if (b.intersects(ahead))
                requestRender(pv);
            Rectangle inter = b.intersection(view);
            int overlap = inter.isEmpty() ? 0 : inter.height;
            if (overlap > bestOverlap) {
                bestOverlap = overlap;
                best = pv.index;
            }
        }
        setCurrentPage(best);
    }

    private void setCurrentPage(int page) {
        if (page != currentPage) {
            currentPage = page;
            updateToolbar();
            firePageChanged();
        }
    }

    private void firePageChanged() {
        for (PageChangeListener l : listeners)
            l.pageChanged(currentPage, pages.size());
    }

    private void requestRender(PageView pv) {
        PageCache.Entry cached = cache.get(pv.index);
        if (cached != null && cached.zoom == zoom)
            return;
        if (pv.pendingZoom == zoom)
            return;
        pv.pendingZoom = zoom;

        int gen = generation.get();
        float z = zoom;
        float scale = deviceScale();
        int index = pv.index;
        RENDER_EXECUTOR.submit(() -> {
            if (gen != generation.get())
                return;
            BufferedImage img;
            try {
                synchronized (docLock) {
                    if (renderer == null || gen != generation.get())
                        return;
                    img = renderer.renderImageWithDPI(index, 72f * z * scale, ImageType.RGB);
                }
            } catch (Exception e) {
                img = null;
            }
            BufferedImage result = img;
            SwingUtilities.invokeLater(() -> {
                if (gen != generation.get())
                    return;
                pv.pendingZoom = -1;
                if (result == null || z != zoom)
                    return;
                cache.put(index, result, z);
                pv.repaint();
            });
        });
    }

    private float deviceScale() {
        GraphicsConfiguration gc = getGraphicsConfiguration();
        if (gc == null)
            return 1f;
        AffineTransform t = gc.getDefaultTransform();
        return t == null ? 1f : (float) Math.max(1.0, t.getScaleX());
    }

    // ------------------------------------------------------------ inner classes

    /** Vertical stack of pages, centered, scrollable. */
    private final class PagesPanel extends JPanel implements Scrollable {

        PagesPanel() {
            setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
            setBorder(BorderFactory.createEmptyBorder(PAGE_GAP / 2, PAGE_MARGIN, PAGE_GAP / 2, PAGE_MARGIN));
        }

        @Override
        public void paint(Graphics g) {
            super.paint(g);
            Rectangle r = marquee;
            if (r == null || r.width <= 0 || r.height <= 0)
                return;
            Graphics2D g2 = (Graphics2D) g.create();
            try {
                g2.setColor(new Color(30, 110, 220, 40));
                g2.fillRect(r.x, r.y, r.width, r.height);
                g2.setColor(new Color(30, 110, 220, 200));
                g2.setStroke(new BasicStroke(1f, BasicStroke.CAP_BUTT, BasicStroke.JOIN_MITER, 10f, new float[]{4f, 3f}, 0f));
                g2.drawRect(r.x, r.y, r.width - 1, r.height - 1);
            } finally {
                g2.dispose();
            }
        }

        void rebuild() {
            removeAll();
            for (int i = 0; i < pages.size(); i++) {
                if (i > 0)
                    add(Box.createVerticalStrut(PAGE_GAP));
                PageView pv = pages.get(i);
                pv.setAlignmentX(CENTER_ALIGNMENT);
                add(pv);
            }
            revalidate();
            repaint();
        }

        @Override
        public Dimension getPreferredScrollableViewportSize() {
            return getPreferredSize();
        }

        @Override
        public int getScrollableUnitIncrement(Rectangle visibleRect, int orientation, int direction) {
            return 20;
        }

        @Override
        public int getScrollableBlockIncrement(Rectangle visibleRect, int orientation, int direction) {
            return orientation == SwingConstants.VERTICAL ? Math.max(20, visibleRect.height - 20) : Math.max(20, visibleRect.width - 20);
        }

        @Override
        public boolean getScrollableTracksViewportWidth() {
            // center narrow content, scroll horizontally when zoomed beyond the viewport
            Container parent = getParent();
            return parent instanceof JViewport && getPreferredSize().width <= parent.getWidth();
        }

        @Override
        public boolean getScrollableTracksViewportHeight() {
            return false;
        }
    }

    /** One page: sized from the media box and zoom, painted from the cache. */
    private final class PageView extends JComponent {
        final int index;
        final float widthPt;
        final float heightPt;
        volatile float pendingZoom = -1;
        private boolean textRequested;

        /** Extracts this page's text on the render thread (for painting a selection), then repaints. */
        private void requestPageText() {
            if (textRequested)
                return;
            textRequested = true;
            int gen = generation.get();
            RENDER_EXECUTOR.submit(() -> {
                if (gen != generation.get())
                    return;
                ensurePageText(index);
                SwingUtilities.invokeLater(this::repaint);
            });
        }

        PageView(int index, PDPage page) {
            this.index = index;
            PDRectangle box = page.getCropBox() != null ? page.getCropBox() : page.getMediaBox();
            int rotation = page.getRotation();
            boolean rotated = rotation == 90 || rotation == 270;
            widthPt = rotated ? box.getHeight() : box.getWidth();
            heightPt = rotated ? box.getWidth() : box.getHeight();
            setOpaque(true);
            updateSize();
        }

        void updateSize() {
            Dimension d = new Dimension(Math.max(1, Math.round(widthPt * zoom)), Math.max(1, Math.round(heightPt * zoom)));
            setPreferredSize(d);
            setMinimumSize(d);
            setMaximumSize(d);
            setSize(d);
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            try {
                int w = getWidth(), h = getHeight();
                g2.setColor(Color.WHITE);
                g2.fillRect(0, 0, w, h);
                PageCache.Entry entry = cache.get(index);
                if (entry != null) {
                    g2.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BILINEAR);
                    g2.drawImage(entry.image, 0, 0, w, h, null);
                    if (entry.zoom != zoom)
                        requestRender(this);
                } else {
                    g2.setColor(Color.GRAY);
                    String label = String.valueOf(index + 1);
                    FontMetrics fm = g2.getFontMetrics();
                    g2.drawString(label, (w - fm.stringWidth(label)) / 2, (h + fm.getAscent()) / 2);
                    requestRender(this);
                }
                paintHighlights(g2);
                g2.setColor(new Color(0, 0, 0, 60));
                g2.drawRect(0, 0, w - 1, h - 1);
            } finally {
                g2.dispose();
            }
        }

        private void paintHighlights(Graphics2D g2) {
            if (selStartPage >= 0 && index >= selStartPage && index <= selEndPage) {
                PageText pt = pageTextIfExtracted(index);
                if (pt == null)
                    requestPageText();
                else {
                    int len = pt.text.length();
                    int s = Math.min(len, index == selStartPage ? selStartIdx : 0);
                    int e = Math.min(len, index == selEndPage ? selEndIdx : len);
                    g2.setColor(SELECTION_COLOR);
                    for (Rectangle2D.Float r : pt.rects(s, e))
                        g2.fillRect(Math.round(r.x * zoom), Math.round(r.y * zoom),
                                Math.max(1, Math.round(r.width * zoom)), Math.max(1, Math.round(r.height * zoom)));
                }
            }
            for (int i = 0; i < matches.size(); i++) {
                Match m = matches.get(i);
                if (m.page != index)
                    continue;
                g2.setColor(i == currentMatch ? CURRENT_HIGHLIGHT_COLOR : HIGHLIGHT_COLOR);
                for (Rectangle2D.Float r : m.rects) {
                    int x = Math.round(r.x * zoom), y = Math.round(r.y * zoom);
                    int rw = Math.max(1, Math.round(r.width * zoom)), rh = Math.max(1, Math.round(r.height * zoom));
                    g2.fillRect(x, y, rw, rh);
                }
            }
        }
    }

    /**
     * Extracted text of one page with a glyph position per character (null for
     * inserted word/line separators), used for searching, highlighting and
     * text selection. {@code lower} is the char-by-char lowercased copy used
     * for case-insensitive search; offsets are identical in both.
     */
    private static final class PageText {
        final String text;
        final String lower;
        final TextPosition[] positions;
        /** Text lines, built lazily: [start, end) char offsets and vertical extent in points. */
        private int[] lineStart, lineEnd;
        private float[] lineTop, lineBottom;

        private PageText(String text, TextPosition[] positions) {
            this.text = text;
            this.lower = lower(text);
            this.positions = positions;
        }

        private void buildLines() {
            if (lineStart != null)
                return;
            List<int[]> idx = new ArrayList<>();
            List<float[]> ys = new ArrayList<>();
            int start = -1, last = -1;
            float base = 0, top = 0, bottom = 0;
            for (int i = 0; i < positions.length; i++) {
                TextPosition tp = positions[i];
                if (tp == null)
                    continue;
                float h = Math.max(tp.getHeightDir(), tp.getFontSizeInPt() * 0.75f);
                float b = tp.getYDirAdj();
                if (start < 0 || Math.abs(b - base) >= h * 0.5f) {
                    if (start >= 0) {
                        idx.add(new int[]{start, last + 1});
                        ys.add(new float[]{top, bottom});
                    }
                    start = i;
                    base = b;
                    top = b - h;
                    bottom = b;
                } else {
                    top = Math.min(top, b - h);
                    bottom = Math.max(bottom, b);
                }
                last = i;
            }
            if (start >= 0) {
                idx.add(new int[]{start, last + 1});
                ys.add(new float[]{top, bottom});
            }
            int n = idx.size();
            lineStart = new int[n];
            lineEnd = new int[n];
            lineTop = new float[n];
            lineBottom = new float[n];
            for (int l = 0; l < n; l++) {
                lineStart[l] = idx.get(l)[0];
                lineEnd[l] = idx.get(l)[1];
                lineTop[l] = ys.get(l)[0];
                lineBottom[l] = ys.get(l)[1];
            }
        }

        /** Character offset nearest to a point in page points (top-left origin); see charIndexAt. */
        int hit(float x, float y) {
            buildLines();
            int n = lineStart.length;
            if (n == 0)
                return 0;
            if (y < lineTop[0])
                return 0;
            if (y > lineBottom[n - 1])
                return text.length();
            int line = 0;
            float bestDist = Float.MAX_VALUE;
            for (int l = 0; l < n; l++) {
                float d = y < lineTop[l] ? lineTop[l] - y : (y > lineBottom[l] ? y - lineBottom[l] : 0);
                if (d < bestDist) {
                    bestDist = d;
                    line = l;
                }
                if (d == 0)
                    break;
            }
            for (int i = lineStart[line]; i < lineEnd[line]; i++) {
                TextPosition tp = positions[i];
                if (tp != null && x < tp.getXDirAdj() + tp.getWidthDirAdj() / 2)
                    return i;
            }
            return lineEnd[line];
        }

        static PageText extract(PDDocument document, int page) throws IOException {
            final StringBuilder sb = new StringBuilder();
            final List<TextPosition> pos = new ArrayList<>();
            PDFTextStripper stripper = new PDFTextStripper() {
                @Override
                protected void writeString(String text, List<TextPosition> textPositions) {
                    // rebuild from the glyphs so every char has its own position
                    for (TextPosition tp : textPositions) {
                        String u = tp.getUnicode();
                        for (int i = 0; i < u.length(); i++) {
                            sb.append(u.charAt(i));
                            pos.add(tp);
                        }
                    }
                }

                @Override
                protected void writeWordSeparator() {
                    sb.append(' ');
                    pos.add(null);
                }

                @Override
                protected void writeLineSeparator() {
                    sb.append('\n');
                    pos.add(null);
                }
            };
            stripper.setSortByPosition(true);
            stripper.setStartPage(page + 1);
            stripper.setEndPage(page + 1);
            stripper.getText(document);
            return new PageText(sb.toString(), pos.toArray(new TextPosition[0]));
        }

        void search(int page, String needle, List<Match> out) {
            int from = 0;
            while (true) {
                int at = lower.indexOf(needle, from);
                if (at < 0)
                    return;
                out.add(new Match(page, at, at + needle.length(), rects(at, at + needle.length())));
                from = at + 1;
            }
        }

        /** Union rectangle per text line covered by [start, end). */
        private List<Rectangle2D.Float> rects(int start, int end) {
            List<Rectangle2D.Float> ret = new ArrayList<>();
            Rectangle2D.Float cur = null;
            float curBase = 0;
            for (int i = start; i < end && i < positions.length; i++) {
                TextPosition tp = positions[i];
                if (tp == null)
                    continue;
                float h = Math.max(tp.getHeightDir(), tp.getFontSizeInPt() * 0.75f);
                float pad = h * 0.15f;
                float x = tp.getXDirAdj(), base = tp.getYDirAdj();
                Rectangle2D.Float r = new Rectangle2D.Float(x, base - h - pad, tp.getWidthDirAdj(), h + 2 * pad);
                if (cur != null && Math.abs(base - curBase) < h * 0.5f) {
                    Rectangle2D.union(cur, r, cur);
                } else {
                    cur = r;
                    curBase = base;
                    ret.add(cur);
                }
            }
            return ret;
        }
    }

    /** Byte-bounded LRU of rendered page images. EDT only. */
    private static final class PageCache {
        static final class Entry {
            final BufferedImage image;
            final float zoom;
            final long bytes;

            Entry(BufferedImage image, float zoom) {
                this.image = image;
                this.zoom = zoom;
                this.bytes = 4L * image.getWidth() * image.getHeight();
            }
        }

        private final LinkedHashMap<Integer, Entry> map = new LinkedHashMap<>(16, 0.75f, true);
        private long maxBytes;
        private long bytes;

        PageCache(long maxBytes) {
            this.maxBytes = maxBytes;
        }

        void setMaxBytes(long maxBytes) {
            this.maxBytes = maxBytes;
            evict();
        }

        Entry get(int page) {
            return map.get(page);
        }

        void put(int page, BufferedImage image, float zoom) {
            Entry old = map.remove(page);
            if (old != null)
                bytes -= old.bytes;
            Entry e = new Entry(image, zoom);
            map.put(page, e);
            bytes += e.bytes;
            evict();
        }

        void clear() {
            map.clear();
            bytes = 0;
        }

        int size() {
            return map.size();
        }

        private void evict() {
            Iterator<Map.Entry<Integer, Entry>> it = map.entrySet().iterator();
            while (bytes > maxBytes && map.size() > 1 && it.hasNext()) {
                Map.Entry<Integer, Entry> oldest = it.next();
                bytes -= oldest.getValue().bytes;
                it.remove();
            }
        }
    }
}
