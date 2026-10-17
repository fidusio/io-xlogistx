package io.xlogistx.gui;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.graphics.image.JPEGFactory;
import org.apache.pdfbox.pdmodel.graphics.image.LosslessFactory;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.multipdf.PDFMergerUtility;
import org.apache.pdfbox.pdmodel.PDPageTree;
import org.apache.pdfbox.pdmodel.interactive.action.PDAction;
import org.apache.pdfbox.pdmodel.interactive.action.PDActionGoTo;
import org.apache.pdfbox.pdmodel.interactive.action.PDActionURI;
import org.apache.pdfbox.pdmodel.interactive.annotation.AnnotationFilter;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotation;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationLink;
import org.apache.pdfbox.pdmodel.interactive.documentnavigation.destination.PDDestination;
import org.apache.pdfbox.pdmodel.interactive.documentnavigation.destination.PDNamedDestination;
import org.apache.pdfbox.pdmodel.interactive.documentnavigation.destination.PDPageDestination;
import org.apache.pdfbox.pdmodel.interactive.documentnavigation.destination.PDPageFitWidthDestination;
import org.apache.pdfbox.pdmodel.interactive.documentnavigation.destination.PDPageXYZDestination;
import org.apache.pdfbox.printing.PDFPageable;
import org.apache.pdfbox.rendering.ImageType;
import org.apache.pdfbox.rendering.PDFRenderer;
import org.apache.pdfbox.text.PDFTextStripper;
import org.apache.pdfbox.text.TextPosition;
import io.xlogistx.gui.pdf.PageTransform;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.shared.util.SUS;

import javax.imageio.ImageIO;
import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.awt.event.*;
import java.awt.geom.AffineTransform;
import java.awt.geom.Point2D;
import java.awt.geom.Rectangle2D;
import java.awt.print.Pageable;
import java.awt.print.PrinterJob;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.io.InputStream;
import java.net.URI;
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
 * immediately; an error dialog is shown if parsing fails. A {@code .md} /
 * {@code .markdown} file given to {@link #setPDF(File)} (or picked in
 * {@link #openFile()}) is converted on the fly with {@link MDToPDF}; the viewer
 * then shows the PDF, {@link #getFile()} still names the Markdown file, and
 * saving writes a {@code .pdf} next to it by default (never over the {@code .md}). {@link #setDocument(PDDocument, boolean)}
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
 * them (toolbar arrow buttons, F3 / Shift+F3). {@link #highlightAsync(String, Consumer)}
 * does search + highlight off the EDT, which is what the toolbar search field uses. {@link #openFile()} shows a
 * PDF file chooser (toolbar "Open" button); {@link #saveAs()} / {@link #save(File)}
 * write the current document out (toolbar "Save" button); {@link #print()} shows
 * the system print dialog and prints off the EDT (toolbar "Print" button).
 *
 * <h2>Links</h2>
 * PDF link annotations are clickable with the pan and select-text tools: the
 * pointer turns into a hand with the target as tooltip, and a click opens an
 * {@code http} / {@code https} / {@code mailto} URI through the desktop or
 * scrolls to the destination of a link into the document. Other link kinds
 * (launch, remote PDF, JavaScript, ...) are ignored. {@link #getLinks(int)},
 * {@link #linkAt(int, float, float)} and {@link #followLink(Link)} are the
 * programmatic forms.
 *
 * <h2>Merging</h2>
 * {@link #insertPDF(File, int)} merges another PDF, a Markdown file converted
 * through {@link MDToPDF}, or an image file wrapped in one page by
 * {@link #imageToPDF(File)}, into the current document at a page index (0 = at the
 * beginning, page count = at the end, n = after page n); {@link #insertDialog()}
 * asks for the file and the position (toolbar "Insert" button). Merging marks
 * the document {@linkplain #isModified() modified}; {@link #confirmDiscard()}
 * asks before unsaved changes are thrown away (used by {@link #openFile()}).
 *
 * <h2>Deleting pages</h2>
 * {@link #deletePages(int[])} removes pages by zero-based index and refreshes the
 * view; {@link #deletePages(String)} takes the one-based selection a person types
 * — {@code current}, {@code 3}, {@code 5-8}, or a comma / space separated list of
 * those — through {@link #parsePageSelection(String, int, int)}; {@link #deleteDialog()}
 * asks for that selection (toolbar "Delete" button). Deleting every page is
 * refused and deleting marks the document {@linkplain #isModified() modified}.
 * The panel itself has no undo; a host that wants one installs an
 * {@link EditDelegate}.
 *
 * <h2>Editing hooks</h2>
 * An {@link EditDelegate} (see {@link #setEditDelegate(EditDelegate)}) is asked
 * first for every insert and delete, owns the modified flag and hears about
 * document replacement and saving, so a host can record edits as undoable
 * commands. The commands act through the direct primitives
 * {@link #insertPagesDirect(PDDocument, int)}, {@link #insertPagesDirect(List, int[], int)},
 * {@link #removePagesDirect(List, int)} and {@link #pagesChanged(int)}, which
 * never ask the delegate. A page whose content changed in place (annotations)
 * is re-rendered with {@link #invalidatePage(int)}. Tools are
 * {@link PDFToolHandler} strategies: the built-in ones are fixed, a host adds
 * its own with {@link #setCustomTool(PDFToolHandler)}.
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
        ZOOM_TO_SELECTION,
        /** The handler installed with {@link PDFViewerPanel#setCustomTool(PDFToolHandler)} decides. */
        CUSTOM
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
     * A host's hook into page editing: asked before the panel inserts or deletes
     * pages (so the host can record the change as an undoable command and apply
     * it through the direct primitives), owner of the modified flag, and told when
     * the document is replaced or saved. All methods are called on the EDT.
     */
    public interface EditDelegate {
        /**
         * Insert requested (toolbar, {@link PDFViewerPanel#insertPDF(File, int)} or
         * {@link PDFViewerPanel#insertDocument(PDDocument, int)}).
         *
         * @param source the document whose pages are inserted
         * @param at     zero-based index the first page lands at, already clamped
         * @return true when handled (the delegate inserted the pages itself), false to let the panel do it
         * @throws IOException if the merge fails
         */
        boolean insertDocument(PDDocument source, int at) throws IOException;

        /**
         * Delete requested, after validation.
         *
         * @param pages zero-based indexes, sorted, distinct, never the whole document
         * @return true when handled, false to let the panel do it
         */
        boolean deletePages(int[] pages);

        /**
         * Move requested (a thumbnail drag, {@link PDFViewerPanel#movePages}).
         *
         * @param pages  zero-based indexes, sorted, distinct, in range
         * @param target zero-based index (before the move) the block lands in front of, clamped; the page count = the end
         * @return true when handled, false to let the panel do it
         */
        default boolean movePages(int[] pages, int target) {
            return false;
        }

        /** A document was installed or the panel was closed: any edit history is void. */
        void documentReplaced();

        /** The document was written to a file without being reloaded. */
        void documentSaved();

        /** @return whether the document has unsaved changes; {@link PDFViewerPanel#isModified()} defers here */
        boolean isModified();
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

    /**
     * A clickable area of a page, taken from a PDF link annotation: either an
     * external URI ({@code http}, {@code https} or {@code mailto}) or a jump to
     * another page of the same document.
     */
    public static final class Link {
        private final int page;
        private final Rectangle2D.Float rect;
        private final String uri;
        private final int targetPage;
        /** Offset of the destination from the top of the target page in points, NaN = top of the page. */
        private final float targetTop;

        Link(int page, Rectangle2D.Float rect, String uri, int targetPage, float targetTop) {
            this.page = page;
            this.rect = rect;
            this.uri = uri;
            this.targetPage = targetPage;
            this.targetTop = targetTop;
        }

        /** @return zero-based page the link sits on */
        public int getPage() {
            return page;
        }

        /** @return the clickable area in points, origin at the page's top-left corner */
        public Rectangle2D.Float getRect() {
            return (Rectangle2D.Float) rect.clone();
        }

        /** @return the external URI, null for a link into this document */
        public String getURI() {
            return uri;
        }

        /** @return zero-based destination page, -1 for an external link */
        public int getTargetPage() {
            return targetPage;
        }

        @Override
        public String toString() {
            return "Link{page=" + page + ", " + (uri != null ? uri : "-> page " + targetPage) + "}";
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
    /** Pointer travel in pixels up to which a press and release still count as a click on a link. */
    private static final int CLICK_SLOP = 3;
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
    private JButton prevMatchButton;
    private JButton nextMatchButton;
    private JButton saveButton;
    private JButton printButton;
    private JButton insertButton;
    private JButton deleteButton;
    private boolean modified;
    /** Bumped by every page-tree edit (insert/delete); pageables created before it are stale. */
    private int edits;
    private JToggleButton panButton;
    private JToggleButton selectButton;
    private JToggleButton zoomSelectButton;
    private JButton copyButton;
    private JPopupMenu selectionMenu;
    private Tool tool = Tool.PAN;
    private final PDFToolHandlers.PanHandler panHandler = new PDFToolHandlers.PanHandler();
    private final PDFToolHandlers.SelectTextHandler selectTextHandler = new PDFToolHandlers.SelectTextHandler();
    private final PDFToolHandlers.ZoomSelectionHandler zoomSelectionHandler = new PDFToolHandlers.ZoomSelectionHandler();
    /** The handler of {@link Tool#CUSTOM}; null until {@link #setCustomTool(PDFToolHandler)}. */
    private PDFToolHandler customHandler;
    /** The handler of the active tool, never null. */
    private PDFToolHandler handler = panHandler;
    private final PDFToolContext toolContext = new ToolContextImpl();
    private ButtonGroup toolGroup;
    private EditDelegate editDelegate;
    /** Adds host items to the pages' right-click menu, see {@link #setContextMenuCustomizer}. */
    private java.util.function.BiConsumer<JPopupMenu, MouseEvent> contextMenuCustomizer;
    /** Annotations the renderer draws; null = all. Re-applied to every new renderer. */
    private AnnotationFilter annotationFilter;
    /** Text selection, normalized (start before end); start page -1 when empty. Indexes are clamped on use. EDT only. */
    private int selStartPage = -1, selStartIdx, selEndPage = -1, selEndIdx;
    /** Rubber band being dragged, in pages panel coordinates; null when idle. */
    private Rectangle marquee;
    /** Link under the pointer (hand cursor + tooltip shown); null when none. */
    private Link hoverLink;
    private boolean updatingToolbar;
    private JFileChooser fileChooser;
    private File currentFile;
    /** The pages' scroll pane in the middle, the thumbnail sidebar on the left when shown. */
    private final JPanel centre = new JPanel(new BorderLayout());
    private PDFThumbnailPanel thumbnails;
    private JScrollPane thumbnailScroll;
    private JToggleButton thumbnailsButton;
    private FontSizeWidget fontSizeWidget;
    /** Takes dropped files before the panel does, see {@link #setDropInterceptor}. */
    private java.util.function.BiPredicate<List<File>, Point> dropInterceptor;
    /** Where the file choosers start without a current file, see {@link #setDefaultDirectory}. */
    private File defaultDirectory;

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
        centre.add(scrollPane, BorderLayout.CENTER);
        add(centre, BorderLayout.CENTER);

        toolbar = buildToolbar();
        add(toolbar, BorderLayout.NORTH);
        toolbar.setVisible(toolbarVisible);

        installInputHandlers();
        setTransferHandler(new FileDropHandler());
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
     * @param pdf the PDF file, never null; a {@code .md}/{@code .markdown} file is
     *            converted with {@link MDToPDF} first, an image file
     *            ({@code .png}, {@code .jpg}, {@code .jpeg}, {@code .gif}, {@code .bmp})
     *            becomes a one-page document (see {@link #imageToPDF(File)})
     */
    public void setPDF(File pdf) {
        SUS.checkIfNull("pdf null", pdf);
        BackgroundTask.run(this, null, () -> loadSource(pdf), doc -> install(doc, true, pdf));
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
        releaseDocument();
        currentFile = file;
        modified = false;
        if (doc == null) {
            notifyDocumentReplaced();
            return this;
        }

        synchronized (docLock) {
            document = doc;
            this.ownsDocument = ownsDocument;
            renderer = new PDFRenderer(doc);
            renderer.setSubsamplingAllowed(true);
            if (annotationFilter != null)
                renderer.setAnnotationsFilter(annotationFilter);
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
        notifyDocumentReplaced();
        return this;
    }

    /**
     * Releases the current document (closing it if owned), cancels pending renders
     * and clears the view. Safe to call repeatedly; the panel can load a new
     * document afterwards.
     */
    public void close() {
        releaseDocument();
        notifyDocumentReplaced();
    }

    private void notifyDocumentReplaced() {
        if (editDelegate != null)
            editDelegate.documentReplaced();
    }

    /** {@link #close()} without telling the edit delegate: {@link #install} tells it once, after the new document is in. */
    private void releaseDocument() {
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
        modified = false;
        matches = new ArrayList<>();
        currentMatch = -1;
        lastQuery = null;
        selStartPage = selEndPage = -1;
        handler.cancel(toolContext);
        hoverLink = null;
        pagesPanel.setToolTipText(null);
        updateToolbar();
        firePageChanged();
    }

    /**
     * @return true if the document has unsaved changes (pages were inserted or
     *         deleted); with an {@link EditDelegate} installed, its answer
     */
    public boolean isModified() {
        return editDelegate != null ? editDelegate.isModified() : modified;
    }

    /**
     * Installs the host's editing hook (see {@link EditDelegate}); null removes it.
     *
     * @param delegate the delegate, may be null
     * @return this panel, for chaining
     */
    public PDFViewerPanel setEditDelegate(EditDelegate delegate) {
        editDelegate = delegate;
        updateToolbar();
        return this;
    }

    /**
     * Installs a hook that adds items to the right-click menu over the pages
     * before the viewer's own Copy / Select all / Clear selection entries (a
     * separator is inserted when it added any). The event is in pages-panel
     * coordinates, like the ones a {@link PDFToolHandler} receives, so
     * {@link PDFToolContext#pageAt} and {@link PDFToolContext#toPagePt} locate
     * what was clicked. Null removes the hook.
     *
     * @param customizer the hook, may be null
     * @return this panel, for chaining
     */
    public PDFViewerPanel setContextMenuCustomizer(java.util.function.BiConsumer<JPopupMenu, MouseEvent> customizer) {
        contextMenuCustomizer = customizer;
        return this;
    }

    /**
     * @return the installed edit delegate, null when none
     */
    public EditDelegate getEditDelegate() {
        return editDelegate;
    }

    /**
     * If the document has unsaved changes, asks the user whether to discard them.
     *
     * @return true if there is nothing to lose or the user chose to discard
     */
    public boolean confirmDiscard() {
        if (!isModified())
            return true;
        int choice = JOptionPane.showConfirmDialog(this,
                "The document has unsaved changes. Discard them?", "Unsaved changes",
                JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        return choice == JOptionPane.YES_OPTION;
    }

    /**
     * Merges the pages of {@code source} into the current document so that its
     * first page lands at {@code index}. Runs off the EDT (file loading, Markdown
     * conversion and the merge itself); the view is refreshed on the EDT showing
     * the first inserted page. With no document loaded the file is simply opened.
     * Error dialog on failure. Must be called on the EDT.
     *
     * @param source a {@code .pdf} file, a {@code .md}/{@code .markdown} file
     *               converted with {@link MDToPDF} first, or an image file turned
     *               into one page with {@link #imageToPDF(File)}; never null
     * @param index  0 = at the beginning, {@link #getPageCount()} = at the end,
     *               n = after page n (one-based); clamped to that range
     */
    public void insertPDF(File source, int index) {
        SUS.checkIfNull("source null", source);
        if (getDocument() == null) {
            setPDF(source);
            return;
        }
        final int at = Math.max(0, Math.min(pages.size(), index));
        BackgroundTask.run(this, insertButton, () -> {
            try (PDDocument src = loadSource(source)) {
                return mergeInto(src, at);
            }
        }, added -> refreshPages(at, added));
    }

    /**
     * Synchronous form of {@link #insertPDF(File, int)} for an already parsed
     * document: merges (copying, {@code source} may be closed afterwards) and
     * refreshes the view. Blocks the EDT for the duration of the merge, so it is
     * meant for small documents and tests. Must be called on the EDT.
     *
     * @param source the document whose pages are inserted, never null
     * @param index  see {@link #insertPDF(File, int)}
     * @return number of pages inserted, 0 if nothing is loaded
     * @throws IOException if the merge fails
     */
    public int insertDocument(PDDocument source, int index) throws IOException {
        SUS.checkIfNull("source null", source);
        if (getDocument() == null)
            return 0;
        int at = Math.max(0, Math.min(pages.size(), index));
        if (editDelegate != null) {
            int before = pages.size();
            if (editDelegate.insertDocument(source, at))
                return pages.size() - before;
        }
        return insertPagesDirect(source, at);
    }

    // ------------------------------------------------------------------ deleting pages

    /**
     * Removes the given pages from the current document and refreshes the view, which
     * then shows the page that took the first deleted page's place (or the last page).
     * Synchronous — page removal is cheap — and must be called on the EDT. Marks the
     * document {@linkplain #isModified() modified}.
     *
     * @param indexes zero-based page indexes, in any order, duplicates ignored; never null
     * @return number of pages removed, 0 if nothing is loaded or {@code pages} is empty
     * @throws IllegalArgumentException if an index is out of range, or if the selection
     *                                  would remove every page (a PDF needs at least one)
     */
    public int deletePages(int[] indexes) {
        SUS.checkIfNull("indexes null", indexes);
        if (getDocument() == null || indexes.length == 0)
            return 0;
        int count = pages.size();
        java.util.TreeSet<Integer> set = new java.util.TreeSet<>();
        for (int p : indexes) {
            if (p < 0 || p >= count)
                throw new IllegalArgumentException("Page " + (p + 1) + " is out of range (1-" + count + ").");
            set.add(p);
        }
        if (set.size() >= count)
            throw new IllegalArgumentException("That would delete every page; a PDF needs at least one.");
        if (editDelegate != null) {
            int[] sorted = new int[set.size()];
            int k = 0;
            for (Integer p : set)
                sorted[k++] = p;
            if (editDelegate.deletePages(sorted))
                return sorted.length;
        }
        synchronized (docLock) {
            if (document == null)
                return 0;
            for (Integer p : set.descendingSet())
                document.removePage(p);
        }
        int first = set.first();
        refreshPages(Math.min(first, count - set.size() - 1), set.size());
        return set.size();
    }

    /**
     * {@link #deletePages(int[])} over a typed selection: {@code current}, single pages,
     * ranges, or a comma / semicolon / space separated list of those, one-based as the
     * toolbar shows pages (see {@link #parsePageSelection(String, int, int)}).
     *
     * @param selection the selection text, never null
     * @return number of pages removed
     * @throws IllegalArgumentException with a message fit for a dialog when the text does
     *                                  not parse, names a page out of range, says
     *                                  {@code current} with no page shown, or would
     *                                  delete every page
     */
    public int deletePages(String selection) {
        return deletePages(parsePageSelection(selection, currentPage, pages.size()));
    }

    /**
     * Parses a one-based page selection into sorted, distinct, zero-based indexes.
     * Accepted tokens: {@code current} (also {@code cur}, {@code this}), a page number,
     * and a range {@code a-b} ({@code b-a} is accepted and flipped); separators are
     * comma, semicolon or whitespace; case does not matter.
     *
     * @param selection   the text, may be null
     * @param currentPage zero-based page currently shown, -1 when none
     * @param pageCount   pages in the document
     * @return the indexes, never empty
     * @throws IllegalArgumentException with a message fit for a dialog: no document, empty
     *                                  selection, unparsable token, page out of range,
     *                                  {@code current} with no page shown, or a selection
     *                                  covering every page
     */
    public static int[] parsePageSelection(String selection, int currentPage, int pageCount) {
        if (pageCount <= 0)
            throw new IllegalArgumentException("No document is loaded.");
        String s = selection == null ? "" : selection.trim().toLowerCase(java.util.Locale.ROOT);
        if (s.isEmpty())
            throw new IllegalArgumentException("Enter the pages to delete: current, 3, or 5-8.");
        java.util.TreeSet<Integer> out = new java.util.TreeSet<>();
        for (String token : s.split("[,;\\s]+")) {
            if (token.isEmpty())
                continue;
            if (token.equals("current") || token.equals("cur") || token.equals("this")) {
                if (currentPage < 0)
                    throw new IllegalArgumentException("There is no current page.");
                out.add(currentPage);
                continue;
            }
            int dash = token.indexOf('-', 1);
            try {
                if (dash > 0) {
                    int a = Integer.parseInt(token.substring(0, dash).trim());
                    int b = Integer.parseInt(token.substring(dash + 1).trim());
                    int lo = Math.min(a, b), hi = Math.max(a, b);
                    checkPage(lo, pageCount);
                    checkPage(hi, pageCount);
                    for (int p = lo; p <= hi; p++)
                        out.add(p - 1);
                } else {
                    int p = Integer.parseInt(token);
                    checkPage(p, pageCount);
                    out.add(p - 1);
                }
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("\"" + token + "\" is not a page number or range.");
            }
        }
        if (out.isEmpty())
            throw new IllegalArgumentException("Enter the pages to delete: current, 3, or 5-8.");
        if (out.size() >= pageCount)
            throw new IllegalArgumentException("That would delete every page; a PDF needs at least one.");
        return out.stream().mapToInt(Integer::intValue).toArray();
    }

    private static void checkPage(int oneBased, int pageCount) {
        if (oneBased < 1 || oneBased > pageCount)
            throw new IllegalArgumentException("Page " + oneBased + " is out of range (1-" + pageCount + ").");
    }

    /**
     * Asks which pages to delete (a text field pre-filled with the current page, accepting
     * {@code current}, single pages, ranges and lists) and {@link #deletePages(String) deletes}
     * them. An unusable selection is reported and the dialog shown again.
     *
     * @return number of pages removed, 0 if cancelled or nothing is loaded
     */
    public int deleteDialog() {
        if (pages.isEmpty())
            return 0;
        JTextField field = new JTextField(currentPage >= 0 ? String.valueOf(currentPage + 1) : "", 14);
        JPanel form = new JPanel();
        form.setLayout(new BoxLayout(form, BoxLayout.Y_AXIS));
        form.add(new JLabel("Pages to delete (of " + pages.size() + "):"));
        form.add(Box.createVerticalStrut(4));
        form.add(field);
        form.add(Box.createVerticalStrut(4));
        JLabel hint = new JLabel("current, 3, 5-8 — or a list: current, 3, 5-8");
        hint.setFont(hint.getFont().deriveFont(hint.getFont().getSize2D() - 2f));
        form.add(hint);
        while (true) {
            if (JOptionPane.showConfirmDialog(this, form, "Delete pages", JOptionPane.OK_CANCEL_OPTION,
                    JOptionPane.PLAIN_MESSAGE) != JOptionPane.OK_OPTION)
                return 0;
            try {
                return deletePages(field.getText());
            } catch (IllegalArgumentException e) {
                JOptionPane.showMessageDialog(this, e.getMessage(), "Delete pages", JOptionPane.WARNING_MESSAGE);
            }
        }
    }

    /**
     * Parses a source file into a document: a PDF as is, a Markdown file through
     * {@link #markdownToPDF(File)}, an image through {@link #imageToPDF(File)}.
     * Off the EDT.
     */
    private static PDDocument loadSource(File f) throws IOException {
        if (isMarkdown(f))
            return Loader.loadPDF(markdownToPDF(f));
        if (isImage(f))
            return imageToPDF(f);
        // read fully: a document that no longer refers to its file can be saved over it without a reload
        return Loader.loadPDF(Files.readAllBytes(f.toPath()));
    }

    /** Converts a Markdown file with {@link MDToPDF}, resolving relative images against its directory. */
    private static byte[] markdownToPDF(File md) throws IOException {
        File dir = md.getAbsoluteFile().getParentFile();
        String baseUri = dir != null ? dir.toURI().toString() : null;
        return MDToPDF.mdToPDF(IOUtil.inputStreamToString(md), baseUri, null).toByteArray();
    }

    /** Page margin around an inserted image, in points (half an inch). */
    static final float IMAGE_MARGIN = 36f;

    /**
     * Wraps an image file in a new one-page document. The page is A4, portrait for
     * an image taller than wide and landscape otherwise; the image is centered and
     * scaled down to fit inside {@link #IMAGE_MARGIN} margins, never scaled up
     * (one pixel = one point at most). JPEGs keep their compressed data; other
     * formats are decoded, converted to (A)RGB and stored losslessly (a palette
     * image with two colors would otherwise be embedded as 1-bit gray by PDFBox).
     * The caller owns and closes the document.
     *
     * @param image a {@code .png}, {@code .jpg}, {@code .jpeg}, {@code .gif} or {@code .bmp} file
     * @return a new document with one page showing the image
     * @throws IOException if the file cannot be read or decoded
     */
    public static PDDocument imageToPDF(File image) throws IOException {
        SUS.checkIfNull("image null", image);
        PDDocument doc = new PDDocument();
        try {
            PDImageXObject img = embedImage(image, doc);
            boolean portrait = img.getHeight() >= img.getWidth();
            PDRectangle size = portrait ? PDRectangle.A4
                    : new PDRectangle(PDRectangle.A4.getHeight(), PDRectangle.A4.getWidth());
            PDPage page = new PDPage(size);
            doc.addPage(page);
            float maxW = size.getWidth() - 2 * IMAGE_MARGIN;
            float maxH = size.getHeight() - 2 * IMAGE_MARGIN;
            float scale = Math.min(1f, Math.min(maxW / img.getWidth(), maxH / img.getHeight()));
            float w = img.getWidth() * scale;
            float h = img.getHeight() * scale;
            try (PDPageContentStream cs = new PDPageContentStream(doc, page)) {
                cs.drawImage(img, (size.getWidth() - w) / 2, (size.getHeight() - h) / 2, w, h);
            }
            return doc;
        } catch (IOException | RuntimeException e) {
            doc.close();
            throw e;
        }
    }

    /** JPEG as is (DCT), everything else decoded with ImageIO, normalized to (A)RGB and stored losslessly. */
    private static PDImageXObject embedImage(File image, PDDocument doc) throws IOException {
        String n = image.getName().toLowerCase();
        if (n.endsWith(".jpg") || n.endsWith(".jpeg"))
            return JPEGFactory.createFromStream(doc, Files.newInputStream(image.toPath()));
        BufferedImage decoded = ImageIO.read(image);
        if (decoded == null)
            throw new IOException("unsupported or corrupt image: " + image.getName());
        int type = decoded.getColorModel().hasAlpha() ? BufferedImage.TYPE_INT_ARGB : BufferedImage.TYPE_INT_RGB;
        BufferedImage rgb = new BufferedImage(decoded.getWidth(), decoded.getHeight(), type);
        Graphics2D g = rgb.createGraphics();
        g.drawImage(decoded, 0, 0, null);
        g.dispose();
        return LosslessFactory.createFromImage(doc, rgb);
    }

    private static boolean isMarkdown(File f) {
        String n = f.getName().toLowerCase();
        return n.endsWith(".md") || n.endsWith(".markdown");
    }

    /** Image extensions accepted by {@link #imageToPDF(File)} and the file choosers. */
    private static final String[] IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "bmp"};

    private static boolean isImage(File f) {
        String n = f.getName().toLowerCase();
        for (String ext : IMAGE_EXTENSIONS)
            if (n.endsWith("." + ext))
                return true;
        return false;
    }

    /** True for a source that is converted on load (Markdown or image), so saving never targets it. */
    private static boolean isConverted(File f) {
        return isMarkdown(f) || isImage(f);
    }

    /** Appends {@code source} to the document and moves the new pages to {@code at}. Under docLock. */
    private int mergeInto(PDDocument source, int at) throws IOException {
        synchronized (docLock) {
            if (document == null)
                throw new IOException("no document loaded");
            PDPageTree tree = document.getPages();
            int before = tree.getCount();
            new PDFMergerUtility().appendDocument(document, source);
            int added = tree.getCount() - before;
            if (at < before && added > 0) {
                List<PDPage> appended = new ArrayList<>();
                for (int i = before; i < before + added; i++)
                    appended.add(tree.get(i));
                PDPage ref = tree.get(at);
                for (PDPage p : appended) {
                    tree.remove(p);
                    tree.insertBefore(p, ref);
                }
            }
            return added;
        }
    }

    // ---------------------------------------------------------- edit primitives

    /**
     * Inserts the pages of {@code source} at {@code index} without asking the
     * {@link EditDelegate}: the primitive an undoable insert command calls.
     * Synchronous, on the EDT; the view is refreshed showing the first new page.
     *
     * @param source the document whose pages are inserted (deep-copied, may be closed afterwards), never null
     * @param index  zero-based index the first page lands at, clamped to the page count
     * @return number of pages inserted, 0 if nothing is loaded
     * @throws IOException if the merge fails
     */
    public int insertPagesDirect(PDDocument source, int index) throws IOException {
        SUS.checkIfNull("source null", source);
        if (getDocument() == null)
            return 0;
        int at = Math.max(0, Math.min(pages.size(), index));
        int added = mergeInto(source, at);
        refreshPages(at, added);
        return added;
    }

    /**
     * Puts page objects that belong to this document (typically ones removed by
     * {@link #removePagesDirect(List, int)}) back into the page tree, each at its
     * index, in list order, without asking the {@link EditDelegate}. Give the
     * indexes ascending with the pages they held before removal and the original
     * order is restored exactly. Synchronous, on the EDT.
     *
     * @param pagesToInsert the pages, never null
     * @param indexes       one zero-based target index per page, each valid at the moment that page is inserted
     * @param showPage      the page to show afterwards
     * @throws IllegalArgumentException if the sizes differ or an index is out of range
     */
    public void insertPagesDirect(List<PDPage> pagesToInsert, int[] indexes, int showPage) {
        SUS.checkIfNull("pages null", pagesToInsert);
        SUS.checkIfNull("indexes null", indexes);
        if (indexes.length != pagesToInsert.size())
            throw new IllegalArgumentException("one index per page expected");
        if (pagesToInsert.isEmpty())
            return;
        synchronized (docLock) {
            if (document == null)
                return;
            PDPageTree tree = document.getPages();
            for (int i = 0; i < indexes.length; i++) {
                int at = indexes[i];
                int count = tree.getCount();
                if (at < 0 || at > count)
                    throw new IllegalArgumentException("Page index " + at + " is out of range (0-" + count + ").");
                PDPage p = pagesToInsert.get(i);
                if (at < count)
                    tree.insertBefore(p, tree.get(at));
                else
                    tree.add(p);
            }
        }
        refreshPages(showPage, pagesToInsert.size());
    }

    /**
     * Removes page objects from the page tree without asking the
     * {@link EditDelegate}: the primitive an undoable delete command calls. The
     * pages stay valid objects of this document and can be put back with
     * {@link #insertPagesDirect(List, int[], int)}. Synchronous, on the EDT.
     *
     * @param pagesToRemove the pages, never null
     * @param showPage      the page to show afterwards (clamped)
     * @throws IllegalArgumentException if the removal would leave no page
     */
    public void removePagesDirect(List<PDPage> pagesToRemove, int showPage) {
        SUS.checkIfNull("pages null", pagesToRemove);
        if (pagesToRemove.isEmpty())
            return;
        synchronized (docLock) {
            if (document == null)
                return;
            PDPageTree tree = document.getPages();
            if (tree.getCount() - pagesToRemove.size() < 1)
                throw new IllegalArgumentException("That would delete every page; a PDF needs at least one.");
            for (PDPage p : pagesToRemove)
                tree.remove(p);
        }
        refreshPages(showPage, pagesToRemove.size());
    }

    /**
     * Rebuilds the view after a caller changed the page tree itself (page order,
     * rotation, count) under {@link #getDocumentLock()}.
     *
     * @param showPage the page to show afterwards (clamped)
     */
    public void pagesChanged(int showPage) {
        refreshPages(showPage, 1);
    }

    /**
     * @return the lock every access to {@link #getDocument()} must hold
     */
    public Object getDocumentLock() {
        return docLock;
    }

    /**
     * Moves page objects of this document to new indexes without asking the
     * {@link EditDelegate}: the pages are taken out of the tree, then each is
     * put back at its target index in list order (same contract as
     * {@link #insertPagesDirect(List, int[], int)}), under one lock and one view
     * refresh. Synchronous, on the EDT.
     *
     * @param pagesToMove   the pages, never null
     * @param targetIndexes one zero-based target index per page, valid at the moment that page is inserted
     * @param showPage      the page to show afterwards (clamped)
     * @throws IllegalArgumentException if the sizes differ or an index is out of range
     */
    public void movePagesDirect(List<PDPage> pagesToMove, int[] targetIndexes, int showPage) {
        SUS.checkIfNull("pages null", pagesToMove);
        SUS.checkIfNull("indexes null", targetIndexes);
        if (targetIndexes.length != pagesToMove.size())
            throw new IllegalArgumentException("one index per page expected");
        if (pagesToMove.isEmpty())
            return;
        synchronized (docLock) {
            if (document == null)
                return;
            PDPageTree tree = document.getPages();
            for (PDPage p : pagesToMove)
                tree.remove(p);
            for (int i = 0; i < targetIndexes.length; i++) {
                int at = targetIndexes[i];
                int count = tree.getCount();
                if (at < 0 || at > count)
                    throw new IllegalArgumentException("Page index " + at + " is out of range (0-" + count + ").");
                PDPage p = pagesToMove.get(i);
                if (at < count)
                    tree.insertBefore(p, tree.get(at));
                else
                    tree.add(p);
            }
        }
        refreshPages(showPage, pagesToMove.size());
    }

    /**
     * Sets page rotations without asking the {@link EditDelegate}, then rebuilds
     * the view (page sizes change). Synchronous, on the EDT.
     *
     * @param pageIndexes zero-based pages, never null
     * @param rotations   one rotation in degrees per page (multiples of 90)
     * @param showPage    the page to show afterwards (clamped)
     * @throws IllegalArgumentException if the sizes differ or a page is out of range
     */
    public void setRotationsDirect(int[] pageIndexes, int[] rotations, int showPage) {
        SUS.checkIfNull("pages null", pageIndexes);
        SUS.checkIfNull("rotations null", rotations);
        if (pageIndexes.length != rotations.length)
            throw new IllegalArgumentException("one rotation per page expected");
        if (pageIndexes.length == 0)
            return;
        synchronized (docLock) {
            if (document == null)
                return;
            int count = document.getNumberOfPages();
            for (int p : pageIndexes)
                if (p < 0 || p >= count)
                    throw new IllegalArgumentException("Page " + (p + 1) + " is out of range (1-" + count + ").");
            for (int i = 0; i < pageIndexes.length; i++)
                document.getPage(pageIndexes[i]).setRotation(((rotations[i] % 360) + 360) % 360);
        }
        refreshPages(showPage, pageIndexes.length);
    }

    /**
     * The selected text's glyph rectangles on one page, one per text line, in PDF
     * points from the displayed page's top-left corner (the geometry a text markup
     * annotation needs). Extracts the page text if needed, so this may block briefly.
     *
     * @param page zero-based page index
     * @return the rectangles, empty when the page holds no selection
     */
    public List<Rectangle2D.Float> getSelectionRects(int page) {
        if (!hasSelection() || page < selStartPage || page > selEndPage)
            return Collections.emptyList();
        PageText pt = ensurePageText(page);
        if (pt == null)
            return Collections.emptyList();
        int len = pt.text.length();
        int s = Math.min(len, page == selStartPage ? selStartIdx : 0);
        int e = Math.min(len, page == selEndPage ? selEndIdx : len);
        return e <= s ? Collections.<Rectangle2D.Float>emptyList() : pt.rects(s, e);
    }

    /**
     * The selected characters' {@link TextPosition}s on one page, in selection
     * order (separators the extractor inserted are left out): glyph identity for
     * tools that rewrite page text. Extracts the page text if needed.
     *
     * @param page zero-based page index
     * @return the positions, empty when the page holds no selection
     */
    public List<TextPosition> getSelectionTextPositions(int page) {
        if (!hasSelection() || page < selStartPage || page > selEndPage)
            return Collections.emptyList();
        PageText pt = ensurePageText(page);
        if (pt == null)
            return Collections.emptyList();
        int len = pt.text.length();
        int s = Math.min(len, page == selStartPage ? selStartIdx : 0);
        int e = Math.min(len, page == selEndPage ? selEndIdx : len);
        List<TextPosition> ret = new ArrayList<>();
        for (int i = s; i < e; i++)
            if (pt.positions[i] != null)
                ret.add(pt.positions[i]);
        return ret;
    }

    /**
     * Restricts which annotations are rendered, e.g. to hide the one a tool is
     * dragging. Applies to the current and any later document; the caller
     * {@linkplain #invalidatePage(int) invalidates} the pages concerned.
     *
     * @param filter the filter, null to render every annotation again
     * @return this panel, for chaining
     */
    public PDFViewerPanel setAnnotationFilter(AnnotationFilter filter) {
        annotationFilter = filter;
        synchronized (docLock) {
            if (renderer != null)
                renderer.setAnnotationsFilter(filter != null ? filter : a -> true);
        }
        return this;
    }

    /**
     * @return the installed annotation filter, null when every annotation is rendered
     */
    public AnnotationFilter getAnnotationFilter() {
        return annotationFilter;
    }

    /**
     * Rebuilds the page views after the document's page tree changed, keeping the
     * document, zoom and tool; highlights and selection are cleared.
     */
    private void refreshPages(int showPage, int changed) {
        if (changed <= 0)
            return;
        edits++;
        generation.incrementAndGet();
        cache.clear();
        pages.clear();
        matches = new ArrayList<>();
        currentMatch = -1;
        lastQuery = null;
        selStartPage = selEndPage = -1;
        handler.cancel(toolContext);
        synchronized (docLock) {
            if (document == null)
                return;
            pageTexts = new PageText[document.getNumberOfPages()];
            for (int i = 0; i < document.getNumberOfPages(); i++)
                pages.add(new PageView(i, document.getPage(i)));
        }
        if (editDelegate == null)
            modified = true;
        pagesPanel.rebuild();
        for (PageView pv : pages)
            pv.updateSize();
        layoutPages();
        if (zoomMode != ZoomMode.CUSTOM)
            applyZoomMode();
        currentPage = -1;
        gotoPage(showPage);
        updateToolbar();
        firePageChanged();
        updateVisiblePages();
    }

    /**
     * Shows a file chooser (PDF or Markdown) and a position dialog (beginning,
     * end, after a page), then {@link #insertPDF(File, int) inserts} the file.
     *
     * @return the chosen file, or null if cancelled
     */
    public File insertDialog() {
        JFileChooser fc = fileChooser(true);
        fc.setDialogTitle("Insert PDF, Markdown or image");
        if (fc.showOpenDialog(this) != JFileChooser.APPROVE_OPTION)
            return null;
        File f = fc.getSelectedFile();
        int count = pages.size();
        if (count == 0) {
            insertPDF(f, 0);
            return f;
        }

        JRadioButton begin = new JRadioButton("At the beginning");
        JRadioButton end = new JRadioButton("At the end", true);
        JRadioButton after = new JRadioButton("After page");
        ButtonGroup g = new ButtonGroup();
        g.add(begin);
        g.add(end);
        g.add(after);
        JSpinner pageSpinner = new JSpinner(new SpinnerNumberModel(Math.max(1, currentPage + 1), 1, count, 1));
        pageSpinner.addChangeListener(e -> after.setSelected(true));
        JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        row.add(after);
        row.add(pageSpinner);
        row.add(new JLabel("of " + count));
        JPanel form = new JPanel();
        form.setLayout(new BoxLayout(form, BoxLayout.Y_AXIS));
        form.add(new JLabel("Insert \"" + f.getName() + "\":"));
        form.add(Box.createVerticalStrut(6));
        form.add(begin);
        form.add(end);
        form.add(row);
        if (JOptionPane.showConfirmDialog(this, form, "Insert", JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.PLAIN_MESSAGE) != JOptionPane.OK_OPTION)
            return null;
        int index = begin.isSelected() ? 0 : end.isSelected() ? count : (Integer) pageSpinner.getValue();
        insertPDF(f, index);
        return f;
    }

    /**
     * Shows a file chooser (PDF, Markdown, images) and loads the selected file via
     * {@link #setPDF(File)}.
     *
     * @return the chosen file, or null if the dialog was cancelled
     */
    public File openFile() {
        if (!confirmDiscard())
            return null;
        JFileChooser fc = fileChooser(true);
        fc.setDialogTitle("Open PDF, Markdown or image");
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
        JFileChooser fc = fileChooser(false);
        fc.setDialogTitle("Save PDF");
        fc.setSelectedFile(currentFile != null ? pdfSibling(currentFile) : new File(fc.getCurrentDirectory(), "document.pdf"));
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
     * failure): to a temporary file next to it first, then moved into place.
     * Saving over the file the document was loaded from works the same way,
     * because files are read fully into memory on load, so the document, the
     * page, the selection and a host's undo history all stay as they are (until
     * 2026-10-17 the document was closed and reloaded instead). The
     * {@link EditDelegate} hears {@code documentSaved()}. Must be called on the EDT.
     *
     * @param target the file to write, never null
     */
    public void save(File target) {
        SUS.checkIfNull("target null", target);
        if (getDocument() == null)
            return;
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
                Files.move(tmp.toPath(), target.toPath(), StandardCopyOption.REPLACE_EXISTING);
                ok = true;
            } finally {
                if (!ok)
                    tmp.delete();
            }
            return target;
        }, saved -> {
            currentFile = saved;
            modified = false;
            if (editDelegate != null)
                editDelegate.documentSaved();
            updateToolbar();
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
     * overlaps with the background page renderer. The pageable is a snapshot of
     * the page list: after {@link #close()}, or after pages were inserted or
     * deleted, it reports {@link java.awt.print.Printable#NO_SUCH_PAGE} for every
     * page instead of printing a stale document — create a new one after edits.
     *
     * @return the pageable, or null if nothing is loaded
     */
    public Pageable createPageable() {
        final PDDocument doc;
        final PDFPageable delegate;
        final int snapshot = edits;
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
                        if (document != doc || edits != snapshot)
                            return java.awt.print.Printable.NO_SUCH_PAGE;
                        return printable.print(graphics, pageFormat, index);
                    }
                };
            }
        };
    }

    private FileNameExtensionFilter pdfFilter;
    private FileNameExtensionFilter sourceFilter;

    /**
     * The shared chooser, with the PDF-only filter (saving) or the all-sources filter
     * (PDF, Markdown and images; opening and inserting) active. Callers must read the
     * selected file before switching the filter again, as changing the active filter
     * clears the chooser's selection.
     */
    private JFileChooser fileChooser(boolean allSources) {
        if (fileChooser == null) {
            fileChooser = new JFileChooser();
            pdfFilter = new FileNameExtensionFilter("PDF files (*.pdf)", "pdf");
            List<String> exts = new ArrayList<>(java.util.Arrays.asList("pdf", "md", "markdown"));
            exts.addAll(java.util.Arrays.asList(IMAGE_EXTENSIONS));
            sourceFilter = new FileNameExtensionFilter(
                    "PDF, Markdown and image files (*.pdf, *.md, *.png, *.jpg, *.gif, *.bmp)",
                    exts.toArray(new String[0]));
            fileChooser.addChoosableFileFilter(pdfFilter);
            fileChooser.addChoosableFileFilter(sourceFilter);
        }
        fileChooser.setFileFilter(allSources ? sourceFilter : pdfFilter);
        if (currentFile != null)
            fileChooser.setCurrentDirectory(currentFile.getAbsoluteFile().getParentFile());
        else if (defaultDirectory != null && defaultDirectory.isDirectory())
            fileChooser.setCurrentDirectory(defaultDirectory);
        return fileChooser;
    }

    /** {@code x.md} / {@code x.png} → {@code x.pdf} in the same directory; a {@code .pdf} is returned as is. */
    private static File pdfSibling(File f) {
        if (!isConverted(f))
            return f;
        String name = f.getName();
        int dot = name.lastIndexOf('.');
        return new File(f.getAbsoluteFile().getParentFile(), (dot > 0 ? name.substring(0, dot) : name) + ".pdf");
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
        if (tool == Tool.CUSTOM && customHandler == null)
            throw new IllegalStateException("no custom tool installed; call setCustomTool first");
        PDFToolHandler next = handlerFor(tool);
        if (next != handler) {
            handler.deactivated(toolContext);
            handler = next;
            this.tool = tool;
            handler.activated(toolContext);
        } else
            this.tool = tool;
        pagesPanel.setCursor(handler.cursor());
        JToggleButton b = tool == Tool.PAN ? panButton : tool == Tool.SELECT_TEXT ? selectButton
                : tool == Tool.ZOOM_TO_SELECTION ? zoomSelectButton : null;
        if (b != null) {
            if (!b.isSelected())
                b.setSelected(true);
        } else if (toolGroup != null)
            toolGroup.clearSelection();
        pagesPanel.repaint();
        return this;
    }

    /**
     * Installs a host-defined tool and selects it ({@link Tool#CUSTOM}); the
     * toolbar toggles show no selection while it is active. Selecting a built-in
     * tool afterwards keeps the handler installed for a later {@code setTool(CUSTOM)}.
     *
     * @param custom the handler, never null
     * @return this panel, for chaining
     */
    public PDFViewerPanel setCustomTool(PDFToolHandler custom) {
        SUS.checkIfNull("handler null", custom);
        if (customHandler != null && handler == customHandler && custom != customHandler) {
            handler.deactivated(toolContext);
            handler = panHandler;
            tool = Tool.PAN;
        }
        customHandler = custom;
        return setTool(Tool.CUSTOM);
    }

    /**
     * @return the handler installed with {@link #setCustomTool(PDFToolHandler)}, null when none
     */
    public PDFToolHandler getCustomTool() {
        return customHandler;
    }

    /**
     * @return the context the panel hands its tool handlers, so a host can drive a
     *         handler programmatically (EDT only)
     */
    public PDFToolContext getToolContext() {
        return toolContext;
    }

    /**
     * @return the active tool
     */
    public Tool getTool() {
        return tool;
    }

    private PDFToolHandler handlerFor(Tool tool) {
        switch (tool) {
            case SELECT_TEXT:
                return selectTextHandler;
            case ZOOM_TO_SELECTION:
                return zoomSelectionHandler;
            case CUSTOM:
                return customHandler;
            default:
                return panHandler;
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
        if (copyInterceptor != null && copyInterceptor.getAsBoolean())
            return true;
        String text = getSelectedText();
        if (text.isEmpty())
            return false;
        GUIUtil.copyToClipboard(text);
        return true;
    }

    private java.util.function.BooleanSupplier copyInterceptor;

    /**
     * Lets a host take over a copy before the viewer copies its text selection
     * (Ctrl+C, the Copy button and the Copy menu entry all go through
     * {@link #copySelection()}): the interceptor returns true when it handled
     * the copy (an editor copies its selected annotation, say), false to let
     * the text be copied.
     *
     * @param interceptor the interceptor, null for none
     * @return this panel, for chaining
     */
    public PDFViewerPanel setCopyInterceptor(java.util.function.BooleanSupplier interceptor) {
        copyInterceptor = interceptor;
        return this;
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
        selectionMenu = buildContextMenu(e);
        selectionMenu.show(pagesPanel, e.getX(), e.getY());
    }

    /**
     * Builds the right-click menu for a point over the pages: the host's items
     * (see {@link #setContextMenuCustomizer}) first, then Copy / Select all /
     * Clear selection. Nothing is shown.
     *
     * @param e the event, in pages-panel coordinates
     * @return a new menu
     */
    public JPopupMenu buildContextMenu(MouseEvent e) {
        JPopupMenu menu = new JPopupMenu();
        if (contextMenuCustomizer != null) {
            contextMenuCustomizer.accept(menu, e);
            if (menu.getComponentCount() > 0)
                menu.addSeparator();
        }
        JMenuItem copy = new JMenuItem("Copy");
        copy.addActionListener(a -> copySelection());
        copy.setEnabled(hasSelection());
        menu.add(copy);
        JMenuItem all = new JMenuItem("Select all");
        all.addActionListener(a -> selectAll());
        all.setEnabled(!pages.isEmpty());
        menu.add(all);
        JMenuItem clear = new JMenuItem("Clear selection");
        clear.addActionListener(a -> clearSelection());
        clear.setEnabled(hasSelection());
        menu.add(clear);
        return menu;
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

    // -------------------------------------------------------------------- links

    /**
     * Returns the links of a page: the PDF link annotations that point to an
     * {@code http}, {@code https} or {@code mailto} URI or to a page of this
     * document. Other link kinds (launch, remote PDF, JavaScript, ...) are left
     * out. Reads the annotations on first use, so this may block briefly.
     *
     * @param page zero-based page index
     * @return the links, empty when the page is out of range or has none
     */
    public List<Link> getLinks(int page) {
        if (page < 0 || page >= pages.size())
            return Collections.emptyList();
        PageView pv = pages.get(page);
        if (pv.links == null) {
            synchronized (docLock) {
                pv.links = document != null ? extractLinks(document, page) : Collections.<Link>emptyList();
            }
        }
        return pv.links;
    }

    /**
     * @param page zero-based page index
     * @param xPt  x in PDF points from the page's left edge
     * @param yPt  y in PDF points from the page's top edge
     * @return the link at that point, null if there is none
     */
    public Link linkAt(int page, float xPt, float yPt) {
        return linkAt(getLinks(page), xPt, yPt);
    }

    /**
     * Follows a link: an external URI is handed to the desktop (default browser
     * or mail client), an internal one scrolls to its destination. This is what a
     * click on a link does.
     *
     * @param link the link, never null
     * @return true if the link was followed
     */
    public boolean followLink(Link link) {
        SUS.checkIfNull("link null", link);
        if (link.uri != null)
            return openURI(link.uri);
        if (link.targetPage < 0 || link.targetPage >= pages.size())
            return false;
        gotoPage(link.targetPage);
        if (!Float.isNaN(link.targetTop))
            scrollBy(0, Math.round(link.targetTop * zoom));
        return true;
    }

    private boolean openURI(String uri) {
        if (GraphicsEnvironment.isHeadless())
            return false;
        try {
            URI u = new URI(uri);
            if ("mailto".equalsIgnoreCase(u.getScheme()))
                Desktop.getDesktop().mail(u);
            else
                Desktop.getDesktop().browse(u);
            return true;
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "Cannot open " + uri + "\n" + e.getMessage(), "Open link", JOptionPane.ERROR_MESSAGE);
            return false;
        }
    }

    /** Only these are handed to the desktop; a PDF must not get to launch files or arbitrary handlers. */
    private static boolean isOpenable(String uri) {
        return uri.regionMatches(true, 0, "http://", 0, 7) || uri.regionMatches(true, 0, "https://", 0, 8)
                || uri.regionMatches(true, 0, "mailto:", 0, 7);
    }

    private static Link linkAt(List<Link> links, float xPt, float yPt) {
        for (Link l : links)
            if (l.rect.contains(xPt, yPt))
                return l;
        return null;
    }

    /** Link under a pages-panel point; null if none or the page's links are not read yet (never blocks). */
    private Link linkAtView(Point p) {
        Component c = pagesPanel.getComponentAt(p);
        if (!(c instanceof PageView) || ((PageView) c).links == null)
            return null;
        return linkAt(((PageView) c).links, (p.x - c.getX()) / zoom, (p.y - c.getY()) / zoom);
    }

    /** Shows the hand cursor and the target as tooltip while the pointer is over a link. */
    private void updateHover(Point p) {
        Link link = handler.followsLinks() ? linkAtView(p) : null;
        pagesPanel.setCursor(link != null ? Cursor.getPredefinedCursor(Cursor.HAND_CURSOR) : handler.cursor());
        if (link != hoverLink) {
            hoverLink = link;
            pagesPanel.setToolTipText(link == null ? null : link.uri != null ? link.uri : "Go to page " + (link.targetPage + 1));
        }
    }

    /** The followable link annotations of a page. Call under docLock. */
    private static List<Link> extractLinks(PDDocument doc, int index) {
        List<Link> ret = new ArrayList<>();
        try {
            PDPage page = doc.getPage(index);
            for (PDAnnotation a : page.getAnnotations(PDAnnotationLink.class::isInstance)) {
                PDAnnotationLink la = (PDAnnotationLink) a;
                if (la.getRectangle() == null)
                    continue;
                Rectangle2D.Float rect = PageTransform.of(page).toViewRect(la.getRectangle());
                try {
                    PDAction action = la.getAction();
                    if (action instanceof PDActionURI) {
                        String uri = ((PDActionURI) action).getURI();
                        if (uri != null && isOpenable(uri.trim()))
                            ret.add(new Link(index, rect, uri.trim(), -1, Float.NaN));
                        continue;
                    }
                    PDDestination dest = action instanceof PDActionGoTo ? ((PDActionGoTo) action).getDestination()
                            : action == null ? la.getDestination() : null;
                    if (dest instanceof PDNamedDestination)
                        dest = doc.getDocumentCatalog().findNamedDestinationPage((PDNamedDestination) dest);
                    if (!(dest instanceof PDPageDestination))
                        continue;
                    int target = ((PDPageDestination) dest).retrievePageNumber();
                    if (target < 0 || target >= doc.getNumberOfPages())
                        continue;
                    // top is in the target page's user space (origin bottom-left); 0 or less = not given
                    int top = dest instanceof PDPageXYZDestination ? ((PDPageXYZDestination) dest).getTop()
                            : dest instanceof PDPageFitWidthDestination ? ((PDPageFitWidthDestination) dest).getTop() : -1;
                    PDPage targetPage = doc.getPage(target);
                    float fromTop = top > 0 && targetPage.getRotation() == 0
                            ? Math.max(0, targetPage.getCropBox().getUpperRightY() - top) : Float.NaN;
                    ret.add(new Link(index, rect, null, target, fromTop));
                } catch (IOException e) {
                    // unreadable target: not a link
                }
            }
        } catch (IOException e) {
            // unreadable annotations: the page has no links
        }
        return Collections.unmodifiableList(ret);
    }

    /**
     * Drops one page's raster (and cached links) so it is rendered again: call
     * after changing the page's content in place, e.g. its annotations. A
     * render in flight for the old content is discarded. Must be called on the EDT.
     *
     * @param page zero-based page index; out of range is ignored
     * @return this panel, for chaining
     */
    public PDFViewerPanel invalidatePage(int page) {
        if (page < 0 || page >= pages.size())
            return this;
        PageView pv = pages.get(page);
        pv.contentVersion++;
        pv.pendingZoom = -1;
        pv.links = null;
        pv.linksRequested = false;
        pv.textRequested = false;
        synchronized (docLock) {
            PageText[] texts = pageTexts;
            if (texts != null && page < texts.length)
                texts[page] = null; // the content may have changed: extract again on demand
        }
        if (hasSelection() && page >= selStartPage && page <= selEndPage)
            clearSelection();
        boolean stale = false;
        for (Match m : matches)
            if (m.page == page)
                stale = true;
        if (stale)
            clearHighlights();
        cache.remove(page);
        if (thumbnails != null)
            thumbnails.invalidateThumbnail(page);
        pv.repaint();
        updateVisiblePages(); // re-request the render now if the page is near the viewport
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
        centre.remove(scrollPane);
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
        centre.add(scrollPane, BorderLayout.CENTER);
        revalidate();
        repaint();
        return this;
    }

    // ------------------------------------------------------------------ drag and drop

    /** What dropped files do to an open document. */
    public enum DropAction {
        /** Replace the document (after {@link PDFViewerPanel#confirmDiscard()}). */
        OPEN,
        /** Insert the pages after the current page. */
        INSERT_AFTER_CURRENT,
        /** Insert the pages at the end. */
        INSERT_AT_END
    }

    /**
     * Lets a host take dropped files before the panel does: the interceptor
     * gets every dropped file and the drop point in pages-panel coordinates
     * (null when the drop was not over the pages) and returns true when it
     * handled the drop (an editor places a dropped picture on the page, say).
     *
     * @param interceptor the interceptor, null for none
     * @return this panel, for chaining
     */
    public PDFViewerPanel setDropInterceptor(java.util.function.BiPredicate<List<File>, Point> interceptor) {
        dropInterceptor = interceptor;
        return this;
    }

    /**
     * Where the open / insert / save dialogs start while no file is open
     * (afterwards they start in the open file's directory).
     *
     * @param dir the directory, null for the chooser's default
     * @return this panel, for chaining
     */
    public PDFViewerPanel setDefaultDirectory(File dir) {
        defaultDirectory = dir;
        return this;
    }

    /** @return the directory set with {@link #setDefaultDirectory}, null when none */
    public File getDefaultDirectory() {
        return defaultDirectory;
    }

    /** @return true for a file the panel can open or insert: a PDF, a Markdown file or an image */
    public static boolean acceptsFile(File f) {
        if (f == null)
            return false;
        return f.getName().toLowerCase().endsWith(".pdf") || isMarkdown(f) || isImage(f);
    }

    private static List<File> accepted(List<File> files) {
        List<File> r = new ArrayList<>();
        for (File f : files)
            if (acceptsFile(f))
                r.add(f);
        return r;
    }

    /**
     * Handles files dropped on the panel (what the drop target does): the
     * {@linkplain #setDropInterceptor interceptor} first; then, with nothing
     * loaded, the files are opened; with a document, the user is asked whether
     * to open them instead, insert them after the current page or at the end.
     * Must be called on the EDT.
     *
     * @param files      the dropped files, never null; files that are neither
     *                   PDF, Markdown nor image are ignored
     * @param panelPoint the drop point in pages-panel coordinates, null when not over the pages
     * @return true when something was done or started
     */
    public boolean dropFiles(List<File> files, Point panelPoint) {
        SUS.checkIfNull("files null", files);
        if (dropInterceptor != null && dropInterceptor.test(files, panelPoint))
            return true;
        List<File> sources = accepted(files);
        if (sources.isEmpty())
            return false;
        if (getDocument() == null) {
            openFiles(sources);
            return true;
        }
        DropAction action = askDropAction(sources);
        if (action == null)
            return false;
        dropFiles(sources, action);
        return true;
    }

    /**
     * Handles dropped files with a chosen outcome (the dialog-free form of
     * {@link #dropFiles(List, Point)}). Must be called on the EDT.
     *
     * @param files  the files, never null; unsupported ones are ignored
     * @param action what to do with them, never null
     */
    public void dropFiles(List<File> files, DropAction action) {
        SUS.checkIfNull("files null", files);
        SUS.checkIfNull("action null", action);
        List<File> sources = accepted(files);
        if (sources.isEmpty())
            return;
        switch (action) {
            case OPEN:
                if (confirmDiscard())
                    openFiles(sources);
                break;
            case INSERT_AFTER_CURRENT:
                insertFiles(sources, currentPage + 1);
                break;
            case INSERT_AT_END:
            default:
                insertFiles(sources, pages.size());
                break;
        }
    }

    private DropAction askDropAction(List<File> sources) {
        String what = sources.size() == 1 ? sources.get(0).getName() : sources.size() + " files";
        String[] options = {"Open", "Insert after page " + (currentPage + 1), "Insert at the end", "Cancel"};
        int choice = JOptionPane.showOptionDialog(this,
                "What should happen with " + what + "?\nOpen replaces the current document; Insert adds the pages to it.",
                "Dropped " + (sources.size() == 1 ? "file" : "files"), JOptionPane.DEFAULT_OPTION, JOptionPane.QUESTION_MESSAGE,
                null, options, options[1]);
        switch (choice) {
            case 0:
                return DropAction.OPEN;
            case 1:
                return DropAction.INSERT_AFTER_CURRENT;
            case 2:
                return DropAction.INSERT_AT_END;
            default:
                return null;
        }
    }

    /**
     * Opens one or more files as one document, off the EDT: a single file as
     * {@link #setPDF(File)} does; several files are converted as needed and
     * their pages joined in the given order into a new, unsaved document
     * without a file (Save asks where). Unsupported files are ignored.
     *
     * @param files the files, never null
     */
    public void openFiles(List<File> files) {
        SUS.checkIfNull("files null", files);
        List<File> sources = accepted(files);
        if (sources.isEmpty())
            return;
        if (sources.size() == 1) {
            setPDF(sources.get(0));
            return;
        }
        BackgroundTask.run(this, null, () -> {
            PDDocument doc = loadSource(sources.get(0));
            try {
                for (int i = 1; i < sources.size(); i++)
                    try (PDDocument src = loadSource(sources.get(i))) {
                        new PDFMergerUtility().appendDocument(doc, src);
                    }
            } catch (IOException | RuntimeException e) {
                doc.close();
                throw e;
            }
            return doc;
        }, doc -> {
            setDocument(doc, true);
            modified = true;
        });
    }

    /**
     * Inserts the pages of one or more files (converted as needed, loaded off
     * the EDT) starting at an index, each file through
     * {@link #insertDocument(PDDocument, int)} so an {@link EditDelegate}
     * records one undoable insert per file. With nothing loaded the files are
     * {@linkplain #openFiles opened} instead.
     *
     * @param files the files, never null; unsupported ones are ignored
     * @param index 0 = at the beginning, {@link #getPageCount()} = at the end, n = after page n; clamped
     */
    public void insertFiles(List<File> files, int index) {
        SUS.checkIfNull("files null", files);
        List<File> sources = accepted(files);
        if (sources.isEmpty())
            return;
        if (getDocument() == null) {
            openFiles(sources);
            return;
        }
        final int at = Math.max(0, Math.min(pages.size(), index));
        BackgroundTask.run(this, insertButton, () -> {
            List<PDDocument> loaded = new ArrayList<>();
            try {
                for (File f : sources)
                    loaded.add(loadSource(f));
            } catch (IOException | RuntimeException e) {
                for (PDDocument d : loaded)
                    d.close();
                throw e;
            }
            return loaded;
        }, loaded -> {
            int next = at;
            try {
                for (PDDocument src : loaded) {
                    try {
                        next += insertDocument(src, next);
                    } finally {
                        src.close();
                    }
                }
            } catch (IOException e) {
                JOptionPane.showMessageDialog(this, "Cannot insert the pages: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        });
    }

    /** Accepts file lists dropped anywhere on the panel and hands them to {@link #dropFiles(List, Point)}. */
    private final class FileDropHandler extends TransferHandler {
        @Override
        public boolean canImport(TransferSupport s) {
            if (!s.isDataFlavorSupported(DataFlavor.javaFileListFlavor))
                return false;
            if (s.isDrop())
                s.setDropAction(COPY);
            List<File> files = filesOf(s);
            return files == null || !accepted(files).isEmpty();
        }

        @Override
        public boolean importData(TransferSupport s) {
            if (!s.isDataFlavorSupported(DataFlavor.javaFileListFlavor))
                return false;
            List<File> files = filesOf(s);
            if (files == null || files.isEmpty())
                return false;
            Point panelPoint = null;
            if (s.isDrop()) {
                Point p = SwingUtilities.convertPoint(s.getComponent(), s.getDropLocation().getDropPoint(), pagesPanel);
                if (pagesPanel.contains(p))
                    panelPoint = p;
            }
            return dropFiles(files, panelPoint);
        }

        /** @return the dropped files, null when the data is not readable yet (some platforms during drag-over) */
        private List<File> filesOf(TransferSupport s) {
            try {
                Object o = s.getTransferable().getTransferData(DataFlavor.javaFileListFlavor);
                if (!(o instanceof List))
                    return null;
                List<File> files = new ArrayList<>();
                for (Object f : (List<?>) o)
                    if (f instanceof File)
                        files.add((File) f);
                return files;
            } catch (UnsupportedFlavorException | IOException | RuntimeException e) {
                return null;
            }
        }
    }

    // ------------------------------------------------------------------ thumbnails

    /**
     * Shows or hides the page thumbnails in a column left of the pages (see
     * {@link PDFThumbnailPanel}: click to show a page, drag to move one). Fires
     * the {@code thumbnailsVisible} property change.
     *
     * @param visible whether the sidebar is shown
     * @return this panel, for chaining
     */
    public PDFViewerPanel setThumbnailsVisible(boolean visible) {
        if (visible == isThumbnailsVisible()) {
            if (thumbnailsButton != null && thumbnailsButton.isSelected() != visible)
                thumbnailsButton.setSelected(visible);
            return this;
        }
        if (visible) {
            PDFThumbnailPanel tp = getThumbnailPanel();
            centre.add(thumbnailScroll, BorderLayout.WEST);
            tp.reload();
        } else
            centre.remove(thumbnailScroll);
        centre.revalidate();
        centre.repaint();
        if (thumbnailsButton != null && thumbnailsButton.isSelected() != visible)
            thumbnailsButton.setSelected(visible);
        firePropertyChange("thumbnailsVisible", !visible, visible);
        return this;
    }

    /** @return whether the thumbnail sidebar is shown */
    public boolean isThumbnailsVisible() {
        return thumbnailScroll != null && thumbnailScroll.getParent() == centre;
    }

    /** @return the thumbnail sidebar (created on first use, shown by {@link #setThumbnailsVisible}) */
    public PDFThumbnailPanel getThumbnailPanel() {
        if (thumbnails == null) {
            thumbnails = new PDFThumbnailPanel(this);
            thumbnailScroll = new JScrollPane(thumbnails, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
            thumbnailScroll.getVerticalScrollBar().setUnitIncrement(20);
            Color rule = UIManager.getColor("Separator.foreground");
            thumbnailScroll.setBorder(BorderFactory.createMatteBorder(0, 0, 0, 1, rule == null ? Color.LIGHT_GRAY : rule));
            int w = PDFThumbnailPanel.THUMB_WIDTH + 2 * PDFThumbnailPanel.GAP + 2 * PDFThumbnailPanel.PAD + 22;
            thumbnailScroll.setPreferredSize(new Dimension(w, 10));
            thumbnails.reload();
        }
        return thumbnails;
    }

    /**
     * Moves pages so that the block lands in front of {@code target}, an index
     * as counted before the move ({@link #getPageCount()} = the end): the
     * thumbnail drag, and the API form of the editor's Move. An
     * {@link EditDelegate} is asked first, so a host can record the move as an
     * undoable edit; otherwise the pages are moved directly and the document
     * is marked modified.
     *
     * @param pageIndexes zero-based pages, any order, duplicates ignored; never null
     * @param target      zero-based index the block lands in front of, clamped
     * @return true when moved (or handled by the delegate)
     * @throws IllegalArgumentException if a page is out of range
     */
    public boolean movePages(int[] pageIndexes, int target) {
        SUS.checkIfNull("pages null", pageIndexes);
        int[] sorted = java.util.Arrays.stream(pageIndexes).distinct().sorted().toArray();
        if (sorted.length == 0 || pages.isEmpty())
            return false;
        int count = pages.size();
        for (int p : sorted)
            if (p < 0 || p >= count)
                throw new IllegalArgumentException("Page " + (p + 1) + " is out of range (1-" + count + ").");
        int t = Math.max(0, Math.min(count, target));
        if (editDelegate != null && editDelegate.movePages(sorted, t))
            return true;
        List<PDPage> moved = new ArrayList<>(sorted.length);
        int shift = 0;
        synchronized (docLock) {
            if (document == null)
                return false;
            for (int p : sorted) {
                moved.add(document.getPage(p));
                if (p < t)
                    shift++;
            }
        }
        int[] landing = new int[sorted.length];
        for (int i = 0; i < sorted.length; i++)
            landing[i] = t - shift + i;
        movePagesDirect(moved, landing, landing[0]);
        return true;
    }

    /** @return {@code {width, height}} of a page as displayed, in points */
    float[] pageSizePt(int index) {
        PageView pv = pages.get(index);
        return new float[]{pv.widthPt, pv.heightPt};
    }

    /** @return the shared render thread, for the thumbnails */
    static ExecutorService renderExecutor() {
        return RENDER_EXECUTOR;
    }

    /** @return the render generation; a render started under an older one is dropped */
    int renderGeneration() {
        return generation.get();
    }

    /**
     * Renders a page at a given pixel width (render thread).
     *
     * @return the image, null when there is no document, the generation moved on or rendering failed
     */
    BufferedImage renderThumbnail(int index, int widthPx, int gen) {
        try {
            synchronized (docLock) {
                if (renderer == null || document == null || gen != generation.get() || index < 0 || index >= document.getNumberOfPages())
                    return null;
                float widthPt = PageTransform.of(document.getPage(index)).widthPt();
                return renderer.renderImageWithDPI(index, 72f * widthPx / Math.max(1f, widthPt), ImageType.RGB);
            }
        } catch (Exception e) {
            return null;
        }
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
        insertButton = GUIUtil.iconButton(new IconUtil.InsertIcon(16));
        insertButton.setToolTipText("Insert a PDF, Markdown or image file at the beginning, the end or after a page");
        insertButton.addActionListener(e -> insertDialog());
        tb.add(insertButton);
        deleteButton = GUIUtil.iconButton(new IconUtil.DeleteIcon(16));
        deleteButton.setToolTipText("Delete pages: the current one, a list or a range");
        deleteButton.addActionListener(e -> deleteDialog());
        tb.add(deleteButton);
        thumbnailsButton = new JToggleButton(new IconUtil.ThumbnailsIcon(16));
        thumbnailsButton.setToolTipText("Page thumbnails: click one to show the page, drag one to move the page");
        thumbnailsButton.addActionListener(e -> setThumbnailsVisible(thumbnailsButton.isSelected()));
        tb.add(thumbnailsButton);
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

        toolGroup = new ButtonGroup();
        ButtonGroup tools = toolGroup;
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
        searchField.setToolTipText("Search (Enter/F3: next, Shift+Enter/Shift+F3: previous, Esc: clear)");
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
        searchButton.setToolTipText("Find (Shift+click: previous)");
        searchButton.addActionListener(e -> runSearch((e.getModifiers() & ActionEvent.SHIFT_MASK) != 0));
        tb.add(searchButton);
        prevMatchButton = GUIUtil.iconButton(new IconUtil.BackIcon(16));
        prevMatchButton.setToolTipText("Previous match (Shift+F3)");
        prevMatchButton.addActionListener(e -> runSearch(true));
        prevMatchButton.setEnabled(false);
        tb.add(prevMatchButton);
        nextMatchButton = GUIUtil.iconButton(new IconUtil.NextIcon(16));
        nextMatchButton.setToolTipText("Next match (F3)");
        nextMatchButton.addActionListener(e -> runSearch(false));
        nextMatchButton.setEnabled(false);
        tb.add(nextMatchButton);
        matchLabel = new JLabel(" ");
        tb.add(matchLabel);

        tb.add(Box.createHorizontalGlue());
        fontSizeWidget = new FontSizeWidget();
        tb.add(fontSizeWidget);

        return tb;
    }

    /** @return the control text size spinner at the end of the toolbar (see {@link UIFontSize}) */
    public FontSizeWidget getFontSizeWidget() {
        return fontSizeWidget;
    }

    /**
     * Toolbar search (search field Enter, find/arrow buttons, F3/Shift+F3): a new query
     * searches, a repeated query steps through the matches.
     */
    private void runSearch(boolean backwards) {
        if (searchField == null)
            return;
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
            if (deleteButton != null)
                deleteButton.setEnabled(pages.size() > 1);
            if (copyButton != null)
                copyButton.setEnabled(hasSelection());
            pageCountLabel.setText(" / " + pages.size() + " ");
            if (matches.isEmpty())
                matchLabel.setText(lastQuery != null && !lastQuery.isEmpty() && !pages.isEmpty() ? " no match " : " ");
            else
                matchLabel.setText(" " + (currentMatch + 1) + " / " + matches.size() + " ");
            if (prevMatchButton != null) {
                prevMatchButton.setEnabled(matches.size() > 1);
                nextMatchButton.setEnabled(matches.size() > 1);
            }
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
        bind(im, am, KeyStroke.getKeyStroke(KeyEvent.VK_F3, 0), "nextMatch", () -> runSearch(false));
        bind(im, am, KeyStroke.getKeyStroke(KeyEvent.VK_F3, InputEvent.SHIFT_DOWN_MASK), "prevMatch", () -> runSearch(true));
        bind(im, am, KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), "escape", () -> {
            marquee = null;
            handler.cancel(toolContext);
            pagesPanel.repaint();
            if (hasSelection())
                clearSelection();
            else
                setTool(Tool.PAN);
        });

        // ctrl+wheel zooms around the pointer; a plain wheel scrolls. The scroll pane only
        // sees wheel events that bubble up from components WITHOUT wheel listeners
        // (Component.dispatchMouseWheelToAncestor), and the pages panel has this one, so
        // plain events are handed to the scroll pane explicitly or nothing scrolls unless
        // the pointer is over the scroll bar itself.
        pagesPanel.addMouseWheelListener(e -> {
            if (!e.isControlDown()) {
                scrollPane.dispatchEvent(SwingUtilities.convertMouseEvent(pagesPanel, e, scrollPane));
                return;
            }
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

        // plain drag: the active tool's handler decides (pan, select text, ...); Shift+drag, or the
        // zoom tool, rubber-bands a zoom rectangle across pages; a click (press and release in
        // place) on a link follows it with the tools that follow links
        MouseAdapter drag = new MouseAdapter() {
            private Point marqueeStart;
            private Link pressedLink;
            /** Where pressedLink was pressed, in viewport coordinates (panning moves the pages under the pointer). */
            private Point pressedAt;
            /** True between handler.pressed and handler.released. */
            private boolean gesture;

            @Override
            public void mouseMoved(MouseEvent e) {
                updateHover(e.getPoint());
                handler.moved(toolContext, e);
            }

            @Override
            public void mousePressed(MouseEvent e) {
                pagesPanel.requestFocusInWindow();
                pressedLink = null;
                if (e.isPopupTrigger()) {
                    showSelectionMenu(e);
                    return;
                }
                if (!SwingUtilities.isLeftMouseButton(e))
                    return;
                if (handler.marqueeZoom() || e.isShiftDown()) {
                    marqueeStart = e.getPoint();
                    marquee = new Rectangle(marqueeStart);
                    pagesPanel.setCursor(Cursor.getPredefinedCursor(Cursor.CROSSHAIR_CURSOR));
                    return;
                }
                pressedLink = handler.followsLinks() ? linkAtView(e.getPoint()) : null;
                pressedAt = SwingUtilities.convertPoint(pagesPanel, e.getPoint(), scrollPane.getViewport());
                gesture = true;
                handler.pressed(toolContext, e);
            }

            @Override
            public void mouseDragged(MouseEvent e) {
                if (marqueeStart != null) {
                    Rectangle old = marquee;
                    marquee = new Rectangle(marqueeStart);
                    marquee.add(e.getPoint());
                    pagesPanel.scrollRectToVisible(new Rectangle(e.getX(), e.getY(), 1, 1));
                    pagesPanel.repaint(old == null ? marquee : old.union(marquee).getBounds());
                    pagesPanel.repaint(marquee);
                    return;
                }
                if (gesture)
                    handler.dragged(toolContext, e);
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                Link clicked = pressedLink;
                pressedLink = null;
                if (e.isPopupTrigger()) {
                    if (gesture) {
                        gesture = false;
                        handler.cancel(toolContext);
                    }
                    showSelectionMenu(e);
                    return;
                }
                // zooming and following a link scroll the pages, the pointer stays put in the viewport
                JViewport vp = scrollPane.getViewport();
                Point at = SwingUtilities.convertPoint(pagesPanel, e.getPoint(), vp);
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
                if (gesture) {
                    gesture = false;
                    handler.released(toolContext, e);
                }
                if (clicked != null && pressedAt != null && at.distance(pressedAt) <= CLICK_SLOP
                        && clicked == linkAtView(e.getPoint()))
                    followLink(clicked);
                updateHover(SwingUtilities.convertPoint(vp, at, pagesPanel));
            }
        };
        pagesPanel.addMouseListener(drag);
        pagesPanel.addMouseMotionListener(drag);
        pagesPanel.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                handler.keyPressed(toolContext, e);
            }
        });
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
        if (cached != null && cached.zoom == zoom && cached.version == pv.contentVersion)
            return;
        if (pv.pendingZoom == zoom)
            return;
        pv.pendingZoom = zoom;

        int gen = generation.get();
        int ver = pv.contentVersion;
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
                // a stale generation or content version: invalidatePage already re-requested
                if (gen != generation.get() || ver != pv.contentVersion)
                    return;
                pv.pendingZoom = -1;
                if (result == null || z != zoom)
                    return;
                cache.put(index, result, z, ver);
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
            if (thumbnails != null)
                thumbnails.reload(); // install, close and every page-tree refresh come through here
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

    /** One page: sized from the displayed page box and zoom, painted from the cache. */
    private final class PageView extends JComponent {
        final int index;
        final float widthPt;
        final float heightPt;
        volatile float pendingZoom = -1;
        /** Bumped by {@link PDFViewerPanel#invalidatePage(int)}; a cached or in-flight render of an older version is dropped. EDT only. */
        int contentVersion;
        private boolean textRequested;
        /** Links of this page, null until read (on first paint or by getLinks). EDT only. */
        List<Link> links;
        private boolean linksRequested;

        /** Reads this page's links on the render thread, so hovering never waits for a render. */
        private void requestLinks() {
            if (linksRequested)
                return;
            linksRequested = true;
            PDDocument doc = document;
            RENDER_EXECUTOR.submit(() -> {
                List<Link> found;
                synchronized (docLock) {
                    if (doc == null || doc != document || index >= doc.getNumberOfPages())
                        return;
                    found = extractLinks(doc, index);
                }
                SwingUtilities.invokeLater(() -> {
                    if (links == null)
                        links = found;
                });
            });
        }

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
            PageTransform t = PageTransform.of(page);
            widthPt = t.widthPt();
            heightPt = t.heightPt();
            setOpaque(true);
            updateSize();
        }

        void updateSize() {
            Dimension d = new Dimension(Math.max(1, Math.round(widthPt * zoom)), Math.max(1, Math.round(heightPt * zoom)));
            setPreferredSize(d);
            setMinimumSize(d);
            setMaximumSize(d);
            setSize(d);
            positionOverlay();
        }

        /** Places the overlay component (if it is this page's child) over its area at the current zoom. */
        void positionOverlay() {
            if (overlay == null || overlayRect == null || overlay.getParent() != this)
                return;
            overlay.setBounds(Math.round(overlayRect.x * zoom), Math.round(overlayRect.y * zoom),
                    Math.max(1, Math.round(overlayRect.width * zoom)), Math.max(1, Math.round(overlayRect.height * zoom)));
        }

        @Override
        public void doLayout() {
            positionOverlay();
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
                    if (entry.zoom != zoom || entry.version != contentVersion)
                        requestRender(this);
                } else {
                    g2.setColor(Color.GRAY);
                    String label = String.valueOf(index + 1);
                    FontMetrics fm = g2.getFontMetrics();
                    g2.drawString(label, (w - fm.stringWidth(label)) / 2, (h + fm.getAscent()) / 2);
                    requestRender(this);
                }
                if (links == null)
                    requestLinks();
                paintHighlights(g2);
                Graphics2D og = (Graphics2D) g2.create();
                try {
                    handler.paintOverlay(toolContext, index, og);
                } finally {
                    og.dispose();
                }
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

    /** The panel as seen by its {@link PDFToolHandler}s. */
    private final class ToolContextImpl implements PDFToolContext {
        private PageView view(int page) {
            if (page < 0 || page >= pages.size())
                throw new IllegalArgumentException("Page " + page + " is out of range (0-" + (pages.size() - 1) + ").");
            return pages.get(page);
        }

        @Override
        public PDFViewerPanel panel() {
            return PDFViewerPanel.this;
        }

        @Override
        public JComponent owner() {
            return pagesPanel;
        }

        @Override
        public JViewport viewport() {
            return scrollPane.getViewport();
        }

        @Override
        public float zoom() {
            return zoom;
        }

        @Override
        public int pageCount() {
            return pages.size();
        }

        @Override
        public int pageAt(Point p) {
            PageView pv = nearestPage(p.y);
            return pv == null ? -1 : pv.index;
        }

        @Override
        public Point2D.Float toPagePt(int page, Point p) {
            PageView pv = view(page);
            return new Point2D.Float((p.x - pv.getX()) / zoom, (p.y - pv.getY()) / zoom);
        }

        @Override
        public Point toPanelPoint(int page, Point2D pt) {
            PageView pv = view(page);
            return new Point(pv.getX() + Math.round((float) pt.getX() * zoom), pv.getY() + Math.round((float) pt.getY() * zoom));
        }

        @Override
        public Rectangle pageBounds(int page) {
            return page < 0 || page >= pages.size() ? new Rectangle() : pages.get(page).getBounds();
        }

        @Override
        public PDDocument document() {
            return document;
        }

        @Override
        public Object docLock() {
            return docLock;
        }

        @Override
        public void repaintPage(int page) {
            if (page >= 0 && page < pages.size())
                pages.get(page).repaint();
        }

        @Override
        public void invalidatePage(int page) {
            PDFViewerPanel.this.invalidatePage(page);
        }

        @Override
        public int[] hitText(Point p) {
            return hitTest(p);
        }

        @Override
        public void select(int startPage, int startIndex, int endPage, int endIndex) {
            PDFViewerPanel.this.select(startPage, startIndex, endPage, endIndex);
        }

        @Override
        public void selectWordAt(int page, int index) {
            PDFViewerPanel.this.selectWordAt(page, index);
        }

        @Override
        public void clearSelection() {
            PDFViewerPanel.this.clearSelection();
        }

        @Override
        public boolean hasSelection() {
            return PDFViewerPanel.this.hasSelection();
        }

        @Override
        public int[] selectionRange() {
            return selStartPage < 0 ? null : new int[]{selStartPage, selStartIdx, selEndPage, selEndIdx};
        }

        @Override
        public Link linkAt(Point p) {
            return linkAtView(p);
        }

        @Override
        public void setCursor(Cursor cursor) {
            pagesPanel.setCursor(cursor != null ? cursor : handler.cursor());
        }

        @Override
        public void showError(String message) {
            JOptionPane.showMessageDialog(PDFViewerPanel.this, message, "Error", JOptionPane.ERROR_MESSAGE);
        }

        @Override
        public List<Rectangle2D.Float> selectionRects(int page) {
            return getSelectionRects(page);
        }

        @Override
        public List<TextPosition> selectionTextPositions(int page) {
            return getSelectionTextPositions(page);
        }

        @Override
        public void setAnnotationFilter(AnnotationFilter filter) {
            PDFViewerPanel.this.setAnnotationFilter(filter);
        }

        @Override
        public void showOverlay(JComponent comp, int page, Rectangle2D viewRect) {
            PDFViewerPanel.this.showOverlay(comp, page, viewRect);
        }

        @Override
        public void hideOverlay() {
            PDFViewerPanel.this.hideOverlay();
        }

        @Override
        public JComponent overlay() {
            return overlay;
        }
    }

    // ------------------------------------------------------------------ overlay (in-place editors)

    /** The component a tool shows over a page area, see {@link PDFToolContext#showOverlay}; a child of that page's view. */
    private JComponent overlay;
    private Rectangle2D.Float overlayRect;

    private void showOverlay(JComponent comp, int page, Rectangle2D viewRect) {
        SUS.checkIfNull("component null", comp);
        SUS.checkIfNull("rect null", viewRect);
        hideOverlay();
        if (page < 0 || page >= pages.size())
            return;
        overlay = comp;
        overlayRect = new Rectangle2D.Float((float) viewRect.getX(), (float) viewRect.getY(), (float) viewRect.getWidth(), (float) viewRect.getHeight());
        PageView pv = pages.get(page);
        pv.add(comp);
        pv.positionOverlay();
        pv.revalidate();
        pv.repaint();
    }

    private void hideOverlay() {
        if (overlay == null)
            return;
        Container parent = overlay.getParent();
        if (parent != null) {
            parent.remove(overlay);
            parent.revalidate();
            parent.repaint();
        }
        overlay = null;
        overlayRect = null;
    }

    /** Byte-bounded LRU of rendered page images. EDT only. */
    private static final class PageCache {
        static final class Entry {
            final BufferedImage image;
            final float zoom;
            /** The page's content version when rendered, see {@link PageView#contentVersion}. */
            final int version;
            final long bytes;

            Entry(BufferedImage image, float zoom, int version) {
                this.image = image;
                this.zoom = zoom;
                this.version = version;
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

        void put(int page, BufferedImage image, float zoom, int version) {
            Entry old = map.remove(page);
            if (old != null)
                bytes -= old.bytes;
            Entry e = new Entry(image, zoom, version);
            map.put(page, e);
            bytes += e.bytes;
            evict();
        }

        void remove(int page) {
            Entry old = map.remove(page);
            if (old != null)
                bytes -= old.bytes;
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
