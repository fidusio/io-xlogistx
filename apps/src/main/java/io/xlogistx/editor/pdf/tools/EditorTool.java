package io.xlogistx.editor.pdf.tools;

import io.xlogistx.editor.pdf.EditorHost;
import io.xlogistx.editor.pdf.PDFEdit;
import io.xlogistx.gui.PDFToolContext;
import io.xlogistx.gui.PDFToolHandler;
import io.xlogistx.gui.pdf.PageTransform;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotation;
import org.zoxweb.shared.util.SUS;

import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.geom.Point2D;
import java.io.IOException;
import java.util.Collections;
import java.util.List;

/**
 * Base of the editor's tools: holds the {@link EditorHost}, applies edits
 * through its model with an error dialog on failure, reads a page's
 * annotations and transform under the document lock, and tells the host when
 * the viewer deactivates the tool.
 */
public abstract class EditorTool extends PDFToolHandler {

    protected final EditorHost host;

    protected EditorTool(EditorHost host) {
        SUS.checkIfNull("host null", host);
        this.host = host;
    }

    /** @return a short name for menus and tooltips */
    public abstract String getName();

    @Override
    public void deactivated(PDFToolContext c) {
        super.deactivated(c);
        host.toolDeactivated(this);
    }

    /** Applies an edit through the model; failures are shown, not thrown. @return true when applied */
    protected boolean apply(PDFToolContext c, PDFEdit edit) {
        try {
            host.model().apply(edit);
            return true;
        } catch (IOException | RuntimeException e) {
            c.showError(edit.name() + " failed: " + e.getMessage());
            return false;
        }
    }

    /** @return the page's annotations (a fresh list), empty when out of range or unreadable; under the lock */
    protected List<PDAnnotation> annotationsOf(PDFToolContext c, int page) {
        synchronized (c.docLock()) {
            PDDocument doc = c.document();
            if (doc == null || page < 0 || page >= doc.getNumberOfPages())
                return Collections.emptyList();
            try {
                return doc.getPage(page).getAnnotations();
            } catch (IOException e) {
                return Collections.emptyList();
            }
        }
    }

    /** @return the page's transform, null when out of range */
    protected PageTransform transformOf(PDFToolContext c, int page) {
        synchronized (c.docLock()) {
            PDDocument doc = c.document();
            if (doc == null || page < 0 || page >= doc.getNumberOfPages())
                return null;
            return PageTransform.of(doc.getPage(page));
        }
    }

    /** @return the page object, null when out of range */
    protected PDPage pageOf(PDFToolContext c, int page) {
        synchronized (c.docLock()) {
            PDDocument doc = c.document();
            if (doc == null || page < 0 || page >= doc.getNumberOfPages())
                return null;
            return doc.getPage(page);
        }
    }

    /** Antialiased graphics with a stroke scaled from points to pixels. */
    protected static void prepare(Graphics2D g2, Color color, float widthPt, float zoom, boolean dashed) {
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g2.setColor(color);
        float w = Math.max(1f, widthPt * zoom);
        g2.setStroke(dashed
                ? new BasicStroke(1f, BasicStroke.CAP_BUTT, BasicStroke.JOIN_MITER, 10f, new float[]{4f, 3f}, 0f)
                : new BasicStroke(w, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
    }

    protected static int px(float pt, float zoom) {
        return Math.round(pt * zoom);
    }

    protected static Point2D.Float pt(Point2D p) {
        return new Point2D.Float((float) p.getX(), (float) p.getY());
    }
}
