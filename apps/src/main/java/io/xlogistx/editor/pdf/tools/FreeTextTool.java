package io.xlogistx.editor.pdf.tools;

import io.xlogistx.editor.pdf.AddAnnotationEdit;
import io.xlogistx.editor.pdf.AnnotationFactory;
import io.xlogistx.editor.pdf.AnnotationStyle;
import io.xlogistx.editor.pdf.EditorDialogs;
import io.xlogistx.editor.pdf.EditorHost;
import io.xlogistx.gui.PDFToolContext;
import io.xlogistx.gui.pdf.PageTransform;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationFreeText;

import java.awt.Cursor;
import java.awt.Graphics2D;
import java.awt.event.MouseEvent;
import java.awt.geom.Point2D;
import java.awt.geom.Rectangle2D;

/**
 * Text boxes: drag a box (or click for a default {@value #DEFAULT_WIDTH} x
 * {@value #DEFAULT_HEIGHT} pt box), type the text in a dialog, and a free text
 * annotation with an embedded-font appearance is added.
 */
public final class FreeTextTool extends EditorTool {

    public static final float DEFAULT_WIDTH = 160f, DEFAULT_HEIGHT = 40f;

    private int page = -1;
    private Point2D.Float start;
    private Rectangle2D.Float band;

    public FreeTextTool(EditorHost host) {
        super(host);
    }

    @Override
    public String getName() {
        return "Text box";
    }

    @Override
    public void cancel(PDFToolContext c) {
        int p = page;
        page = -1;
        start = null;
        band = null;
        if (p >= 0)
            c.repaintPage(p);
    }

    @Override
    public void pressed(PDFToolContext c, MouseEvent e) {
        page = c.pageAt(e.getPoint());
        start = page < 0 ? null : c.toPagePt(page, e.getPoint());
        band = null;
    }

    @Override
    public void dragged(PDFToolContext c, MouseEvent e) {
        if (start == null)
            return;
        band = ShapeTool.rect(start, c.toPagePt(page, e.getPoint()));
        c.repaintPage(page);
    }

    @Override
    public void released(PDFToolContext c, MouseEvent e) {
        int p = page;
        Point2D.Float s = start;
        Rectangle2D.Float r = band;
        cancel(c);
        if (p < 0 || s == null)
            return;
        if (r == null || r.width < ShapeTool.MIN_SIZE_PT || r.height < ShapeTool.MIN_SIZE_PT)
            r = new Rectangle2D.Float(s.x, s.y, DEFAULT_WIDTH, DEFAULT_HEIGHT);
        String text = EditorDialogs.askText(host.dialogParent(), "New text box", "", true);
        if (text == null || text.trim().isEmpty())
            return;
        addFreeText(c, p, r, text);
    }

    /**
     * Adds a text box (undoable).
     *
     * @param page     zero-based page
     * @param viewRect the box in view space
     * @param text     the text
     * @return the annotation, null when the page is gone
     */
    public PDAnnotationFreeText addFreeText(PDFToolContext c, int page, Rectangle2D viewRect, String text) {
        PDAnnotationFreeText a;
        synchronized (c.docLock()) {
            PDPage pg = pageOf(c, page);
            if (pg == null)
                return null;
            a = AnnotationFactory.freeText(c.document(), pg, PageTransform.of(pg), viewRect, text, host.style(EditorHost.StyleKey.TEXT));
        }
        return apply(c, new AddAnnotationEdit(c.panel(), page, a)) ? a : null;
    }

    @Override
    public void paintOverlay(PDFToolContext c, int pageIndex, Graphics2D g2) {
        if (pageIndex != page || band == null)
            return;
        AnnotationStyle style = host.style(EditorHost.StyleKey.TEXT);
        float z = c.zoom();
        prepare(g2, style.getStrokeColor(), 1f, z, true);
        g2.draw(new Rectangle2D.Float(band.x * z, band.y * z, band.width * z, band.height * z));
    }

    @Override
    public Cursor cursor() {
        return Cursor.getPredefinedCursor(Cursor.TEXT_CURSOR);
    }

    @Override
    public boolean followsLinks() {
        return false;
    }
}
