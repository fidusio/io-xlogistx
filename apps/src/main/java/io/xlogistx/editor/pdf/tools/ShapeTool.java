package io.xlogistx.editor.pdf.tools;

import io.xlogistx.editor.pdf.AddAnnotationEdit;
import io.xlogistx.editor.pdf.AnnotationFactory;
import io.xlogistx.editor.pdf.AnnotationStyle;
import io.xlogistx.editor.pdf.EditorHost;
import io.xlogistx.gui.PDFToolContext;
import io.xlogistx.gui.pdf.PageTransform;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationSquareCircle;

import java.awt.Cursor;
import java.awt.Graphics2D;
import java.awt.event.MouseEvent;
import java.awt.geom.Ellipse2D;
import java.awt.geom.Point2D;
import java.awt.geom.Rectangle2D;

/**
 * Rectangle or ellipse: a drag rubber-bands the bounds on the page it started
 * on, the release adds the annotation (drags smaller than
 * {@value #MIN_SIZE_PT} pt are ignored).
 */
public final class ShapeTool extends EditorTool {

    static final float MIN_SIZE_PT = 3f;

    private final boolean circle;
    private int page = -1;
    private Point2D.Float start;
    private Rectangle2D.Float band;

    public ShapeTool(EditorHost host, boolean circle) {
        super(host);
        this.circle = circle;
    }

    public boolean isCircle() {
        return circle;
    }

    @Override
    public String getName() {
        return circle ? "Ellipse" : "Rectangle";
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
        band = rect(start, c.toPagePt(page, e.getPoint()));
        c.repaintPage(page);
    }

    @Override
    public void released(PDFToolContext c, MouseEvent e) {
        int p = page;
        Rectangle2D.Float r = band;
        cancel(c);
        if (p < 0 || r == null || r.width < MIN_SIZE_PT || r.height < MIN_SIZE_PT)
            return;
        addShape(c, p, r);
    }

    /**
     * Adds a rectangle or ellipse annotation (undoable).
     *
     * @param page     zero-based page
     * @param viewRect the bounds in view space
     * @return the annotation, null when the page is gone
     */
    public PDAnnotationSquareCircle addShape(PDFToolContext c, int page, Rectangle2D viewRect) {
        PDAnnotationSquareCircle a;
        synchronized (c.docLock()) {
            PDPage pg = pageOf(c, page);
            if (pg == null)
                return null;
            a = AnnotationFactory.shape(c.document(), pg, PageTransform.of(pg), circle, viewRect, host.style(EditorHost.StyleKey.DRAWING));
        }
        return apply(c, new AddAnnotationEdit(c.panel(), page, a)) ? a : null;
    }

    @Override
    public void paintOverlay(PDFToolContext c, int pageIndex, Graphics2D g2) {
        if (pageIndex != page || band == null)
            return;
        AnnotationStyle style = host.style(EditorHost.StyleKey.DRAWING);
        float z = c.zoom();
        Rectangle2D.Float r = new Rectangle2D.Float(band.x * z, band.y * z, band.width * z, band.height * z);
        if (style.getFillColor() != null) {
            g2.setColor(style.getFillColor());
            g2.fill(circle ? new Ellipse2D.Float(r.x, r.y, r.width, r.height) : r);
        }
        prepare(g2, style.getStrokeColor(), style.getStrokeWidth(), z, false);
        g2.draw(circle ? new Ellipse2D.Float(r.x, r.y, r.width, r.height) : r);
    }

    @Override
    public Cursor cursor() {
        return Cursor.getPredefinedCursor(Cursor.CROSSHAIR_CURSOR);
    }

    @Override
    public boolean followsLinks() {
        return false;
    }

    static Rectangle2D.Float rect(Point2D.Float a, Point2D.Float b) {
        float x = Math.min(a.x, b.x), y = Math.min(a.y, b.y);
        return new Rectangle2D.Float(x, y, Math.abs(a.x - b.x), Math.abs(a.y - b.y));
    }
}
