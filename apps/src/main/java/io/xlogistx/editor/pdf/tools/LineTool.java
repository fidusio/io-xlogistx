package io.xlogistx.editor.pdf.tools;

import io.xlogistx.editor.pdf.AddAnnotationEdit;
import io.xlogistx.editor.pdf.AnnotationFactory;
import io.xlogistx.editor.pdf.AnnotationStyle;
import io.xlogistx.editor.pdf.EditorHost;
import io.xlogistx.gui.PDFToolContext;
import io.xlogistx.gui.pdf.PageTransform;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationLine;

import java.awt.Cursor;
import java.awt.Graphics2D;
import java.awt.event.MouseEvent;
import java.awt.geom.Line2D;
import java.awt.geom.Point2D;

/**
 * Straight line or arrow: a drag rubber-bands the line on the page it started
 * on, the release adds the annotation (lines shorter than
 * {@value ShapeTool#MIN_SIZE_PT} pt are ignored).
 */
public final class LineTool extends EditorTool {

    private final boolean arrow;
    private int page = -1;
    private Point2D.Float start, end;

    public LineTool(EditorHost host, boolean arrow) {
        super(host);
        this.arrow = arrow;
    }

    public boolean isArrow() {
        return arrow;
    }

    @Override
    public String getName() {
        return arrow ? "Arrow" : "Line";
    }

    @Override
    public void cancel(PDFToolContext c) {
        int p = page;
        page = -1;
        start = end = null;
        if (p >= 0)
            c.repaintPage(p);
    }

    @Override
    public void pressed(PDFToolContext c, MouseEvent e) {
        page = c.pageAt(e.getPoint());
        start = page < 0 ? null : c.toPagePt(page, e.getPoint());
        end = null;
    }

    @Override
    public void dragged(PDFToolContext c, MouseEvent e) {
        if (start == null)
            return;
        end = c.toPagePt(page, e.getPoint());
        c.repaintPage(page);
    }

    @Override
    public void released(PDFToolContext c, MouseEvent e) {
        int p = page;
        Point2D.Float a = start, b = end;
        cancel(c);
        if (p < 0 || a == null || b == null || a.distance(b) < ShapeTool.MIN_SIZE_PT)
            return;
        addLine(c, p, a, b);
    }

    /**
     * Adds a line or arrow annotation (undoable).
     *
     * @param page zero-based page
     * @param p1   start in view space
     * @param p2   end in view space (the arrow head)
     * @return the annotation, null when the page is gone
     */
    public PDAnnotationLine addLine(PDFToolContext c, int page, Point2D p1, Point2D p2) {
        PDAnnotationLine a;
        synchronized (c.docLock()) {
            PDPage pg = pageOf(c, page);
            if (pg == null)
                return null;
            a = AnnotationFactory.line(c.document(), pg, PageTransform.of(pg), p1, p2, arrow, host.style(EditorHost.StyleKey.DRAWING));
        }
        return apply(c, new AddAnnotationEdit(c.panel(), page, a)) ? a : null;
    }

    @Override
    public void paintOverlay(PDFToolContext c, int pageIndex, Graphics2D g2) {
        if (pageIndex != page || start == null || end == null)
            return;
        AnnotationStyle style = host.style(EditorHost.StyleKey.DRAWING);
        float z = c.zoom();
        prepare(g2, style.getStrokeColor(), style.getStrokeWidth(), z, false);
        float x1 = start.x * z, y1 = start.y * z, x2 = end.x * z, y2 = end.y * z;
        g2.draw(new Line2D.Float(x1, y1, x2, y2));
        if (arrow) {
            double ang = Math.atan2(y2 - y1, x2 - x1), len = Math.max(6, 10 * z), spread = Math.toRadians(25);
            g2.draw(new Line2D.Double(x2, y2, x2 - len * Math.cos(ang - spread), y2 - len * Math.sin(ang - spread)));
            g2.draw(new Line2D.Double(x2, y2, x2 - len * Math.cos(ang + spread), y2 - len * Math.sin(ang + spread)));
        }
    }

    @Override
    public Cursor cursor() {
        return Cursor.getPredefinedCursor(Cursor.CROSSHAIR_CURSOR);
    }

    @Override
    public boolean followsLinks() {
        return false;
    }
}
