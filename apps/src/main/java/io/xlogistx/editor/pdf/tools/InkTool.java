package io.xlogistx.editor.pdf.tools;

import io.xlogistx.editor.pdf.AddAnnotationEdit;
import io.xlogistx.editor.pdf.AnnotationFactory;
import io.xlogistx.editor.pdf.AnnotationStyle;
import io.xlogistx.editor.pdf.EditorHost;
import io.xlogistx.gui.pdf.PDFToolContext;
import io.xlogistx.gui.pdf.PageTransform;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationInk;

import java.awt.Cursor;
import java.awt.Graphics2D;
import java.awt.event.MouseEvent;
import java.awt.geom.Path2D;
import java.awt.geom.Point2D;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Freehand drawing: a drag collects points on the page it started on
 * (points closer than {@value #MIN_STEP_PT} pt to the last one are skipped),
 * the overlay shows the stroke, the release adds one ink annotation.
 */
public final class InkTool extends EditorTool {

    private static final float MIN_STEP_PT = 1.5f;

    private int page = -1;
    private final List<Point2D.Float> stroke = new ArrayList<>();

    public InkTool(EditorHost host) {
        super(host);
    }

    @Override
    public String getName() {
        return "Ink";
    }

    @Override
    public void cancel(PDFToolContext c) {
        int p = page;
        page = -1;
        stroke.clear();
        if (p >= 0)
            c.repaintPage(p);
    }

    @Override
    public void pressed(PDFToolContext c, MouseEvent e) {
        page = c.pageAt(e.getPoint());
        stroke.clear();
        if (page >= 0)
            stroke.add(c.toPagePt(page, e.getPoint()));
    }

    @Override
    public void dragged(PDFToolContext c, MouseEvent e) {
        if (page < 0)
            return;
        Point2D.Float pt = c.toPagePt(page, e.getPoint());
        if (stroke.isEmpty() || stroke.get(stroke.size() - 1).distance(pt) >= MIN_STEP_PT) {
            stroke.add(pt);
            c.repaintPage(page);
        }
    }

    @Override
    public void released(PDFToolContext c, MouseEvent e) {
        int p = page;
        List<Point2D.Float> points = new ArrayList<>(stroke);
        page = -1;
        stroke.clear();
        if (p < 0)
            return;
        c.repaintPage(p);
        if (points.size() < 2)
            return;
        addInk(c, p, Collections.singletonList(points));
    }

    /**
     * Adds an ink annotation (undoable).
     *
     * @param page    zero-based page
     * @param strokes the strokes in view space
     * @return the annotation, null when the page is gone
     */
    public PDAnnotationInk addInk(PDFToolContext c, int page, List<? extends List<? extends Point2D>> strokes) {
        PDAnnotationInk ink;
        synchronized (c.docLock()) {
            PDPage pg = pageOf(c, page);
            if (pg == null)
                return null;
            ink = AnnotationFactory.ink(c.document(), pg, PageTransform.of(pg), strokes, host.style(EditorHost.StyleKey.DRAWING));
        }
        return apply(c, new AddAnnotationEdit(c.panel(), page, ink)) ? ink : null;
    }

    @Override
    public void paintOverlay(PDFToolContext c, int pageIndex, Graphics2D g2) {
        if (pageIndex != page || stroke.size() < 2)
            return;
        AnnotationStyle style = host.style(EditorHost.StyleKey.DRAWING);
        float z = c.zoom();
        prepare(g2, style.getStrokeColor(), style.getStrokeWidth(), z, false);
        Path2D.Float path = new Path2D.Float();
        path.moveTo(stroke.get(0).x * z, stroke.get(0).y * z);
        for (int i = 1; i < stroke.size(); i++)
            path.lineTo(stroke.get(i).x * z, stroke.get(i).y * z);
        g2.draw(path);
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
