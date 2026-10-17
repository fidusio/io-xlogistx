package io.xlogistx.editor.pdf.tools;

import io.xlogistx.editor.pdf.AddAnnotationEdit;
import io.xlogistx.editor.pdf.AnnotationFactory;
import io.xlogistx.editor.pdf.EditorDialogs;
import io.xlogistx.editor.pdf.EditorHost;
import io.xlogistx.gui.PDFToolContext;
import io.xlogistx.gui.pdf.PageTransform;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationText;

import java.awt.Cursor;
import java.awt.event.MouseEvent;
import java.awt.geom.Point2D;

/**
 * Sticky notes: a click asks for the text and places a comment icon with its
 * popup at the click.
 */
public final class NoteTool extends EditorTool {

    public NoteTool(EditorHost host) {
        super(host);
    }

    @Override
    public String getName() {
        return "Note";
    }

    @Override
    public void released(PDFToolContext c, MouseEvent e) {
        int page = c.pageAt(e.getPoint());
        if (page < 0)
            return;
        Point2D.Float pt = c.toPagePt(page, e.getPoint());
        String text = EditorDialogs.askText(host.dialogParent(), "New note", "", true);
        if (text == null)
            return;
        addNote(c, page, pt, text);
    }

    /**
     * Adds a note (undoable).
     *
     * @param page   zero-based page
     * @param viewPt top-left of the icon in view space
     * @param text   the note text
     * @return the note, null when the page is gone
     */
    public PDAnnotationText addNote(PDFToolContext c, int page, Point2D viewPt, String text) {
        PDAnnotationText note;
        synchronized (c.docLock()) {
            PDPage p = pageOf(c, page);
            if (p == null)
                return null;
            note = AnnotationFactory.note(c.document(), p, PageTransform.of(p), viewPt, text, host.style(EditorHost.StyleKey.NOTE));
        }
        return apply(c, new AddAnnotationEdit(c.panel(), page, note)) ? note : null;
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
