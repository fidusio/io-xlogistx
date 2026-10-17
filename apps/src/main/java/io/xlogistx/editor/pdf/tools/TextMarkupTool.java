package io.xlogistx.editor.pdf.tools;

import io.xlogistx.editor.pdf.AddAnnotationEdit;
import io.xlogistx.editor.pdf.AnnotationFactory;
import io.xlogistx.editor.pdf.AnnotationFactory.MarkupKind;
import io.xlogistx.editor.pdf.AnnotationStyle;
import io.xlogistx.editor.pdf.CompoundEdit;
import io.xlogistx.editor.pdf.EditorHost;
import io.xlogistx.editor.pdf.PDFEdit;
import io.xlogistx.gui.PDFToolContext;
import io.xlogistx.gui.pdf.PageTransform;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotation;

import java.awt.Cursor;
import java.awt.Rectangle;
import java.awt.event.MouseEvent;
import java.awt.geom.Rectangle2D;
import java.util.ArrayList;
import java.util.List;

/**
 * Highlight / underline / strikeout: a drag selects text (double click = a
 * word) and the release marks the selection, one annotation per page, as one
 * undo step. {@link #markSelection(PDFToolContext)} does the same for an
 * existing selection.
 */
public final class TextMarkupTool extends EditorTool {

    private final MarkupKind kind;
    private int[] anchor;

    public TextMarkupTool(EditorHost host, MarkupKind kind) {
        super(host);
        this.kind = kind;
    }

    public MarkupKind getKind() {
        return kind;
    }

    @Override
    public String getName() {
        switch (kind) {
            case UNDERLINE:
                return "Underline";
            case STRIKEOUT:
                return "Strikeout";
            default:
                return "Highlight";
        }
    }

    @Override
    public void cancel(PDFToolContext c) {
        anchor = null;
    }

    @Override
    public void pressed(PDFToolContext c, MouseEvent e) {
        int[] hit = c.hitText(e.getPoint());
        if (hit != null && e.getClickCount() == 2) {
            anchor = null;
            c.selectWordAt(hit[0], hit[1]);
            return;
        }
        anchor = hit;
        c.clearSelection();
    }

    @Override
    public void dragged(PDFToolContext c, MouseEvent e) {
        if (anchor == null)
            return;
        int[] hit = c.hitText(e.getPoint());
        if (hit != null)
            c.select(anchor[0], anchor[1], hit[0], hit[1]);
        c.owner().scrollRectToVisible(new Rectangle(e.getX(), e.getY(), 1, 1));
    }

    @Override
    public void released(PDFToolContext c, MouseEvent e) {
        anchor = null;
        if (c.hasSelection())
            markSelection(c);
    }

    @Override
    public Cursor cursor() {
        return Cursor.getPredefinedCursor(Cursor.TEXT_CURSOR);
    }

    /**
     * Marks the current text selection with this tool's kind and clears it.
     *
     * @param c the context
     * @return the number of annotations added (one per page with selected text)
     */
    public int markSelection(PDFToolContext c) {
        return mark(c, host, kind);
    }

    /**
     * Marks the current text selection, one annotation per page, as one undo step.
     *
     * @return the number of annotations added
     */
    public static int mark(PDFToolContext c, EditorHost host, MarkupKind kind) {
        int[] range = c.selectionRange();
        if (range == null)
            return 0;
        AnnotationStyle style = host.style(kind == MarkupKind.HIGHLIGHT ? EditorHost.StyleKey.HIGHLIGHT
                : kind == MarkupKind.UNDERLINE ? EditorHost.StyleKey.UNDERLINE : EditorHost.StyleKey.STRIKEOUT);
        List<PDFEdit> parts = new ArrayList<>();
        for (int page = range[0]; page <= range[2]; page++) {
            List<Rectangle2D.Float> rects = c.selectionRects(page);
            if (rects.isEmpty())
                continue;
            PDAnnotation a;
            synchronized (c.docLock()) {
                PDDocument doc = c.document();
                if (doc == null)
                    return 0;
                PDPage p = doc.getPage(page);
                a = AnnotationFactory.textMarkup(doc, p, PageTransform.of(p), kind, rects, style);
            }
            parts.add(new AddAnnotationEdit(c.panel(), page, a));
        }
        if (parts.isEmpty())
            return 0;
        PDFEdit edit = parts.size() == 1 ? parts.get(0) : new CompoundEdit(parts.get(0).name() + " (" + parts.size() + " pages)", parts);
        c.clearSelection();
        try {
            host.model().apply(edit);
        } catch (Exception e) {
            c.showError(edit.name() + " failed: " + e.getMessage());
            return 0;
        }
        return parts.size();
    }
}
