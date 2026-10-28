package io.xlogistx.editor.pdf.tools;

import io.xlogistx.editor.pdf.EditorDialogs;
import io.xlogistx.editor.pdf.EditorFonts;
import io.xlogistx.editor.pdf.EditorHost;
import io.xlogistx.editor.pdf.ReplaceTextEdit;
import io.xlogistx.editor.pdf.TextEditor;
import io.xlogistx.gui.pdf.PDFToolContext;
import io.xlogistx.gui.pdf.PageTransform;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.text.TextPosition;

import java.awt.Cursor;
import java.awt.Rectangle;
import java.awt.event.KeyEvent;
import java.awt.event.MouseEvent;
import java.io.IOException;
import java.util.List;

/**
 * Edits text that is already on the page: a drag selects text (like the
 * viewer's Select-text tool), a double click selects a word and opens the
 * replacement dialog, Enter opens it for the current selection. The
 * replacement is written into the page's content stream, with the same font
 * (characters it lacks are refused) or, when the dialog says so, with
 * another font, size or colour (see {@link TextEditor.Format}).
 */
public final class EditTextTool extends EditorTool {

    private int[] anchor;
    /** The alignment picked last, offered again next time. */
    private TextEditor.Alignment lastAlignment = TextEditor.Alignment.LEFT;

    public EditTextTool(EditorHost host) {
        super(host);
    }

    @Override
    public String getName() {
        return "Edit text";
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
            if (c.hasSelection())
                editSelection(c);
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
    }

    @Override
    public void keyPressed(PDFToolContext c, KeyEvent e) {
        if (e.getKeyCode() == KeyEvent.VK_ENTER && c.hasSelection()) {
            editSelection(c);
            e.consume();
        }
    }

    /**
     * Asks for the replacement of the current selection and applies it.
     *
     * @return true when the text was replaced
     */
    public boolean editSelection(PDFToolContext c) {
        int[] range = c.selectionRange();
        if (range == null)
            return false;
        if (range[0] != range[2]) {
            c.showError("Select text on one page to edit it.");
            return false;
        }
        String current = c.panel().getSelectedText();
        float size = 12f;
        java.awt.Color color = null;
        int style = java.awt.Font.PLAIN;
        try {
            synchronized (c.docLock()) {
                PDDocument doc = c.document();
                if (doc != null) {
                    PDPage p = doc.getPage(range[0]);
                    TextEditor.Glyph first = TextEditor.first(TextEditor.match(TextEditor.glyphs(p), PageTransform.of(p),
                            c.selectionTextPositions(range[0])));
                    if (first != null) {
                        size = first.renderedSize();
                        color = first.color;
                        style = EditorFonts.styleOf(first.font);
                    }
                }
            }
        } catch (IllegalArgumentException | IOException e) {
            // the replacement itself reports the problem
        }
        EditorDialogs.AlignedText r = EditorDialogs.askTextAligned(host.dialogParent(), "Edit text", current, lastAlignment, size, color, style);
        if (r == null)
            return false;
        lastAlignment = r.alignment;
        if (r.text.equals(current) && r.format.isSame())
            return false;
        return replaceSelection(c, r.text, r.alignment, r.format);
    }

    /** @return the alignment used last (the dialog's default) */
    public TextEditor.Alignment getLastAlignment() {
        return lastAlignment;
    }

    /**
     * Replaces the current selection (which must lie on one page) with
     * {@code replacement}, undoable.
     *
     * @return true when replaced; errors are shown
     */
    public boolean replaceSelection(PDFToolContext c, String replacement) {
        return replaceSelection(c, replacement, TextEditor.Alignment.LEFT);
    }

    /**
     * Replaces the current selection (one page) with {@code replacement}
     * placed by {@code alignment} in the room the old text took, undoable.
     *
     * @return true when replaced; errors are shown
     */
    public boolean replaceSelection(PDFToolContext c, String replacement, TextEditor.Alignment alignment) {
        return replaceSelection(c, replacement, alignment, TextEditor.Format.SAME);
    }

    /**
     * Replaces the current selection (one page) with {@code replacement}
     * placed by {@code alignment}, written with the font, size and colour the
     * format gives (what it leaves out is kept from the old text), undoable.
     *
     * @return true when replaced; errors are shown
     */
    public boolean replaceSelection(PDFToolContext c, String replacement, TextEditor.Alignment alignment, TextEditor.Format format) {
        int[] range = c.selectionRange();
        if (range == null) {
            c.showError("Select the text to replace first.");
            return false;
        }
        if (range[0] != range[2]) {
            c.showError("Select text on one page to edit it.");
            return false;
        }
        int page = range[0];
        List<TextPosition> positions = c.selectionTextPositions(page);
        if (positions.isEmpty()) {
            c.showError("The selection holds no characters.");
            return false;
        }
        String current = c.panel().getSelectedText();
        byte[] before, after;
        try {
            synchronized (c.docLock()) {
                PDDocument doc = c.document();
                if (doc == null)
                    return false;
                PDPage p = doc.getPage(page);
                List<TextEditor.Glyph> glyphs = TextEditor.glyphs(p);
                List<TextEditor.Glyph> selected = TextEditor.match(glyphs, PageTransform.of(p), positions);
                before = TextEditor.originalContent(p);
                after = TextEditor.replace(doc, p, selected, replacement, alignment, format);
            }
        } catch (IllegalArgumentException | IOException e) {
            c.showError(e.getMessage());
            return false;
        }
        String name = "Replace \"" + shorten(current) + "\" with \"" + shorten(replacement) + "\"";
        return apply(c, new ReplaceTextEdit(c.panel(), page, before, after, name));
    }

    private static String shorten(String s) {
        String t = s == null ? "" : s.replace('\n', ' ');
        return t.length() > 24 ? t.substring(0, 21) + "..." : t;
    }

    @Override
    public Cursor cursor() {
        return Cursor.getPredefinedCursor(Cursor.TEXT_CURSOR);
    }
}
