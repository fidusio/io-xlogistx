package io.xlogistx.editor.pdf.tools;

import io.xlogistx.editor.pdf.AnnotationFactory;
import io.xlogistx.editor.pdf.EditorFonts;
import io.xlogistx.editor.pdf.FreeTextAppearance;
import io.xlogistx.gui.PDFToolContext;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationFreeText;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDBorderStyleDictionary;
import org.zoxweb.shared.util.SUS;

import javax.swing.AbstractAction;
import javax.swing.BorderFactory;
import javax.swing.JComponent;
import javax.swing.JTextArea;
import javax.swing.KeyStroke;
import javax.swing.border.Border;
import java.awt.Color;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.awt.geom.Rectangle2D;
import java.util.function.Consumer;

/**
 * Typing into a text box on the page: a text area in the box's font, colours,
 * border and padding, hosted over the box through
 * {@link PDFToolContext#showOverlay} so it scrolls and zooms with the page,
 * while the box's own appearance is hidden. Enter breaks the line,
 * Ctrl+Enter or a click elsewhere (focus loss) commits, Esc cancels; the
 * caller decides what a commit means (change the text of an existing box, add
 * a new one, or nothing when the text is empty). One edit, one editor.
 */
public final class InPlaceTextEditor {

    private final PDFToolContext c;
    private final int page;
    private final PDAnnotationFreeText box;
    private final Rectangle2D.Float viewRect;
    private final boolean hideBox;
    private final Consumer<String> onCommit;
    private final Runnable onCancel;
    private final JTextArea area = new JTextArea();
    private float sizePt = 12f, borderPt;
    private String family;
    private int style;
    private Color textColor = Color.BLACK;
    private boolean done;

    /**
     * @param c        the tool context, never null
     * @param page     zero-based page of the box
     * @param box      the box, with its style keys set (DA, DS, C, BS) and contents; never null
     * @param viewRect the box in view space, never null
     * @param hideBox  true to hide the box's own appearance while editing (an existing box; a new one is not on the page yet)
     * @param onCommit gets the text typed, never null
     * @param onCancel called when the edit is abandoned, never null
     */
    public InPlaceTextEditor(PDFToolContext c, int page, PDAnnotationFreeText box, Rectangle2D.Float viewRect, boolean hideBox,
                             Consumer<String> onCommit, Runnable onCancel) {
        SUS.checkIfNull("context null", c);
        SUS.checkIfNull("box null", box);
        SUS.checkIfNull("rect null", viewRect);
        SUS.checkIfNull("onCommit null", onCommit);
        SUS.checkIfNull("onCancel null", onCancel);
        this.c = c;
        this.page = page;
        this.box = box;
        this.viewRect = viewRect;
        this.hideBox = hideBox;
        this.onCommit = onCommit;
        this.onCancel = onCancel;
    }

    /** Shows the editor over the box with the box's text and takes the focus. */
    public void show() {
        String da = box.getDefaultAppearance(), ds = box.getDefaultStyleString();
        sizePt = FreeTextAppearance.fontSize(da);
        textColor = FreeTextAppearance.textColor(da);
        family = FreeTextAppearance.fontFamily(ds);
        style = FreeTextAppearance.fontStyle(ds);
        PDBorderStyleDictionary bs = box.getBorderStyle();
        borderPt = bs == null ? 0f : bs.getWidth();
        Color fill = AnnotationFactory.awtColor(box.getColor());

        String contents = box.getContents();
        area.setText(contents == null ? "" : contents);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setForeground(textColor);
        area.setCaretColor(textColor);
        area.setOpaque(fill != null);
        area.setBackground(fill != null ? fill : new Color(255, 255, 255, 0));
        area.setName("in-place-text");
        bind(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, InputEvent.CTRL_DOWN_MASK), "commit", this::commit);
        bind(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), "cancel", this::cancel);
        area.addFocusListener(new FocusAdapter() {
            @Override
            public void focusLost(FocusEvent e) {
                if (!e.isTemporary())
                    commit();
            }
        });
        area.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentResized(ComponentEvent e) {
                applyZoom();
            }
        });
        if (hideBox) {
            final COSDictionary hidden = box.getCOSObject();
            c.setAnnotationFilter(a -> a.getCOSObject() != hidden);
            c.invalidatePage(page);
        }
        c.showOverlay(area, page, viewRect);
        applyZoom();
        area.setCaretPosition(area.getText().length());
        area.requestFocusInWindow();
    }

    private void bind(KeyStroke key, String name, Runnable action) {
        area.getInputMap(JComponent.WHEN_FOCUSED).put(key, name);
        area.getActionMap().put(name, new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                action.run();
            }
        });
    }

    /** Font size, border and padding follow the zoom, like the box they stand in for. */
    private void applyZoom() {
        float z = c.zoom();
        area.setFont(new Font(EditorFonts.familyOrDefault(family), style, 12).deriveFont(sizePt * z));
        int inset = Math.max(0, Math.round(FreeTextAppearance.PADDING * z));
        Border padding = BorderFactory.createEmptyBorder(inset, inset, inset, inset);
        if (borderPt > 0)
            area.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createLineBorder(textColor, Math.max(1, Math.round(borderPt * z))), padding));
        else
            area.setBorder(padding);
    }

    /** @return the text area (tests type into it) */
    public JTextArea getTextArea() {
        return area;
    }

    /** @return the text as typed so far */
    public String getText() {
        return area.getText();
    }

    /** @return true until committed or cancelled */
    public boolean isActive() {
        return !done;
    }

    /** @return the box being edited */
    public PDAnnotationFreeText getBox() {
        return box;
    }

    /** Ends the edit and hands the text to the caller (no-op once ended). */
    public void commit() {
        if (done)
            return;
        done = true;
        String text = area.getText();
        hide();
        onCommit.accept(text);
    }

    /** Ends the edit, leaving the box as it was (no-op once ended). */
    public void cancel() {
        if (done)
            return;
        done = true;
        hide();
        onCancel.run();
    }

    private void hide() {
        c.hideOverlay();
        if (hideBox) {
            c.setAnnotationFilter(null);
            c.invalidatePage(page);
        }
        c.owner().requestFocusInWindow();
    }
}
