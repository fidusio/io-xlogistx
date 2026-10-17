package io.xlogistx.editor.pdf.tools;

import io.xlogistx.editor.pdf.EditorHost;
import io.xlogistx.editor.pdf.FormFields;
import io.xlogistx.editor.pdf.FormFields.Widget;
import io.xlogistx.editor.pdf.SetFieldValueEdit;
import io.xlogistx.gui.PDFToolContext;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.form.PDCheckBox;
import org.apache.pdfbox.pdmodel.interactive.form.PDChoice;
import org.apache.pdfbox.pdmodel.interactive.form.PDComboBox;
import org.apache.pdfbox.pdmodel.interactive.form.PDField;
import org.apache.pdfbox.pdmodel.interactive.form.PDRadioButton;
import org.apache.pdfbox.pdmodel.interactive.form.PDTextField;

import javax.swing.*;
import javax.swing.text.JTextComponent;
import java.awt.*;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.MouseEvent;
import java.awt.geom.Point2D;
import java.awt.geom.Rectangle2D;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Fills AcroForm fields: fillable widgets are outlined while the tool is
 * active; a click toggles a check box, selects a radio button, opens an inline
 * editor over a text field or a list over a combo / list box. The text editor
 * keeps what was typed whenever it closes (Enter, a click elsewhere, a tool
 * switch, undo, save, {@link #commitPending()}) except on Escape; a multi-line
 * field gets a text area where Ctrl+Enter commits. Every change is one
 * {@link SetFieldValueEdit}. Read-only, push-button and signature fields are
 * shown but ignored.
 */
public final class FormFillTool extends EditorTool {

    private static final Color OUTLINE = new Color(30, 110, 220, 110);
    private static final Color OUTLINE_LOCKED = new Color(150, 150, 150, 90);

    private final Map<Integer, List<Widget>> cache = new HashMap<>();
    private Popup popup;
    private Widget editing;
    /** Commits the text being typed in the open editor; null when none is open or it is a choice. */
    private Runnable pending;

    public FormFillTool(EditorHost host) {
        super(host);
    }

    @Override
    public String getName() {
        return "Fill form";
    }

    @Override
    public void activated(PDFToolContext c) {
        cache.clear();
        for (int p = 0; p < c.pageCount(); p++)
            c.repaintPage(p);
    }

    @Override
    public void deactivated(PDFToolContext c) {
        closePopup();
        cache.clear();
        super.deactivated(c);
        for (int p = 0; p < c.pageCount(); p++)
            c.repaintPage(p);
    }

    @Override
    public void cancel(PDFToolContext c) {
        discardPopup();
    }

    /**
     * Ends the open text edit keeping the typed text (undo, redo and save call
     * this first).
     *
     * @return true when a text editor was open
     */
    public boolean commitPending() {
        if (pending == null)
            return false;
        closePopup();
        return true;
    }

    /** @return the widget whose editor is open, null when none */
    public Widget getEditing() {
        return editing;
    }

    /** Forgets cached widget positions (after a page-tree change). */
    public void refresh(PDFToolContext c) {
        cache.clear();
        for (int p = 0; p < c.pageCount(); p++)
            c.repaintPage(p);
    }

    /** @return the widgets on a page (cached until {@link #refresh}) */
    public List<Widget> widgetsOn(PDFToolContext c, int page) {
        List<Widget> list = cache.get(page);
        if (list == null) {
            synchronized (c.docLock()) {
                PDDocument doc = c.document();
                list = doc == null ? new ArrayList<Widget>() : FormFields.widgetsOn(doc, page);
            }
            cache.put(page, list);
        }
        return list;
    }

    /** @return the widget under a view point on a page, null when none */
    public Widget widgetAt(PDFToolContext c, int page, Point2D viewPt) {
        Widget hit = null;
        for (Widget w : widgetsOn(c, page))
            if (w.getViewRect().contains(viewPt))
                hit = w; // last wins: drawn on top
        return hit;
    }

    @Override
    public void pressed(PDFToolContext c, MouseEvent e) {
        closePopup();
        int page = c.pageAt(e.getPoint());
        if (page < 0)
            return;
        Widget w = widgetAt(c, page, c.toPagePt(page, e.getPoint()));
        if (w == null || !w.isFillable())
            return;
        PDField f = w.getField();
        if (f instanceof PDCheckBox) {
            PDCheckBox cb = (PDCheckBox) f;
            setValue(c, f, cb.isChecked() ? "Off" : cb.getOnValue());
        } else if (f instanceof PDRadioButton) {
            String export = w.getExportValue();
            if (export != null)
                setValue(c, f, export);
        } else if (f instanceof PDTextField)
            editText(c, w);
        else if (f instanceof PDChoice)
            editChoice(c, w);
    }

    /**
     * Sets a field's value (undoable).
     *
     * @param value a String, or a List of Strings for a multi-select choice
     * @return true when applied
     */
    public boolean setValue(PDFToolContext c, PDField field, Object value) {
        try {
            return apply(c, new SetFieldValueEdit(c.panel(), field, value));
        } catch (IllegalArgumentException e) {
            c.showError(e.getMessage());
            return false;
        }
    }

    private void editText(PDFToolContext c, Widget w) {
        JTextComponent tc = textEditorFor(c, w);
        show(c, w, tc instanceof JTextArea ? new JScrollPane(tc) : tc, tc);
    }

    /**
     * Builds the editor for a text field and registers it as the open edit, so
     * that closing it in any way but Escape writes the text into the field:
     * Enter (Ctrl+Enter in a multi-line field), the focus moving elsewhere, a
     * press on the page, a tool switch or {@link #commitPending()}. A press on
     * the page shows it over the widget; public so the commit can be driven
     * without a screen.
     *
     * @param w a fillable text field widget
     * @return the text component, holding the field's current value
     */
    public JTextComponent textEditorFor(PDFToolContext c, Widget w) {
        closePopup();
        PDTextField f = (PDTextField) w.getField();
        String current = f.getValueAsString();
        JTextComponent tc;
        if (f.isMultiline()) {
            JTextArea area = new JTextArea(current);
            area.setLineWrap(true);
            area.setWrapStyleWord(true);
            tc = area;
        } else
            tc = new JTextField(current);
        tc.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyCode() == KeyEvent.VK_ESCAPE) {
                    discardPopup();
                    e.consume();
                } else if (e.getKeyCode() == KeyEvent.VK_ENTER && (!f.isMultiline() || e.isControlDown())) {
                    closePopup();
                    e.consume();
                }
            }
        });
        tc.addFocusListener(new FocusAdapter() {
            @Override
            public void focusLost(FocusEvent e) {
                // the focus went elsewhere (another control, another window) while this editor is
                // still the open edit: keep the text. Closing the editor itself clears `editing`
                // before the component goes away, so that focus loss is ignored.
                if (!e.isTemporary() && editing == w)
                    closePopup();
            }
        });
        editing = w;
        pending = () -> commitText(c, f, tc.getText());
        return tc;
    }

    private void commitText(PDFToolContext c, PDTextField f, String text) {
        if (!text.equals(f.getValueAsString()))
            setValue(c, f, text);
    }

    private void editChoice(PDFToolContext c, Widget w) {
        PDChoice f = (PDChoice) w.getField();
        List<String> display = f.getOptionsDisplayValues();
        List<String> export = f.getOptionsExportValues();
        if (f.isMultiSelect()) {
            JList<String> list = new JList<>(display.toArray(new String[0]));
            list.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
            List<String> current = f.getValue();
            List<Integer> idx = new ArrayList<>();
            for (int i = 0; i < export.size(); i++)
                if (current.contains(export.get(i)))
                    idx.add(i);
            int[] sel = new int[idx.size()];
            for (int i = 0; i < sel.length; i++)
                sel[i] = idx.get(i);
            list.setSelectedIndices(sel);
            int r = JOptionPane.showConfirmDialog(host.dialogParent(), new JScrollPane(list), "Select values", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
            if (r != JOptionPane.OK_OPTION)
                return;
            List<String> chosen = new ArrayList<>();
            for (int i : list.getSelectedIndices())
                chosen.add(export.get(i));
            setValue(c, f, chosen);
            return;
        }
        JComboBox<String> combo = new JComboBox<>(display.toArray(new String[0]));
        combo.setEditable(f instanceof PDComboBox && ((PDComboBox) f).isEdit());
        String current = f.getValueAsString();
        int at = export.indexOf(current);
        if (at >= 0)
            combo.setSelectedIndex(at);
        else if (combo.isEditable())
            combo.setSelectedItem(current);
        combo.addActionListener(e -> {
            if (editing != w)
                return;
            int i = combo.getSelectedIndex();
            String value = i >= 0 && i < export.size() ? export.get(i) : String.valueOf(combo.getSelectedItem());
            closePopup();
            if (!value.equals(current))
                setValue(c, f, value);
        });
        combo.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyCode() == KeyEvent.VK_ESCAPE)
                    closePopup();
            }
        });
        show(c, w, combo, combo);
    }

    /** Shows an editor over the widget's rectangle (or in a dialog when the pages are not on screen). */
    private void show(PDFToolContext c, Widget w, JComponent editor, JComponent focus) {
        if (editing != w) { // a choice editor; a text editor registered itself in textEditorFor
            closePopup();
            editing = w;
        }
        Rectangle2D.Float r = w.getViewRect();
        float z = c.zoom();
        Point topLeft = c.toPanelPoint(w.getPage(), new Point2D.Float(r.x, r.y));
        int width = Math.max(60, Math.round(r.width * z)), height = Math.max(22, Math.round(r.height * z));
        editor.setPreferredSize(new Dimension(width, height));
        editor.setSize(width, height);
        if (!c.owner().isShowing()) {
            // no screen: fall back to a dialog
            int res = JOptionPane.showConfirmDialog(host.dialogParent(), editor, w.getField().getPartialName(), JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
            if (res == JOptionPane.OK_OPTION)
                closePopup();
            else
                discardPopup();
            return;
        }
        Point screen = new Point(topLeft);
        SwingUtilities.convertPointToScreen(screen, c.owner());
        popup = PopupFactory.getSharedInstance().getPopup(c.owner(), editor, screen.x, screen.y);
        popup.show();
        focus.requestFocusInWindow();
        if (focus instanceof JTextField)
            ((JTextField) focus).selectAll();
        if (focus instanceof JComboBox)
            ((JComboBox<?>) focus).showPopup();
    }

    /** Closes the open editor keeping what was typed in it. */
    private void closePopup() {
        Runnable commit = pending;
        discardPopup();
        if (commit != null)
            commit.run();
    }

    /** Closes the open editor and drops what was typed in it. */
    private void discardPopup() {
        pending = null;
        editing = null;
        if (popup != null) {
            Popup p = popup;
            popup = null;
            p.hide();
        }
    }

    @Override
    public void paintOverlay(PDFToolContext c, int page, Graphics2D g2) {
        float z = c.zoom();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g2.setStroke(new BasicStroke(1f));
        for (Widget w : widgetsOn(c, page)) {
            Rectangle2D.Float r = w.getViewRect();
            g2.setColor(w.isFillable() ? OUTLINE : OUTLINE_LOCKED);
            g2.drawRect(px(r.x, z), px(r.y, z), Math.max(1, px(r.width, z)), Math.max(1, px(r.height, z)));
        }
    }

    @Override
    public Cursor cursor() {
        return Cursor.getPredefinedCursor(Cursor.HAND_CURSOR);
    }

    @Override
    public boolean followsLinks() {
        return false;
    }
}
