package io.xlogistx.editor.pdf;

import io.xlogistx.gui.PDFViewerPanel;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.pdmodel.interactive.form.PDCheckBox;
import org.apache.pdfbox.pdmodel.interactive.form.PDChoice;
import org.apache.pdfbox.pdmodel.interactive.form.PDField;
import org.zoxweb.shared.util.SUS;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Undoable change of a form field's value. Values are a {@code String} (text,
 * check box on-value or {@code "Off"}, radio export value, single choice) or a
 * {@code List<String>} for a multi-select choice. PDFBox regenerates the widget
 * appearances in {@code setValue}; when the form says {@code NeedAppearances}
 * they are refreshed explicitly, then every page holding a widget of the field
 * is re-rendered.
 */
public final class SetFieldValueEdit implements PDFEdit {

    private final PDFViewerPanel panel;
    private final PDField field;
    private final Object before;
    private final Object after;
    private int[] pages = new int[0];

    /**
     * @param panel the panel showing the document, never null
     * @param field the field, never null and {@linkplain FormFields#isFillable(PDField) fillable}
     * @param after the new value: a String, or a List of Strings for a multi-select choice
     */
    public SetFieldValueEdit(PDFViewerPanel panel, PDField field, Object after) {
        this(panel, field, FormFields.valueOf(field), after);
    }

    public SetFieldValueEdit(PDFViewerPanel panel, PDField field, Object before, Object after) {
        SUS.checkIfNull("panel null", panel);
        SUS.checkIfNull("field null", field);
        if (!FormFields.isFillable(field))
            throw new IllegalArgumentException("Field '" + field.getFullyQualifiedName() + "' cannot be filled (read-only, button or signature).");
        this.panel = panel;
        this.field = field;
        this.before = copy(before);
        this.after = copy(after);
    }

    @Override
    public String name() {
        String n = field.getPartialName();
        return "Fill field" + (n == null || n.isEmpty() ? "" : " \"" + n + "\"");
    }

    @Override
    public void apply() throws IOException {
        set(after);
    }

    @Override
    public void revert() throws IOException {
        set(before);
    }

    private void set(Object value) throws IOException {
        synchronized (panel.getDocumentLock()) {
            PDDocument doc = panel.getDocument();
            if (doc == null)
                return;
            if (field instanceof PDCheckBox) {
                PDCheckBox cb = (PDCheckBox) field;
                if (value == null || "Off".equals(value) || "".equals(value))
                    cb.unCheck();
                else
                    cb.check();
            } else if (value instanceof List) {
                if (!(field instanceof PDChoice))
                    throw new IllegalArgumentException("only choice fields take a list of values");
                @SuppressWarnings("unchecked")
                List<String> list = (List<String>) value;
                ((PDChoice) field).setValue(list);
            } else if (field instanceof PDChoice && (value == null || value.toString().isEmpty())) {
                ((PDChoice) field).setValue((String) null); // no selection: remove V
            } else
                field.setValue(value == null ? "" : value.toString());
            PDAcroForm form = field.getAcroForm();
            if (form != null && form.getNeedAppearances())
                form.refreshAppearances(Collections.singletonList(field));
            pages = FormFields.pagesOf(doc, field);
        }
        for (int p : pages)
            panel.invalidatePage(p);
    }

    @Override
    public int[] affectedPages() {
        return pages.clone();
    }

    @Override
    public boolean structural() {
        return false;
    }

    /** @return the field */
    public PDField getField() {
        return field;
    }

    /** @return the value this edit sets */
    public Object getValue() {
        return copy(after);
    }

    private static Object copy(Object v) {
        return v instanceof List ? new ArrayList<>((List<?>) v) : v;
    }
}
