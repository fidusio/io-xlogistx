package io.xlogistx.editor.pdf;

import io.xlogistx.gui.pdf.PageTransform;
import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationWidget;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.pdmodel.interactive.form.PDCheckBox;
import org.apache.pdfbox.pdmodel.interactive.form.PDChoice;
import org.apache.pdfbox.pdmodel.interactive.form.PDField;
import org.apache.pdfbox.pdmodel.interactive.form.PDPushButton;
import org.apache.pdfbox.pdmodel.interactive.form.PDRadioButton;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;
import org.apache.pdfbox.pdmodel.interactive.form.PDTerminalField;
import org.apache.pdfbox.pdmodel.interactive.form.PDTextField;

import java.awt.geom.Rectangle2D;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Read-only helpers over a document's AcroForm: the fillable terminal fields,
 * the widgets on a page with their view-space rectangles, and which pages a
 * field's widgets sit on. Call under the document lock.
 */
public final class FormFields {

    /** A widget on a page together with its field. */
    public static final class Widget {
        private final PDTerminalField field;
        private final PDAnnotationWidget widget;
        private final Rectangle2D.Float viewRect;
        private final int page;

        Widget(PDTerminalField field, PDAnnotationWidget widget, Rectangle2D.Float viewRect, int page) {
            this.field = field;
            this.widget = widget;
            this.viewRect = viewRect;
            this.page = page;
        }

        public PDTerminalField getField() {
            return field;
        }

        public PDAnnotationWidget getWidget() {
            return widget;
        }

        /** @return the widget's rectangle in view space of its page */
        public Rectangle2D.Float getViewRect() {
            return viewRect;
        }

        public int getPage() {
            return page;
        }

        /** @return true when the field's value can be changed here */
        public boolean isFillable() {
            return FormFields.isFillable(field);
        }

        /** @return for radio buttons, the export value this widget stands for; null otherwise */
        public String getExportValue() {
            if (!(field instanceof PDRadioButton))
                return null;
            List<String> exports = ((PDRadioButton) field).getExportValues();
            List<PDAnnotationWidget> widgets = field.getWidgets();
            for (int i = 0; i < widgets.size(); i++)
                if (widgets.get(i).getCOSObject() == widget.getCOSObject())
                    return i < exports.size() ? exports.get(i) : onState(widget);
            return onState(widget);
        }

        @Override
        public String toString() {
            return field.getFullyQualifiedName() + "@" + page + viewRect;
        }
    }

    private FormFields() {
    }

    /** @return the document's AcroForm, null when it has none */
    public static PDAcroForm acroForm(PDDocument doc) {
        return doc == null ? null : doc.getDocumentCatalog().getAcroForm();
    }

    /** @return every terminal field of the form, in tree order; empty without a form */
    public static List<PDTerminalField> fields(PDDocument doc) {
        PDAcroForm form = acroForm(doc);
        if (form == null)
            return Collections.emptyList();
        List<PDTerminalField> ret = new ArrayList<>();
        for (PDField f : form.getFieldTree())
            if (f instanceof PDTerminalField)
                ret.add((PDTerminalField) f);
        return ret;
    }

    /** @return true for text, check box, radio and choice fields that are not read-only (push buttons and signatures are not) */
    public static boolean isFillable(PDField f) {
        if (f == null || f.isReadOnly() || f instanceof PDPushButton || f instanceof PDSignatureField)
            return false;
        return f instanceof PDTextField || f instanceof PDCheckBox || f instanceof PDRadioButton || f instanceof PDChoice;
    }

    /**
     * The widgets drawn on a page, with their fields.
     *
     * @param doc  the document
     * @param page zero-based page index
     * @return the widgets, empty without a form
     */
    public static List<Widget> widgetsOn(PDDocument doc, int page) {
        PDAcroForm form = acroForm(doc);
        if (form == null || page < 0 || page >= doc.getNumberOfPages())
            return Collections.emptyList();
        PDPage p = doc.getPage(page);
        PageTransform t = PageTransform.of(p);
        COSArray annots = p.getCOSObject().getCOSArray(COSName.ANNOTS);
        if (annots == null)
            return Collections.emptyList();
        List<Widget> ret = new ArrayList<>();
        for (PDTerminalField f : fields(doc))
            for (PDAnnotationWidget w : f.getWidgets()) {
                if (w.getRectangle() == null || !contains(annots, w.getCOSObject()))
                    continue;
                ret.add(new Widget(f, w, t.toViewRect(w.getRectangle()), page));
            }
        return ret;
    }

    /** @return the zero-based pages holding a widget of the field */
    public static int[] pagesOf(PDDocument doc, PDField field) {
        List<Integer> pages = new ArrayList<>();
        for (PDAnnotationWidget w : field.getWidgets()) {
            PDPage wp = w.getPage();
            int idx = wp == null ? -1 : doc.getPages().indexOf(wp);
            if (idx < 0)
                for (int i = 0; i < doc.getNumberOfPages() && idx < 0; i++) {
                    COSArray annots = doc.getPage(i).getCOSObject().getCOSArray(COSName.ANNOTS);
                    if (annots != null && contains(annots, w.getCOSObject()))
                        idx = i;
                }
            if (idx >= 0 && !pages.contains(idx))
                pages.add(idx);
        }
        int[] ret = new int[pages.size()];
        for (int i = 0; i < ret.length; i++)
            ret[i] = pages.get(i);
        return ret;
    }

    /**
     * @return the current value: a String (empty when the field has none), or a
     *         List of Strings for a multi-select choice
     */
    public static Object valueOf(PDField f) {
        if (f instanceof PDChoice) {
            List<String> v = ((PDChoice) f).getValue();
            if (((PDChoice) f).isMultiSelect())
                return new ArrayList<>(v);
            return v.isEmpty() ? "" : v.get(0);
        }
        if (f instanceof PDCheckBox)
            return ((PDCheckBox) f).isChecked() ? ((PDCheckBox) f).getOnValue() : "Off";
        String s = f.getValueAsString();
        return s == null ? "" : s;
    }

    /** @return the widget's "on" appearance state name (anything but Off), null when it has none */
    public static String onState(PDAnnotationWidget w) {
        COSBase ap = w.getCOSObject().getDictionaryObject(COSName.AP);
        if (!(ap instanceof COSDictionary))
            return null;
        COSBase n = ((COSDictionary) ap).getDictionaryObject(COSName.N);
        if (!(n instanceof COSDictionary))
            return null;
        for (COSName key : ((COSDictionary) n).keySet())
            if (!COSName.Off.equals(key))
                return key.getName();
        return null;
    }

    private static boolean contains(COSArray annots, COSDictionary dict) {
        for (int i = 0; i < annots.size(); i++)
            if (annots.getObject(i) == dict)
                return true;
        return false;
    }
}
