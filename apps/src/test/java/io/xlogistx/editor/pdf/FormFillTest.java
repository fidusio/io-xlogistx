package io.xlogistx.editor.pdf;

import io.xlogistx.editor.pdf.tools.FormFillTool;
import io.xlogistx.gui.PDFViewerPanel;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.PDResources;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationWidget;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceDictionary;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceEntry;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceStream;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.pdmodel.interactive.form.PDCheckBox;
import org.apache.pdfbox.pdmodel.interactive.form.PDComboBox;
import org.apache.pdfbox.pdmodel.interactive.form.PDField;
import org.apache.pdfbox.pdmodel.interactive.form.PDTerminalField;
import org.apache.pdfbox.pdmodel.interactive.form.PDTextField;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.swing.*;
import java.awt.*;
import java.awt.geom.Point2D;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.function.BooleanSupplier;

import static org.junit.jupiter.api.Assertions.*;

/** AcroForm filling: a text field, a check box and a combo box built in the test. */
public class FormFillTest {

    /** Widget rectangles in PDF space on an A4 page. */
    private static final PDRectangle TEXT_RECT = new PDRectangle(50, 700, 200, 24);
    private static final PDRectangle CHECK_RECT = new PDRectangle(50, 650, 20, 20);
    private static final PDRectangle COMBO_RECT = new PDRectangle(50, 600, 150, 24);

    private static byte[] formPDF;
    private PDFEditorPane pane;
    private PDFViewerPanel viewer;

    @BeforeAll
    static void headless() throws Exception {
        System.setProperty("java.awt.headless", "true");
        formPDF = buildForm();
    }

    @BeforeEach
    void setUp() throws Exception {
        pane = onEDT(() -> {
            PDFEditorPane p = new PDFEditorPane();
            p.setSize(700, 900);
            layoutTree(p);
            return p;
        });
        viewer = pane.getViewer();
        PDDocument doc = Loader.loadPDF(formPDF);
        onEDT(() -> {
            viewer.setDocument(doc, true);
            layoutTree(pane);
            pane.setEditable(true);
            return null;
        });
    }

    @AfterEach
    void tearDown() throws Exception {
        onEDT(() -> {
            viewer.close();
            return null;
        });
    }

    @Test
    void listsFieldsAndWidgets() throws Exception {
        List<PDTerminalField> fields = onEDT(pane::getFormFields);
        assertEquals(Arrays.asList("name", "agree", "colour", "locked"), names(fields));
        assertTrue(FormFields.isFillable(fields.get(0)));
        assertTrue(FormFields.isFillable(fields.get(1)));
        assertTrue(FormFields.isFillable(fields.get(2)));
        assertFalse(FormFields.isFillable(fields.get(3)), "read-only");

        FormFillTool tool = (FormFillTool) pane.getTool(PDFEditorPane.EditTool.FORM);
        List<FormFields.Widget> widgets = onEDT(() -> tool.widgetsOn(viewer.getToolContext(), 0));
        assertEquals(4, widgets.size());
        FormFields.Widget text = widgets.get(0);
        assertEquals("name", text.getField().getPartialName());
        // the text widget's top edge is (page height - 724) pt from the top
        assertEquals(50, text.getViewRect().x, 0.01);
        assertEquals(PDRectangle.A4.getHeight() - 724, text.getViewRect().y, 0.01);
        assertSame(text, onEDT(() -> tool.widgetAt(viewer.getToolContext(), 0, new Point2D.Float(60, 125))));
        assertNull(onEDT(() -> tool.widgetAt(viewer.getToolContext(), 0, new Point2D.Float(400, 400))));
        assertArrayEquals(new int[]{0}, onEDT(() -> {
            synchronized (viewer.getDocumentLock()) {
                return FormFields.pagesOf(viewer.getDocument(), fields.get(0));
            }
        }));
    }

    @Test
    void textValueIsSetRenderedSavedAndUndone() throws Exception {
        PDField name = field("name");
        waitFor(() -> viewer.getPageImage(0) != null, 10000);
        BufferedImage blank = onEDT(() -> viewer.getPageImage(0));
        assertFalse(darkInside(blank, TEXT_RECT), "the empty field renders blank");

        assertTrue(onEDT(() -> pane.setFieldValue(name, "Hello forms")));
        assertEquals("Hello forms", valueOf("name"));
        assertTrue(pane.isModified());
        assertEquals("Fill field \"name\"", pane.getEditModel().peekUndo().name());
        waitFor(() -> viewer.getPageImage(0) != null && viewer.getPageImage(0) != blank, 10000);
        assertTrue(darkInside(onEDT(() -> viewer.getPageImage(0)), TEXT_RECT), "the value is drawn into the widget");

        onEDT(pane::undo);
        assertEquals("", valueOf("name"));
        assertFalse(pane.isModified());
        onEDT(pane::redo);
        assertEquals("Hello forms", valueOf("name"));

        File out = File.createTempFile("pdfeditor-form", ".pdf");
        out.deleteOnExit();
        onEDT(() -> {
            viewer.save(out);
            return null;
        });
        waitFor(() -> !pane.isModified(), 15000);
        try (PDDocument saved = Loader.loadPDF(out)) {
            assertEquals("Hello forms", saved.getDocumentCatalog().getAcroForm().getField("name").getValueAsString());
        }
    }

    @Test
    void checkBoxAndComboAreUndoable() throws Exception {
        PDCheckBox agree = (PDCheckBox) field("agree");
        assertFalse(agree.isChecked());
        assertTrue(onEDT(() -> pane.setFieldValue(agree, agree.getOnValue())));
        assertTrue(agree.isChecked());
        assertEquals("Yes", valueOf("agree"));
        onEDT(pane::undo);
        assertFalse(agree.isChecked());
        onEDT(pane::redo);
        assertTrue(agree.isChecked());
        assertTrue(onEDT(() -> pane.setFieldValue(agree, "Off")));
        assertFalse(agree.isChecked());

        PDComboBox colour = (PDComboBox) field("colour");
        assertTrue(colour.getValue().isEmpty());
        assertEquals("", FormFields.valueOf(colour));
        assertTrue(onEDT(() -> pane.setFieldValue(colour, "green")));
        assertEquals(Arrays.asList("green"), colour.getValue());
        assertEquals("green", FormFields.valueOf(colour));
        onEDT(pane::undo);
        assertTrue(colour.getValue().isEmpty(), "back to no selection");
        onEDT(pane::redo);
        assertEquals(Arrays.asList("green"), colour.getValue());
        assertEquals(3, pane.getEditModel().getUndoDepth(), "check, uncheck, combo (undo/redo do not add steps)");
    }

    @Test
    void readOnlyFieldIsRefused() throws Exception {
        PDField locked = field("locked");
        assertThrows(IllegalArgumentException.class, () -> new SetFieldValueEdit(viewer, locked, "x"));
        assertEquals("fixed", valueOf("locked"));
    }

    // ---------------------------------------------------------------- helpers

    /** An A4 page with a text field, a check box (Yes/Off appearances), a combo box and a read-only text field. */
    private static byte[] buildForm() throws Exception {
        try (PDDocument doc = new PDDocument()) {
            PDPage page = new PDPage(PDRectangle.A4);
            doc.addPage(page);
            PDAcroForm form = new PDAcroForm(doc);
            doc.getDocumentCatalog().setAcroForm(form);
            PDResources res = new PDResources();
            res.put(COSName.getPDFName("Helv"), new PDType1Font(Standard14Fonts.FontName.HELVETICA));
            form.setDefaultResources(res);
            form.setDefaultAppearance("/Helv 0 Tf 0 g");

            PDTextField name = new PDTextField(form);
            name.setPartialName("name");
            name.setDefaultAppearance("/Helv 12 Tf 0 g");
            widget(name, page, TEXT_RECT);
            form.getFields().add(name);

            PDCheckBox agree = new PDCheckBox(form);
            agree.setPartialName("agree");
            PDAnnotationWidget cw = widget(agree, page, CHECK_RECT);
            PDAppearanceDictionary ap = new PDAppearanceDictionary();
            COSDictionary states = new COSDictionary();
            states.setItem(COSName.getPDFName("Yes"), cross(doc, CHECK_RECT));
            states.setItem(COSName.Off, blank(doc, CHECK_RECT));
            ap.setNormalAppearance(new PDAppearanceEntry(states));
            cw.setAppearance(ap);
            cw.setAppearanceState("Off");
            form.getFields().add(agree);

            PDComboBox colour = new PDComboBox(form);
            colour.setPartialName("colour");
            colour.setDefaultAppearance("/Helv 12 Tf 0 g");
            colour.setOptions(Arrays.asList("red", "green", "blue"));
            widget(colour, page, COMBO_RECT);
            form.getFields().add(colour);

            PDTextField locked = new PDTextField(form);
            locked.setPartialName("locked");
            locked.setDefaultAppearance("/Helv 12 Tf 0 g");
            widget(locked, page, new PDRectangle(300, 700, 150, 24));
            locked.setValue("fixed");
            locked.setReadOnly(true);
            form.getFields().add(locked);

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            doc.save(out);
            return out.toByteArray();
        }
    }

    private static PDAnnotationWidget widget(PDTerminalField field, PDPage page, PDRectangle rect) throws Exception {
        PDAnnotationWidget w = field.getWidgets().get(0);
        w.setRectangle(rect);
        w.setPage(page);
        page.getAnnotations().add(w);
        return w;
    }

    private static PDAppearanceStream cross(PDDocument doc, PDRectangle r) throws Exception {
        PDAppearanceStream s = new PDAppearanceStream(doc);
        s.setBBox(new PDRectangle(0, 0, r.getWidth(), r.getHeight()));
        try (PDPageContentStream cs = new PDPageContentStream(doc, s)) {
            cs.setLineWidth(2);
            cs.moveTo(3, 3);
            cs.lineTo(r.getWidth() - 3, r.getHeight() - 3);
            cs.moveTo(3, r.getHeight() - 3);
            cs.lineTo(r.getWidth() - 3, 3);
            cs.stroke();
        }
        return s;
    }

    private static PDAppearanceStream blank(PDDocument doc, PDRectangle r) throws Exception {
        PDAppearanceStream s = new PDAppearanceStream(doc);
        s.setBBox(new PDRectangle(0, 0, r.getWidth(), r.getHeight()));
        try (PDPageContentStream cs = new PDPageContentStream(doc, s)) {
            cs.setLineWidth(1);
            cs.addRect(0.5f, 0.5f, r.getWidth() - 1, r.getHeight() - 1);
            cs.stroke();
        }
        return s;
    }

    private static List<String> names(List<PDTerminalField> fields) {
        String[] n = new String[fields.size()];
        for (int i = 0; i < n.length; i++)
            n[i] = fields.get(i).getPartialName();
        return Arrays.asList(n);
    }

    private PDField field(String name) throws Exception {
        return onEDT(() -> {
            synchronized (viewer.getDocumentLock()) {
                return viewer.getDocument().getDocumentCatalog().getAcroForm().getField(name);
            }
        });
    }

    private String valueOf(String name) throws Exception {
        return onEDT(() -> {
            synchronized (viewer.getDocumentLock()) {
                return viewer.getDocument().getDocumentCatalog().getAcroForm().getField(name).getValueAsString();
            }
        });
    }

    /** Dark pixel inside the widget's rectangle (PDF space on an A4 page rendered at the viewer's zoom). */
    private boolean darkInside(BufferedImage img, PDRectangle r) {
        float z = img.getWidth() / PDRectangle.A4.getWidth();
        int x1 = Math.round((r.getLowerLeftX() + 2) * z), x2 = Math.round((r.getUpperRightX() - 2) * z);
        int y1 = Math.round((PDRectangle.A4.getHeight() - r.getUpperRightY() + 2) * z), y2 = Math.round((PDRectangle.A4.getHeight() - r.getLowerLeftY() - 2) * z);
        for (int y = y1; y < y2; y++)
            for (int x = x1; x < x2; x++)
                if ((img.getRGB(x, y) & 0xff) < 100)
                    return true;
        return false;
    }

    private static void layoutTree(Component c) {
        c.doLayout();
        if (c instanceof Container)
            for (Component child : ((Container) c).getComponents())
                layoutTree(child);
        if (c instanceof Container)
            c.doLayout();
    }

    private static <T> T onEDT(Callable<T> call) throws Exception {
        Object[] result = new Object[1];
        Exception[] error = new Exception[1];
        SwingUtilities.invokeAndWait(() -> {
            try {
                result[0] = call.call();
            } catch (Exception e) {
                error[0] = e;
            }
        });
        if (error[0] != null)
            throw error[0];
        @SuppressWarnings("unchecked")
        T t = (T) result[0];
        return t;
    }

    private void waitFor(BooleanSupplier condition, long timeoutMs) throws Exception {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < deadline) {
            if (onEDT(condition::getAsBoolean))
                return;
            Thread.sleep(50);
        }
        fail("condition not met within " + timeoutMs + " ms");
    }
}
