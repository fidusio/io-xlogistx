package io.xlogistx.editor.pdf;

import io.xlogistx.editor.pdf.tools.FreeTextTool;
import io.xlogistx.editor.pdf.tools.SelectAnnotationTool;
import io.xlogistx.gui.MDToPDF;
import io.xlogistx.gui.PDFToolContext;
import io.xlogistx.gui.PDFViewerPanel;
import io.xlogistx.gui.pdf.PageTransform;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDResources;
import org.apache.pdfbox.pdmodel.font.PDFont;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationFreeText;
import org.apache.pdfbox.text.PDFTextStripper;
import org.apache.pdfbox.text.TextPosition;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.swing.JComboBox;
import javax.swing.SwingUtilities;
import java.awt.Color;
import java.awt.Component;
import java.awt.Container;
import java.awt.Font;
import java.awt.geom.Rectangle2D;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.function.BooleanSupplier;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Fonts, sizes and colours for text: the font registry, text boxes in a
 * chosen family / face (kept in the annotation's DS, round-tripped by the
 * selection tool, undone), and in-place page text rewritten in another font,
 * size and colour with the rest of the line untouched.
 */
public class TextFontTest {

    private static final String ARIAL = "Arial";
    private static byte[] pdf;
    private PDFEditorPane pane;
    private PDFViewerPanel viewer;

    @BeforeAll
    static void headless() throws Exception {
        System.setProperty("java.awt.headless", "true");
        pdf = MDToPDF.mdToPDF("# One\n\nfirst page text").toByteArray();
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
        PDDocument doc = Loader.loadPDF(pdf);
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
    void registryListsTheBundledFamilyFirstAndLoadsFacesOncePerDocument() throws Exception {
        List<String> families = EditorFonts.families();
        assertEquals(EditorFonts.DEFAULT_FAMILY, families.get(0));
        assertFalse(families.contains("Dialog"), "logical families are left out");
        assertFalse(families.contains("SansSerif"));
        assertEquals("Arial Bold Italic", EditorFonts.describe("Arial", Font.BOLD | Font.ITALIC));
        assertEquals(EditorFonts.DEFAULT_FAMILY, EditorFonts.familyOrDefault(" "));
        try (PDDocument doc = new PDDocument()) {
            PDFont regular = EditorFonts.load(doc, null, Font.PLAIN);
            PDFont bold = EditorFonts.load(doc, "roboto", Font.BOLD);
            assertTrue(regular.getName().contains("Roboto-Regular"), regular.getName());
            assertTrue(bold.getName().contains("Roboto-Bold"), bold.getName());
            assertNotSame(regular, EditorFonts.load(doc, "Roboto", Font.PLAIN), "a fresh font per use");
            // sealing builds the subset at once: the font is complete in memory and off the save-time list
            assertNull(bold.getFontDescriptor().getFontFile2(), "no program until sealed");
            bold.encode("first");
            EditorFonts.seal(doc, bold);
            assertNotNull(bold.getFontDescriptor().getFontFile2(), "program written");
            assertFalse(EditorFonts.fontsToSubset(doc).contains(bold), "PDFBox must not subset it again at save");
            assertTrue(bold.getName().matches("[A-Z]{6}\\+Roboto-Bold"), bold.getName());
            EditorFonts.seal(doc, bold); // a second seal is a no-op
            IOException e = assertThrows(IOException.class, () -> EditorFonts.load(doc, "No Such Font Family 12345", Font.PLAIN));
            assertTrue(e.getMessage().contains("No Such Font Family"), e.getMessage());
            // the face and family of a document font
            assertEquals(Font.BOLD, EditorFonts.styleOf(bold));
            assertEquals(Font.PLAIN, EditorFonts.styleOf(regular));
            assertEquals("Roboto", EditorFonts.familyOf(bold));
            if (EditorFonts.families().contains(ARIAL)) {
                PDFont arial = EditorFonts.load(doc, ARIAL, Font.BOLD | Font.ITALIC);
                assertEquals(Font.BOLD | Font.ITALIC, EditorFonts.styleOf(arial));
                assertEquals(ARIAL, EditorFonts.familyOf(arial));
            }
            assertNull(EditorFonts.familyOf(new org.apache.pdfbox.pdmodel.font.PDType1Font(org.apache.pdfbox.pdmodel.font.Standard14Fonts.FontName.ZAPF_DINGBATS)));
        }
        JComboBox<String> combo = EditorDialogs.fontCombo("Roboto");
        assertEquals("Roboto", combo.getSelectedItem());
        EditorDialogs.selectFamily(combo, "Not Installed Family");
        assertEquals("Not Installed Family", combo.getSelectedItem(), "a document's unknown family is listed so it can be kept");
    }

    @Test
    void textBoxUsesTheChosenFontAndFaceAndRoundTripsThroughTheSelection() throws Exception {
        Assumptions.assumeTrue(EditorFonts.families().contains(ARIAL), "Arial is installed");
        waitFor(() -> viewer.getPageImage(0) != null, 10000);
        AnnotationStyle arial = AnnotationStyle.TEXT.withFontFamily(ARIAL).withFontStyle(Font.BOLD | Font.ITALIC).withFontSize(14f).withUnderline(true).withStrikethrough(true).withHighlightColor(Color.YELLOW);
        onEDT(() -> pane.setStyle(EditorHost.StyleKey.TEXT, arial));
        FreeTextTool tool = (FreeTextTool) pane.getTool(PDFEditorPane.EditTool.TEXT_BOX);
        Rectangle2D.Float box = new Rectangle2D.Float(100, 400, 200, 60);
        PDAnnotationFreeText ft = onEDT(() -> tool.addFreeText(ctx(), 0, box, "Ünïcödé in Arial"));
        assertNotNull(ft);
        String ds = ft.getDefaultStyleString();
        assertTrue(ds.contains("font-family: Arial"), ds);
        assertTrue(ds.contains("font-weight: bold"), ds);
        assertTrue(ds.contains("font-style: italic"), ds);
        assertTrue(ds.contains("text-decoration: underline line-through"), ds);
        assertTrue(ds.contains("background-color: #FFFF00"), ds);
        assertEquals(3, countOf(appearanceContent(ft), " re\n"), "a highlight band, one bar under and one through the single line");
        assertTrue(appearanceContent(ft).indexOf(" re\n") < appearanceContent(ft).indexOf("BT"), "the highlight is painted before the text");
        assertTrue(ft.getDefaultAppearance().startsWith("/Helv 14"), ft.getDefaultAppearance());
        assertTrue(appearanceFont(ft).contains("Arial-BoldItalicMT"), appearanceFont(ft));
        assertTrue(appearanceFontEmbedded(ft), "sealed: the glyphs are right before any save");
        waitFor(() -> darkInside(viewer.getPageImage(0), box, viewer.getZoom()), 10000);
        assertTrue(yellowish(onEDT(() -> viewer.getPageImage(0)), box, viewer.getZoom()), "the highlight shows behind the text");

        // the selection tool reads the font back and writes a new one
        onEDT(() -> pane.selectAnnotation(0, ft));
        SelectAnnotationTool select = (SelectAnnotationTool) pane.getTool(PDFEditorPane.EditTool.SELECT);
        AnnotationStyle read = onEDT(() -> select.styleOf(ctx()));
        assertEquals(ARIAL, read.getFontFamily());
        assertTrue(read.isBold() && read.isItalic() && read.isUnderline() && read.isStrikethrough(), read.toString());
        assertEquals(Color.YELLOW, read.getHighlightColor());
        assertEquals(14f, read.getFontSize(), 0.01);
        assertTrue(onEDT(() -> pane.applyStyleToSelection(read.withFontFamily(null).withFontStyle(Font.PLAIN).withUnderline(false).withStrikethrough(false).withHighlightColor(null).withStrokeColor(Color.BLUE))));
        assertFalse(ft.getDefaultStyleString().contains("background-color"), ft.getDefaultStyleString());
        assertTrue(ft.getDefaultStyleString().contains("font-family: Roboto"), ft.getDefaultStyleString());
        assertTrue(ft.getDefaultStyleString().contains("text-decoration: none"), ft.getDefaultStyleString());
        assertFalse(appearanceContent(ft).contains(" re"), "no bar without underline");
        assertTrue(appearanceFont(ft).contains("Roboto-Regular"), appearanceFont(ft));
        assertEquals(Color.BLUE, FreeTextAppearance.textColor(ft.getDefaultAppearance()));
        onEDT(pane::undo);
        assertTrue(ft.getDefaultStyleString().contains("font-family: Arial"), "DS is part of the undo snapshot");
        assertTrue(appearanceFont(ft).contains("Arial-BoldItalicMT"), appearanceFont(ft));

        // a family the system lacks falls back to the bundled one without failing
        onEDT(() -> pane.setStyle(EditorHost.StyleKey.TEXT, AnnotationStyle.TEXT.withFontFamily("No Such Font Family 12345")));
        PDAnnotationFreeText odd = onEDT(() -> tool.addFreeText(ctx(), 0, new Rectangle2D.Float(100, 500, 200, 40), "fallback"));
        assertNotNull(odd);
        assertTrue(odd.getDefaultStyleString().contains("No Such Font Family"), "the wish is kept");
        assertTrue(appearanceFont(odd).contains("Roboto"), appearanceFont(odd));

        // the DS parser copes with other writers' forms
        assertEquals("Times New Roman", FreeTextAppearance.fontFamily("font: 12pt; font-family: \"Times New Roman\", serif; color: #000"));
        assertEquals(Font.BOLD, FreeTextAppearance.fontStyle("font-weight: 700"));
        assertEquals(Font.ITALIC, FreeTextAppearance.fontStyle("font-style: oblique"));
        assertEquals(EditorFonts.DEFAULT_FAMILY, FreeTextAppearance.fontFamily(null));
        assertEquals(1, FreeTextAppearance.q(TextEditor.Alignment.CENTER));
        assertEquals(TextEditor.Alignment.RIGHT, FreeTextAppearance.alignment(2));
        assertEquals(TextEditor.Alignment.LEFT, FreeTextAppearance.alignment(7));
        assertTrue(FreeTextAppearance.underline("text-decoration: underline"));
        assertFalse(FreeTextAppearance.underline("text-decoration: none"));
        assertTrue(FreeTextAppearance.strikethrough("text-decoration: line-through"));
        assertFalse(FreeTextAppearance.strikethrough("text-decoration: underline"));
        assertTrue(FreeTextAppearance.defaultStyle(AnnotationStyle.TEXT.withStrikethrough(true)).contains("text-decoration: line-through;"));
        assertEquals(new Color(0x12, 0x34, 0x56), FreeTextAppearance.highlight("background-color: #123456"));
        assertEquals(Color.WHITE, FreeTextAppearance.highlight("background-color:#fff"));
        assertNull(FreeTextAppearance.highlight("background-color: transparent"));
        assertNull(FreeTextAppearance.highlight("color: #000"));
    }

    @Test
    void pageTextGetsAnotherFaceOfItsOwnFamilyAndAnUnderline() throws Exception {
        waitFor(() -> viewer.getPageImage(0) != null, 10000);
        TextEditor.Glyph originalF = glyph("f", 0);
        assertEquals(Font.PLAIN, EditorFonts.styleOf(originalF.font), originalF.font.getName());
        assertEquals("Roboto", EditorFonts.familyOf(originalF.font), "the page font is a subset of the bundled family");
        float originalSize = originalF.renderedSize();

        // bold + underline, font kept: the bundled bold face is used, a line is stroked under the word
        selectWord("first");
        assertTrue(onEDT(() -> pane.replaceSelectedText("first", TextEditor.Alignment.LEFT,
                new TextEditor.Format(null, Font.BOLD, 0f, null, true))));
        assertEquals("first page text", bodyLine());
        TextEditor.Glyph f = glyph("f", 0);
        assertTrue(f.font.getName().contains("Roboto-Bold"), f.font.getName());
        assertEquals(Font.BOLD, EditorFonts.styleOf(f.font));
        assertEquals(originalSize, f.renderedSize(), 0.05, "same size");
        TextEditor.Glyph p = glyph("p", "first page text".indexOf('p'));
        assertTrue(p.font.getName().contains("Roboto-Regular"), "the rest keeps its face: " + p.font.getName());
        PDPage edited = page();
        String content = new String(onEDT(() -> {
            synchronized (viewer.getDocumentLock()) {
                return TextEditor.originalContent(edited);
            }
        }), "ISO-8859-1");
        assertTrue(content.contains(" RG") && content.contains(" l\nS"), "a stroked underline after the text object: " + content);
        assertTrue(content.indexOf(" l\nS") > content.indexOf("ET"), "drawn after ET");
        // the line sits just under the baseline of the word (no descenders in "first"), not elsewhere
        PageTransform t = PageTransform.of(page());
        java.awt.geom.Point2D.Float base = t.toView(new java.awt.geom.Point2D.Float(f.x, f.y));
        float drop = FreeTextAppearance.UNDERLINE_DROP * originalSize;
        float wordWidth = glyph("t", 4).x + glyph("t", 4).width - f.x;
        Rectangle2D.Float band = new Rectangle2D.Float(base.x + 1, base.y + drop - 1f, wordWidth - 2, 2.5f);
        Rectangle2D.Float below = new Rectangle2D.Float(base.x + 1, base.y + drop + 3f, wordWidth - 2, 3f);
        waitFor(() -> anyDark(viewer.getPageImage(0), band, viewer.getZoom()), 10000);
        assertFalse(anyDark(onEDT(() -> viewer.getPageImage(0)), below, viewer.getZoom()), "nothing further down");
        onEDT(pane::undo);
        assertTrue(glyph("f", 0).font.getName().contains("Roboto-Regular"));
        waitFor(() -> !anyDark(viewer.getPageImage(0), band, viewer.getZoom()), 10000);

        // strikethrough, everything else kept: a line through the x-height of the word, nothing under it
        selectWord("first");
        assertTrue(onEDT(() -> pane.replaceSelectedText("first", TextEditor.Alignment.LEFT,
                new TextEditor.Format(null, TextEditor.Format.KEEP_STYLE, 0f, null, false, true))));
        assertEquals("first page text", bodyLine());
        assertTrue(glyph("f", 0).font.getName().contains("Roboto-Regular"), "face kept");
        float rise = FreeTextAppearance.STRIKE_RISE * originalSize;
        // the bar spans the word only: nothing left of it at that height, nothing under the baseline
        Rectangle2D.Float strikeBand = new Rectangle2D.Float(base.x + 1, base.y - rise - 1f, wordWidth - 2, 2.5f);
        Rectangle2D.Float leftOfWord = new Rectangle2D.Float(base.x - 5f, base.y - rise - 1f, 3f, 2.5f);
        waitFor(() -> anyDark(viewer.getPageImage(0), strikeBand, viewer.getZoom()), 10000);
        assertFalse(anyDark(onEDT(() -> viewer.getPageImage(0)), band, viewer.getZoom()), "no underline");
        assertFalse(anyDark(onEDT(() -> viewer.getPageImage(0)), leftOfWord, viewer.getZoom()), "the bar starts at the word");
        PDPage struck = page();
        String struckContent = new String(onEDT(() -> {
            synchronized (viewer.getDocumentLock()) {
                return TextEditor.originalContent(struck);
            }
        }), "ISO-8859-1");
        assertEquals(1, countOf(struckContent, " l\nS"), "one stroked line");
        onEDT(pane::undo);
        assertEquals(0, countOf(new String(onEDT(() -> {
            synchronized (viewer.getDocumentLock()) {
                return TextEditor.originalContent(struck);
            }
        }), "ISO-8859-1"), " l\nS"));

        // a highlight: a yellow band behind the word, painted before its text object, the glyphs still on top
        selectWord("first");
        assertTrue(onEDT(() -> pane.replaceSelectedText("first", TextEditor.Alignment.LEFT,
                new TextEditor.Format(null, TextEditor.Format.KEEP_STYLE, 0f, null, false, false, Color.YELLOW))));
        assertEquals("first page text", bodyLine());
        PDPage lit = page();
        String litContent = new String(onEDT(() -> {
            synchronized (viewer.getDocumentLock()) {
                return TextEditor.originalContent(lit);
            }
        }), "ISO-8859-1");
        int fillAt = litContent.lastIndexOf("h\nf\n");
        assertTrue(fillAt > 0, "a filled band: " + litContent);
        assertTrue(fillAt < litContent.lastIndexOf("BT") && fillAt > litContent.indexOf("ET"), "before the body text object, after the heading's");
        Rectangle2D.Float wordBox = new Rectangle2D.Float(base.x, base.y - originalSize * 0.9f, wordWidth, originalSize * 1.1f);
        waitFor(() -> yellowish(viewer.getPageImage(0), wordBox, viewer.getZoom()), 10000);
        assertTrue(anyDark(onEDT(() -> viewer.getPageImage(0)), wordBox, viewer.getZoom()), "the text is still on top");
        assertFalse(yellowish(onEDT(() -> viewer.getPageImage(0)), new Rectangle2D.Float(base.x + wordWidth + 20, base.y - originalSize * 0.9f, 30, originalSize * 1.1f), viewer.getZoom()),
                "the band covers the word only");
        onEDT(pane::undo);
        waitFor(() -> !yellowish(viewer.getPageImage(0), wordBox, viewer.getZoom()), 10000);

        // italic on a kept font whose family is not installed is refused with a hint
        try (PDDocument doc = new PDDocument()) {
            PDPage pg = new PDPage();
            doc.addPage(pg);
            org.apache.pdfbox.pdmodel.font.PDType1Font dingbats = new org.apache.pdfbox.pdmodel.font.PDType1Font(org.apache.pdfbox.pdmodel.font.Standard14Fonts.FontName.COURIER); // no "Courier" TrueType family installed, only "Courier New"
            try (org.apache.pdfbox.pdmodel.PDPageContentStream cs = new org.apache.pdfbox.pdmodel.PDPageContentStream(doc, pg)) {
                cs.beginText();
                cs.setFont(dingbats, 12);
                cs.newLineAtOffset(50, 700);
                cs.showText("abc");
                cs.endText();
            }
            List<TextEditor.Glyph> glyphs = TextEditor.glyphs(pg);
            assertEquals(3, glyphs.size());
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> TextEditor.replace(doc, pg, glyphs, "a",
                    TextEditor.Alignment.LEFT, new TextEditor.Format(null, Font.ITALIC, 0f, null)));
            assertTrue(e.getMessage().contains("pick a font"), e.getMessage());
            // keeping the face is always fine
            assertNotNull(TextEditor.replace(doc, pg, glyphs, "a", TextEditor.Alignment.LEFT, TextEditor.Format.SAME));
        }
    }

    @Test
    void textBoxLinesAreAlignedLeftCentreOrRight() throws Exception {
        waitFor(() -> viewer.getPageImage(0) != null, 10000);
        onEDT(() -> pane.setStyle(EditorHost.StyleKey.TEXT, AnnotationStyle.TEXT.withAlignment(TextEditor.Alignment.CENTER)));
        FreeTextTool tool = (FreeTextTool) pane.getTool(PDFEditorPane.EditTool.TEXT_BOX);
        Rectangle2D.Float box = new Rectangle2D.Float(100, 400, 240, 40);
        PDAnnotationFreeText ft = onEDT(() -> tool.addFreeText(ctx(), 0, box, "hi"));
        assertEquals(1, ft.getQ(), "centred = Q 1");
        Rectangle2D.Float left = new Rectangle2D.Float(104, 404, 60, 32), middle = new Rectangle2D.Float(190, 404, 60, 32), right = new Rectangle2D.Float(276, 404, 60, 32);
        waitFor(() -> darkInside(viewer.getPageImage(0), middle, viewer.getZoom()), 10000);
        assertFalse(darkInside(onEDT(() -> viewer.getPageImage(0)), left, viewer.getZoom()), "nothing at the left");
        assertFalse(darkInside(onEDT(() -> viewer.getPageImage(0)), right, viewer.getZoom()), "nothing at the right");

        onEDT(() -> pane.selectAnnotation(0, ft));
        SelectAnnotationTool select = (SelectAnnotationTool) pane.getTool(PDFEditorPane.EditTool.SELECT);
        AnnotationStyle read = onEDT(() -> select.styleOf(ctx()));
        assertEquals(TextEditor.Alignment.CENTER, read.getAlignment());
        assertTrue(onEDT(() -> pane.applyStyleToSelection(read.withAlignment(TextEditor.Alignment.RIGHT).withUnderline(true))));
        assertEquals(2, ft.getQ());
        waitFor(() -> darkInside(viewer.getPageImage(0), right, viewer.getZoom()), 10000);
        assertFalse(darkInside(onEDT(() -> viewer.getPageImage(0)), middle, viewer.getZoom()), "moved out of the middle");
        assertFalse(darkInside(onEDT(() -> viewer.getPageImage(0)), left, viewer.getZoom()), "the underline bar moved with the text");
        onEDT(pane::undo);
        assertEquals(1, ft.getQ(), "Q is part of the undo snapshot");
        waitFor(() -> darkInside(viewer.getPageImage(0), middle, viewer.getZoom()), 10000);
        onEDT(() -> pane.selectAnnotation(0, ft)); // undo drops the selection
        assertTrue(onEDT(() -> pane.applyStyleToSelection(read.withAlignment(TextEditor.Alignment.LEFT))));
        assertEquals(0, ft.getQ());
        waitFor(() -> darkInside(viewer.getPageImage(0), left, viewer.getZoom()), 10000);
    }

    @Test
    void pageTextIsRewrittenInAnotherFontSizeAndColourLeavingTheRestAlone() throws Exception {
        Assumptions.assumeTrue(EditorFonts.families().contains(ARIAL), "Arial is installed");
        waitFor(() -> viewer.getPageImage(0) != null, 10000);
        TextEditor.Glyph originalP = glyph("p", "first page text".indexOf('p'));
        float originalSize = originalP.renderedSize();
        assertTrue(originalSize > 5 && originalSize < 30, "rendered size in points: " + originalSize);
        assertNotNull(originalP.fontName, "the Tf operand is recorded");
        assertNotNull(originalP.color, "the fill colour is recorded");
        COSName originalFont = originalP.fontName;

        selectWord("first");
        TextEditor.Format fmt = new TextEditor.Format(ARIAL, Font.BOLD, 14f, Color.RED);
        assertTrue(onEDT(() -> pane.replaceSelectedText("Fïrst", TextEditor.Alignment.LEFT, fmt)),
                "a character the page font lacks is fine in another font");
        assertEquals("Fïrst page text", bodyLine());
        assertEquals("Replace \"first\" with \"Fïrst\"", pane.getEditModel().peekUndo().name());

        // the replacement: Arial Bold at 14 pt in red; the rest of the line: as before
        TextEditor.Glyph f = glyph("F", 0);
        assertTrue(f.font.getName().contains("Arial-BoldMT"), f.font.getName());
        assertTrue(f.font.isEmbedded(), "sealed: the page font carries its program before any save");
        assertEquals(14f, f.renderedSize(), 0.15);
        assertEquals(Color.RED, f.color);
        assertNotEquals(originalFont, f.fontName);
        TextEditor.Glyph p = glyph("p", "Fïrst page text".indexOf('p'));
        assertEquals(originalFont, p.fontName, "the old font is restored after the run");
        assertEquals(originalSize, p.renderedSize(), 0.05);
        assertEquals(originalP.color, p.color, "the old colour is restored after the run");
        assertEquals(originalP.x, p.x, 0.05, "the rest of the line stays where it was (no reflow)");
        waitFor(() -> hasRed(viewer.getPageImage(0)), 10000);

        // saved: the embedded subset of Arial Bold travels with the page
        File out = Files.createTempFile("fonted", ".pdf").toFile();
        out.deleteOnExit();
        onEDT(() -> {
            viewer.save(out);
            return null;
        });
        waitFor(() -> !pane.getEditModel().isModified(), 15000);
        try (PDDocument saved = Loader.loadPDF(out)) {
            PDFTextStripper s = new PDFTextStripper();
            assertTrue(s.getText(saved).contains("Fïrst page text"), s.getText(saved));
            boolean arial = false;
            PDResources res = saved.getPage(0).getResources();
            for (COSName n : res.getFontNames())
                arial |= res.getFont(n).getName().contains("Arial-BoldMT");
            assertTrue(arial, "Arial Bold is embedded in the page");
        }

        // undo brings the old bytes back (the font stays in the resources, unused)
        onEDT(pane::undo);
        assertEquals("first page text", bodyLine());
        assertEquals(originalFont, glyph("f", 0).fontName);

        // size only, same font: the Tf operand follows the rendered size
        selectWord("page");
        assertTrue(onEDT(() -> pane.replaceSelectedText("page", TextEditor.Alignment.LEFT, new TextEditor.Format(null, Font.PLAIN, 20f, null))));
        TextEditor.Glyph big = glyph("p", "first page text".indexOf('p'));
        assertEquals(20f, big.renderedSize(), 0.15);
        assertEquals(originalFont, big.fontName, "same font");
        assertEquals(originalSize, glyph("t", "first page text".lastIndexOf('t')).renderedSize(), 0.05, "the next word keeps its size");
        onEDT(pane::undo);

        // colour only, centred: no font switch at all
        selectWord("text");
        // (the page font is a subset: only glyphs it already shows can be used without a font change)
        assertTrue(onEDT(() -> pane.replaceSelectedText("txet", TextEditor.Alignment.CENTER, new TextEditor.Format(null, Font.PLAIN, 0f, Color.BLUE))));
        assertEquals("first page txet", bodyLine());
        assertEquals(Color.BLUE, glyph("x", "first page txet".indexOf('x')).color);
        assertEquals(originalFont, glyph("x", "first page txet".indexOf('x')).fontName);
        onEDT(pane::undo);
        assertEquals("first page text", bodyLine());

        // an unknown family is refused before anything changes
        selectWord("text");
        PDPage page = page();
        List<TextEditor.Glyph> matched = onEDT(() -> {
            synchronized (viewer.getDocumentLock()) {
                return TextEditor.match(TextEditor.glyphs(page), PageTransform.of(page), viewer.getSelectionTextPositions(0));
            }
        });
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> TextEditor.replace(
                viewer.getDocument(), page, matched, "x", TextEditor.Alignment.LEFT, new TextEditor.Format("No Such Font Family 12345", 0, 0, null)));
        assertTrue(e.getMessage().contains("No Such Font Family"), e.getMessage());
        assertEquals("first page text", bodyLine());
        assertTrue(TextEditor.Format.SAME.isSame());
        assertFalse(fmt.isSame());
    }

    // ---------------------------------------------------------------- helpers

    private PDFToolContext ctx() {
        return viewer.getToolContext();
    }

    private PDPage page() throws Exception {
        return onEDT(() -> {
            synchronized (viewer.getDocumentLock()) {
                return viewer.getDocument().getPage(0);
            }
        });
    }

    /** The n-th glyph of the body line (the last text line of the page) by unicode, where n counts the line's characters. */
    private TextEditor.Glyph glyph(String unicode, int indexInLine) throws Exception {
        PDPage page = page();
        List<TextEditor.Glyph> glyphs = onEDT(() -> {
            synchronized (viewer.getDocumentLock()) {
                return TextEditor.glyphs(page);
            }
        });
        // the body line is the lowest one on the page: smallest y
        float minY = Float.MAX_VALUE;
        for (TextEditor.Glyph g : glyphs)
            minY = Math.min(minY, g.y);
        List<TextEditor.Glyph> line = new ArrayList<>();
        for (TextEditor.Glyph g : glyphs)
            if (Math.abs(g.y - minY) < 2f && !g.unicode.trim().isEmpty())
                line.add(g);
        // stream order (a wider replacement may overlap what follows: nothing reflows)
        line.sort((a, b) -> a.op != b.op ? Integer.compare(a.op, b.op) : a.string != b.string ? Integer.compare(a.string, b.string) : Integer.compare(a.code, b.code));
        // indexInLine counts characters including spaces in the extracted line; map by order of non-space glyphs
        String extracted = bodyLine();
        int nonSpaceIndex = 0;
        for (int i = 0; i < indexInLine && i < extracted.length(); i++)
            if (extracted.charAt(i) != ' ')
                nonSpaceIndex++;
        TextEditor.Glyph g = line.get(nonSpaceIndex);
        assertEquals(unicode, g.unicode, "glyph at " + indexInLine + " of \"" + extracted + "\"");
        return g;
    }

    private void selectWord(String word) throws Exception {
        int start = onEDT(() -> viewer.search(word).get(0).getStart());
        onEDT(() -> viewer.select(0, start, 0, start + word.length()));
        assertEquals(word, onEDT(viewer::getSelectedText));
    }

    private String bodyLine() throws Exception {
        return onEDT(() -> {
            synchronized (viewer.getDocumentLock()) {
                PDFTextStripper s = new PDFTextStripper();
                String[] lines = s.getText(viewer.getDocument()).trim().split("\\R");
                return lines[lines.length - 1].trim().replaceAll("\\s+", " ");
            }
        });
    }

    private String appearanceContent(PDAnnotationFreeText a) throws IOException {
        synchronized (viewer.getDocumentLock()) {
            return new String(a.getNormalAppearanceStream().getContentStream().toByteArray(), "ISO-8859-1");
        }
    }

    private static boolean yellowish(BufferedImage img, Rectangle2D.Float viewRect, float zoom) {
        if (img == null)
            return false;
        int x1 = Math.round(viewRect.x * zoom), x2 = Math.round((viewRect.x + viewRect.width) * zoom);
        int y1 = Math.round(viewRect.y * zoom), y2 = Math.round((viewRect.y + viewRect.height) * zoom);
        for (int y = Math.max(0, y1); y <= Math.min(img.getHeight() - 1, y2); y++)
            for (int x = Math.max(0, x1); x <= Math.min(img.getWidth() - 1, x2); x++) {
                int rgb = img.getRGB(x, y);
                int r = (rgb >> 16) & 0xff, g = (rgb >> 8) & 0xff, b = rgb & 0xff;
                if (r > 200 && g > 200 && b < 100)
                    return true;
            }
        return false;
    }

    private static int countOf(String s, String part) {
        int n = 0;
        for (int i = s.indexOf(part); i >= 0; i = s.indexOf(part, i + part.length()))
            n++;
        return n;
    }

    private static boolean anyDark(BufferedImage img, Rectangle2D.Float viewRect, float zoom) {
        if (img == null)
            return false;
        int x1 = Math.round(viewRect.x * zoom), x2 = Math.round((viewRect.x + viewRect.width) * zoom);
        int y1 = Math.round(viewRect.y * zoom), y2 = Math.round((viewRect.y + viewRect.height) * zoom);
        for (int y = Math.max(0, y1); y <= Math.min(img.getHeight() - 1, y2); y++)
            for (int x = Math.max(0, x1); x <= Math.min(img.getWidth() - 1, x2); x++)
                if ((img.getRGB(x, y) & 0xff) < 120)
                    return true;
        return false;
    }

    /** Under the document lock: the render thread reads the same in-memory font streams, and PDFBox streams are not thread-safe. */
    private boolean appearanceFontEmbedded(PDAnnotationFreeText a) throws IOException {
        synchronized (viewer.getDocumentLock()) {
            PDResources res = a.getNormalAppearanceStream().getResources();
            for (COSName n : res.getFontNames())
                if (!res.getFont(n).isEmbedded())
                    return false;
            return true;
        }
    }

    private String appearanceFont(PDAnnotationFreeText a) throws IOException {
        synchronized (viewer.getDocumentLock()) {
            PDResources res = a.getNormalAppearanceStream().getResources();
            StringBuilder sb = new StringBuilder();
            for (COSName n : res.getFontNames())
                sb.append(res.getFont(n).getName()).append(' ');
            return sb.toString().trim();
        }
    }

    private static boolean hasRed(BufferedImage img) {
        if (img == null)
            return false;
        for (int y = 0; y < img.getHeight(); y += 2)
            for (int x = 0; x < img.getWidth(); x += 2) {
                int rgb = img.getRGB(x, y);
                int r = (rgb >> 16) & 0xff, g = (rgb >> 8) & 0xff, b = rgb & 0xff;
                if (r > 180 && g < 90 && b < 90)
                    return true;
            }
        return false;
    }

    private static boolean darkInside(BufferedImage img, Rectangle2D.Float viewRect, float zoom) {
        if (img == null)
            return false;
        int x1 = Math.round(viewRect.x * zoom) + 2, x2 = Math.round((viewRect.x + viewRect.width) * zoom) - 2;
        int y1 = Math.round(viewRect.y * zoom) + 2, y2 = Math.round((viewRect.y + viewRect.height) * zoom) - 2;
        for (int y = Math.max(0, y1); y < Math.min(img.getHeight(), y2); y++)
            for (int x = Math.max(0, x1); x < Math.min(img.getWidth(), x2); x++)
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
