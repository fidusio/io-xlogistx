package io.xlogistx.editor.pdf;

import io.xlogistx.editor.pdf.tools.EditTextTool;
import io.xlogistx.gui.MDToPDF;
import io.xlogistx.gui.pdf.PDFViewerPanel;
import io.xlogistx.gui.pdf.PageTransform;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.text.PDFTextStripper;
import org.apache.pdfbox.text.TextPosition;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.swing.*;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.File;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.function.BooleanSupplier;

import static org.junit.jupiter.api.Assertions.*;

/**
 * In-place text editing: glyphs are located in the page stream, the selection
 * is matched to them, the replacement is re-encoded with the same font, the
 * change renders, saves and undoes; unsupported characters are refused.
 */
public class TextEditTest {

    private static final String PAGE_BREAK = "\n\n<div style=\"page-break-before: always\"></div>\n\n";
    private static byte[] threePagePDF;
    private PDFEditorPane pane;
    private PDFViewerPanel viewer;

    @BeforeAll
    static void headless() throws Exception {
        System.setProperty("java.awt.headless", "true");
        threePagePDF = MDToPDF.mdToPDF("# One\n\nfirst page text" + PAGE_BREAK + "# Two\n\nsecond page text" + PAGE_BREAK + "# Three\n\nthird page text").toByteArray();
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
        PDDocument doc = Loader.loadPDF(threePagePDF);
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
    void locatesEveryGlyphAndMatchesTheSelection() throws Exception {
        List<TextEditor.Glyph> glyphs = onEDT(() -> {
            synchronized (viewer.getDocumentLock()) {
                return TextEditor.glyphs(viewer.getDocument().getPage(0));
            }
        });
        StringBuilder sb = new StringBuilder();
        for (TextEditor.Glyph g : glyphs)
            sb.append(g.unicode);
        assertTrue(sb.toString().contains("One"), sb.toString());
        assertTrue(sb.toString().contains("first"), sb.toString());
        for (TextEditor.Glyph g : glyphs) {
            assertNotNull(g.font);
            assertTrue(g.width > 0 || g.unicode.trim().isEmpty(), "advance for " + g);
            assertTrue(g.height > 0, "size for " + g);
        }

        // select "first" on page 0 (the body line starts after "One")
        int start = onEDT(() -> viewer.search("first").get(0).getStart());
        onEDT(() -> viewer.select(0, start, 0, start + 5));
        assertEquals("first", onEDT(viewer::getSelectedText));
        List<TextPosition> positions = onEDT(() -> viewer.getSelectionTextPositions(0));
        assertEquals(5, positions.size());
        PageTransform t = onEDT(() -> {
            synchronized (viewer.getDocumentLock()) {
                return PageTransform.of(viewer.getDocument().getPage(0));
            }
        });
        List<TextEditor.Glyph> matched = TextEditor.match(glyphs, t, positions);
        assertEquals(5, matched.size());
        assertEquals("first", matched.stream().map(g -> g.unicode).reduce("", String::concat));
        assertEquals(matched.get(0).op, matched.get(4).op, "one word, one operator");
        for (int i = 1; i < matched.size(); i++)
            assertTrue(matched.get(i).code > matched.get(i - 1).code, "stream order");
        assertThrows(IllegalArgumentException.class, () -> TextEditor.match(glyphs, t, Arrays.asList(positions.get(0), positions.get(0))), "a glyph matches once");
    }

    @Test
    void replacesTextInPlaceRendersSavesAndUndoes() throws Exception {
        waitFor(() -> viewer.getPageImage(0) != null, 10000);
        BufferedImage before = onEDT(() -> viewer.getPageImage(0));
        selectWord(0, "first");

        // "third" uses glyphs the subset font already has (t, h, i, r, d appear on page 3)
        assertTrue(onEDT(() -> pane.replaceSelectedText("third")));
        assertEquals("third page text", bodyLine(0));
        assertEquals(Arrays.asList(0, 2), onEDT(() -> viewer.find("third")));
        assertTrue(onEDT(() -> viewer.find("first")).isEmpty());
        assertFalse(viewer.hasSelection(), "the selection is dropped with the old text");
        assertTrue(pane.isModified());
        assertEquals("Replace \"first\" with \"third\"", pane.getEditModel().peekUndo().name());
        waitFor(() -> viewer.getPageImage(0) != null && viewer.getPageImage(0) != before, 10000);
        assertNotEquals(signature(before), signature(onEDT(() -> viewer.getPageImage(0))), "the raster changed");

        onEDT(pane::undo);
        assertEquals("first page text", bodyLine(0));
        assertFalse(pane.isModified());
        onEDT(pane::redo);
        assertEquals("third page text", bodyLine(0));

        File out = File.createTempFile("pdfeditor-text", ".pdf");
        out.deleteOnExit();
        onEDT(() -> {
            viewer.save(out);
            return null;
        });
        waitFor(() -> !pane.isModified(), 15000);
        try (PDDocument saved = Loader.loadPDF(out)) {
            PDFTextStripper s = new PDFTextStripper();
            s.setStartPage(1);
            s.setEndPage(1);
            String text = s.getText(saved).replaceAll("\\s+", " ");
            assertTrue(text.contains("third page text"), text);
            assertFalse(text.contains("first"), text);
        }
    }

    @Test
    void longerShorterAndEmptyReplacementsWork() throws Exception {
        selectWord(0, "first");
        assertTrue(onEDT(() -> pane.replaceSelectedText("seconddd")), "no reflow, but longer text is allowed");
        assertEquals("seconddd page text", bodyLine(0));
        onEDT(pane::undo);
        selectWord(0, "page");
        assertTrue(onEDT(() -> pane.replaceSelectedText("")), "empty = delete");
        assertEquals("first text", bodyLine(0), "the gap stays (no reflow), the extractor collapses it");
        onEDT(pane::undo);
        assertEquals("first page text", bodyLine(0));
        assertEquals(0, pane.getEditModel().getUndoDepth());
    }

    @Test
    void alignmentKeepsStartMiddleOrEndAndTheRestOfTheLine() throws Exception {
        float[] orig = edges(0, "first");          // start of 'f', end of 't'
        float pageX = edges(0, "page")[0];          // start of the following word
        for (TextEditor.Alignment a : TextEditor.Alignment.values()) {
            selectWord(0, "first");
            assertTrue(onEDT(() -> pane.replaceSelectedText("it", a)), a.name());
            float[] now = edges(0, "it");
            float width = now[1] - now[0];
            assertTrue(width > 0 && width < orig[1] - orig[0], a + ": shorter text");
            switch (a) {
                case LEFT:
                    assertEquals(orig[0], now[0], 0.05, "left keeps the start");
                    break;
                case RIGHT:
                    assertEquals(orig[1], now[1], 0.05, "right keeps the end");
                    break;
                default:
                    assertEquals((orig[0] + orig[1]) / 2, (now[0] + now[1]) / 2, 0.05, "centre keeps the middle");
            }
            assertEquals(pageX, edges(0, "page")[0], 0.05, a + ": the following word does not move");
            assertEquals("it page text", bodyLine(0));
            onEDT(pane::undo);
            assertEquals("first page text", bodyLine(0));
        }
        // longer text aligned right starts earlier and still leaves "page" where it was
        selectWord(0, "first");
        assertTrue(onEDT(() -> pane.replaceSelectedText("seconds", TextEditor.Alignment.RIGHT)));
        float[] longer = edges(0, "seconds");
        assertEquals(orig[1], longer[1], 0.05);
        assertTrue(longer[0] < orig[0]);
        assertEquals(pageX, edges(0, "page")[0], 0.05);
        onEDT(pane::undo);
    }

    @Test
    void refusesCharactersTheFontCannotShow() throws Exception {
        selectWord(0, "first");
        PDPage page = onEDT(() -> {
            synchronized (viewer.getDocumentLock()) {
                return viewer.getDocument().getPage(0);
            }
        });
        List<TextEditor.Glyph> glyphs = TextEditor.glyphs(page);
        List<TextPosition> positions = onEDT(() -> viewer.getSelectionTextPositions(0));
        List<TextEditor.Glyph> matched = TextEditor.match(glyphs, PageTransform.of(page), positions);
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> TextEditor.replace(page, matched, "Fïrst"));
        assertTrue(e.getMessage().contains("no glyph for"), e.getMessage());
        assertTrue(e.getMessage().contains("ï"), e.getMessage());
        assertEquals("first page text", bodyLine(0), "nothing changed");
        assertThrows(IllegalArgumentException.class, () -> TextEditor.replace(page, Arrays.<TextEditor.Glyph>asList(), "x"));
    }

    @Test
    void editTextToolSelectsLikeTheTextToolAndNeedsOnePage() throws Exception {
        onEDT(() -> pane.setActiveTool(PDFEditorPane.EditTool.EDIT_TEXT));
        assertEquals(PDFViewerPanel.Tool.CUSTOM, viewer.getTool());
        EditTextTool tool = (EditTextTool) pane.getTool(PDFEditorPane.EditTool.EDIT_TEXT);
        assertEquals("Edit text", tool.getName());
        onEDT(viewer::clearSelection);
        assertFalse(onEDT(pane::editSelectedText), "nothing selected");
        assertEquals(0, pane.getEditModel().getUndoDepth());
        InputMap im = pane.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT);
        assertEquals("editText", im.get(KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_E, java.awt.event.InputEvent.CTRL_DOWN_MASK)));
    }

    // ---------------------------------------------------------------- helpers

    /** {start x of the first glyph, end x of the last glyph} of the first occurrence of {@code word} in the page stream, user space. */
    private float[] edges(int page, String word) throws Exception {
        List<TextEditor.Glyph> glyphs = onEDT(() -> {
            synchronized (viewer.getDocumentLock()) {
                return TextEditor.glyphs(viewer.getDocument().getPage(page));
            }
        });
        StringBuilder sb = new StringBuilder();
        for (TextEditor.Glyph g : glyphs)
            sb.append(g.unicode);
        int at = sb.indexOf(word);
        assertTrue(at >= 0, word + " in " + sb);
        // map the char offset back to glyph indexes (unicode strings may be longer than one char)
        int idx = 0, pos = 0;
        while (pos < at)
            pos += glyphs.get(idx++).unicode.length();
        TextEditor.Glyph first = glyphs.get(idx);
        int endIdx = idx;
        pos = first.unicode.length();
        while (pos < word.length())
            pos += glyphs.get(++endIdx).unicode.length();
        TextEditor.Glyph last = glyphs.get(endIdx);
        return new float[]{first.x, last.x + last.width};
    }

    private void selectWord(int page, String word) throws Exception {
        int start = onEDT(() -> viewer.search(word).get(0).getStart());
        onEDT(() -> viewer.select(page, start, page, start + word.length()));
        assertEquals(word, onEDT(viewer::getSelectedText));
    }

    /** The last text line of a page as PDFBox extracts it, runs of whitespace collapsed (a kept gap reads as extra spaces). */
    private String bodyLine(int page) throws Exception {
        return onEDT(() -> {
            synchronized (viewer.getDocumentLock()) {
                PDFTextStripper s = new PDFTextStripper();
                s.setStartPage(page + 1);
                s.setEndPage(page + 1);
                String[] lines = s.getText(viewer.getDocument()).trim().split("\\R");
                return lines[lines.length - 1].trim().replaceAll("\\s+", " ");
            }
        });
    }

    private static long signature(BufferedImage img) {
        long h = 0;
        for (int y = 0; y < img.getHeight(); y += 3)
            for (int x = 0; x < img.getWidth(); x += 3)
                h = h * 31 + (img.getRGB(x, y) & 0xffffff);
        return h;
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
