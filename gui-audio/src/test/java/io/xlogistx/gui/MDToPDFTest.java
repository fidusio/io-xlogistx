package io.xlogistx.gui;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.text.PDFTextStripper;
import org.junit.jupiter.api.Test;
import org.zoxweb.server.io.UByteArrayOutputStream;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

import static org.junit.jupiter.api.Assertions.*;

public class MDToPDFTest {

    private static final String SAMPLE =
            "# Sample Title\n\n" +
            "Some **bold**, *italic* and ~~struck~~ text with `inline code`.\n\n" +
            "Ünïcödé — “curly quotes” and Ελληνικά and Кириллица.\n\n" +
            "- [x] done task\n" +
            "- [ ] open task\n\n" +
            "| Name | Value |\n" +
            "|------|-------|\n" +
            "| alpha | 1 |\n" +
            "| beta | 2 |\n\n" +
            "```java\n" +
            "System.out.println(\"hello\");\n" +
            "```\n\n" +
            "> a quote\n\n" +
            "[link](https://example.com)\n";

    private static String extractText(byte[] pdf) throws IOException {
        try (PDDocument doc = Loader.loadPDF(pdf)) {
            assertTrue(doc.getNumberOfPages() >= 1);
            return new PDFTextStripper().getText(doc);
        }
    }

    @Test
    public void rendersAllConstructs() throws IOException {
        UByteArrayOutputStream os = MDToPDF.mdToPDF(SAMPLE);
        byte[] pdf = os.toByteArray();
        assertTrue(pdf.length > 1000);
        assertEquals("%PDF", new String(pdf, 0, 4, StandardCharsets.US_ASCII));

        String text = extractText(pdf);
        assertTrue(text.contains("Sample Title"));
        assertTrue(text.contains("struck"));
        assertTrue(text.contains("alpha"));
        assertTrue(text.contains("println"));
        assertTrue(text.contains("a quote"));
        // task list checkboxes become text markers
        assertTrue(text.contains("[x] done task"));
        assertTrue(text.contains("[ ] open task"));
    }

    @Test
    public void embedsUnicodeFont() throws IOException {
        byte[] pdf = MDToPDF.mdToPDF("Ünïcödé — “q” Ελληνικά Кириллица").toByteArray();
        String text = extractText(pdf);
        assertTrue(text.contains("Ünïcödé"), text);
        assertTrue(text.contains("Ελληνικά"), text);
        assertTrue(text.contains("Кириллица"), text);
    }

    @Test
    public void htmlUsesViewerExtensions() {
        String html = MDToPDF.toHTML("~~gone~~\n\n| a | b |\n|---|---|\n| 1 | 2 |\n\n- [x] t");
        assertTrue(html.contains("<del>gone</del>"), html);
        assertTrue(html.contains("<table>"), html);
        assertTrue(html.contains("[x] "), html);
        assertFalse(html.contains("<input"), html);
    }

    @Test
    public void customCss() throws IOException {
        byte[] pdf = MDToPDF.mdToPDF("# Letter", null,
                "@page { size: letter; margin: 1cm; } body { font-family: sans-serif; }").toByteArray();
        try (PDDocument doc = Loader.loadPDF(pdf)) {
            // US letter is 612 x 792 pt, A4 is 595 x 842 pt
            assertEquals(612f, doc.getPage(0).getMediaBox().getWidth(), 1f);
        }
    }

    @Test
    public void fileConversion() throws IOException {
        File dir = Files.createTempDirectory("mdtopdf").toFile();
        File md = new File(dir, "doc.md");
        Files.write(md.toPath(), "# From File\n\ntext".getBytes(StandardCharsets.UTF_8));
        File pdf = MDToPDF.mdToPDF(md, null);
        assertEquals(new File(dir, "doc.pdf"), pdf);
        assertTrue(pdf.length() > 0);
        assertTrue(extractText(Files.readAllBytes(pdf.toPath())).contains("From File"));
    }

    @Test
    public void nullMarkdownRejected() {
        assertThrows(NullPointerException.class, () -> MDToPDF.mdToPDF((String) null));
    }
}
