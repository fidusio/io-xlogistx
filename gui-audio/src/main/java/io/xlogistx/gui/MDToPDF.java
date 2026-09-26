package io.xlogistx.gui;

import com.openhtmltopdf.outputdevice.helper.BaseRendererBuilder;
import com.openhtmltopdf.pdfboxout.PdfRendererBuilder;
import org.commonmark.Extension;
import org.commonmark.ext.gfm.strikethrough.StrikethroughExtension;
import org.commonmark.ext.gfm.tables.TablesExtension;
import org.commonmark.ext.task.list.items.TaskListItemsExtension;
import org.commonmark.parser.Parser;
import org.commonmark.renderer.html.HtmlRenderer;
import org.jsoup.Jsoup;
import org.jsoup.helper.W3CDom;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.zoxweb.server.io.IOUtil;
import org.zoxweb.server.io.UByteArrayOutputStream;
import org.zoxweb.shared.util.ParamUtil;
import org.zoxweb.shared.util.SUS;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

/**
 * Markdown to PDF converter. The markdown is parsed with commonmark using the
 * same GitHub-flavored extensions as {@link MDViewerPanel} (tables,
 * strikethrough, task list items), rendered to HTML, styled with a CSS
 * stylesheet and laid out into a PDF by OpenHTMLtoPDF on top of PDFBox.
 *
 * <h2>Fonts</h2>
 * The Roboto family shipped with the {@code flatlaf-fonts-roboto} dependency is
 * embedded (regular, bold, italic, bold-italic) so Latin, Greek and Cyrillic
 * text renders correctly; the PDF standard fonts alone only cover Latin-1.
 * Monospace text uses the built-in Courier. If the Roboto resources are not on
 * the classpath the converter silently falls back to the built-in fonts.
 *
 * <h2>Diagrams</h2>
 * {@code ```mermaid} fenced blocks holding a flowchart are rendered to PNG by
 * {@link MermaidRenderer} and embedded as images (scaled to the text width at
 * most); a block the renderer does not understand (other diagram types,
 * syntax it lacks) is left as a code block so the source stays readable.
 *
 * <h2>Styling</h2>
 * {@link #DEFAULT_CSS} defines the page (A4, 2cm margins) and the basic
 * typography. Callers can pass their own stylesheet to
 * {@link #mdToPDF(String, String, String)}; it replaces the default entirely,
 * so include a {@code @page} rule and reference {@link #FONT_FAMILY} to keep
 * the embedded font.
 *
 * <h2>Usage</h2>
 * <pre>{@code
 * UByteArrayOutputStream pdf = MDToPDF.mdToPDF("# Title\nSome **bold** text");
 * File out = MDToPDF.mdToPDF(new File("README.md"), null); // writes README.pdf
 * }</pre>
 * Command line: {@code MDToPDF md=input.md [pdf=output.pdf] [css=style.css]}
 */
public final class MDToPDF {

    /** Font family name the embedded Roboto fonts are registered under. */
    public static final String FONT_FAMILY = "Roboto";

    /** Stylesheet applied when the caller does not supply one. */
    public static final String DEFAULT_CSS =
            "@page { size: A4; margin: 2cm; }" +
            "body { font-family: '" + FONT_FAMILY + "', sans-serif; font-size: 11pt; line-height: 1.4; }" +
            "h1, h2 { border-bottom: 1px solid #ddd; padding-bottom: 2px; }" +
            "pre, code { font-family: 'Courier', monospace; background: #f4f4f4; }" +
            "code { padding: 0 2px; }" +
            "pre { padding: 8px; white-space: pre-wrap; word-wrap: break-word; }" +
            "blockquote { margin-left: 12px; padding-left: 8px; border-left: 3px solid #ccc; color: #555; }" +
            "table { border-collapse: collapse; }" +
            "th { background: #eee; }" +
            "th, td { border: 1px solid #999; padding: 4px 8px; }" +
            "img { max-width: 100%; }" +
            "p.diagram { text-align: center; page-break-inside: avoid; }" +
            "del { text-decoration: line-through; }" +
            "a { color: #0b5cb5; }";

    private static final String ROBOTO_PATH = "/com/formdev/flatlaf/fonts/roboto/";
    /** Diagram device scale: crisp when printed at the CSS size. */
    private static final float DIAGRAM_SCALE = 2f;
    /** Widest a diagram may be laid out, in CSS px (A4 text width at 2cm margins is ~640). */
    private static final int DIAGRAM_MAX_WIDTH = 640;

    private static final List<Extension> EXT = Arrays.asList(
            TablesExtension.create(),
            StrikethroughExtension.create(),
            TaskListItemsExtension.create());
    private static final Parser PARSER = Parser.builder().extensions(EXT).build();
    private static final HtmlRenderer RENDERER = HtmlRenderer.builder().extensions(EXT).build();

    private MDToPDF() {}

    /**
     * Converts markdown to PDF using {@link #DEFAULT_CSS} and no base URI.
     *
     * @param markdown the markdown text, never null
     * @return the PDF bytes
     * @throws IOException if rendering fails
     */
    public static UByteArrayOutputStream mdToPDF(String markdown) throws IOException {
        return mdToPDF(markdown, null, null);
    }

    /**
     * Converts markdown to PDF using {@link #DEFAULT_CSS}.
     *
     * @param markdown the markdown text, never null
     * @param baseUri  base URI relative links and images are resolved against, may be null
     * @return the PDF bytes
     * @throws IOException if rendering fails
     */
    public static UByteArrayOutputStream mdToPDF(String markdown, String baseUri) throws IOException {
        return mdToPDF(markdown, baseUri, null);
    }

    /**
     * Converts markdown to PDF.
     *
     * @param markdown the markdown text, never null
     * @param baseUri  base URI relative links and images are resolved against, may be null
     * @param css      stylesheet replacing {@link #DEFAULT_CSS}, null for the default
     * @return the PDF bytes
     * @throws IOException if rendering fails
     */
    public static UByteArrayOutputStream mdToPDF(String markdown, String baseUri, String css) throws IOException {
        UByteArrayOutputStream os = new UByteArrayOutputStream();
        mdToPDF(markdown, baseUri, css, os);
        return os;
    }

    /**
     * Converts markdown to PDF and writes it to the given stream. The stream is
     * flushed but not closed.
     *
     * @param markdown the markdown text, never null
     * @param baseUri  base URI relative links and images are resolved against, may be null
     * @param css      stylesheet replacing {@link #DEFAULT_CSS}, null for the default
     * @param out      destination stream, never null
     * @throws IOException if rendering fails
     */
    public static void mdToPDF(String markdown, String baseUri, String css, OutputStream out) throws IOException {
        SUS.checkIfNull("markdown null", markdown);
        SUS.checkIfNull("out null", out);

        Document doc = toDocument(markdown, css != null ? css : DEFAULT_CSS);

        PdfRendererBuilder builder = new PdfRendererBuilder();
        builder.useFastMode();
        registerFonts(builder);
        builder.withW3cDocument(new W3CDom().fromJsoup(doc), baseUri);
        builder.toStream(out);
        builder.run();
        out.flush();
    }

    /**
     * Converts a markdown file to a PDF file. Relative links and images in the
     * markdown are resolved against the markdown file's directory.
     *
     * @param md  the markdown file, never null
     * @param pdf the PDF file to write; null writes next to {@code md} with a {@code .pdf} extension
     * @return the written PDF file
     * @throws IOException if the markdown cannot be read or rendering fails
     */
    public static File mdToPDF(File md, File pdf) throws IOException {
        return mdToPDF(md, pdf, null);
    }

    /**
     * Converts a markdown file to a PDF file with a custom stylesheet. Relative
     * links and images in the markdown are resolved against the markdown file's
     * directory.
     *
     * @param md  the markdown file, never null
     * @param pdf the PDF file to write; null writes next to {@code md} with a {@code .pdf} extension
     * @param css stylesheet replacing {@link #DEFAULT_CSS}, null for the default
     * @return the written PDF file
     * @throws IOException if the markdown cannot be read or rendering fails
     */
    public static File mdToPDF(File md, File pdf, String css) throws IOException {
        SUS.checkIfNull("md null", md);
        File dir = md.getAbsoluteFile().getParentFile();
        if (pdf == null) {
            String name = md.getName();
            int dot = name.lastIndexOf('.');
            pdf = new File(dir, (dot > 0 ? name.substring(0, dot) : name) + ".pdf");
        }
        String markdown = IOUtil.inputStreamToString(md);
        String baseUri = dir != null ? dir.toURI().toString() : null;
        try (OutputStream out = new FileOutputStream(pdf)) {
            mdToPDF(markdown, baseUri, css, out);
        }
        return pdf;
    }

    /**
     * Renders markdown to the HTML body fragment the PDF is built from
     * (task list checkboxes already replaced by text markers).
     *
     * @param markdown the markdown text, never null
     * @return the HTML body content
     */
    public static String toHTML(String markdown) {
        SUS.checkIfNull("markdown null", markdown);
        return toDocument(markdown, DEFAULT_CSS).body().html();
    }

    private static Document toDocument(String markdown, String css) {
        String body = RENDERER.render(PARSER.parse(markdown));
        Document doc = Jsoup.parse("<html><head><meta charset=\"UTF-8\"><style>"
                + css + "</style></head><body>" + body + "</body></html>");
        // mermaid flowcharts become images; anything the renderer rejects stays code
        for (Element code : doc.select("pre > code.language-mermaid")) {
            Element img = renderDiagram(doc, code.wholeText());
            if (img != null)
                code.parent().replaceWith(img);
        }
        // commonmark emits task items as disabled <input type="checkbox">; the PDF
        // renderer does not draw form controls, so replace them with text markers
        for (Element input : doc.select("input[type=checkbox]")) {
            Element marker = doc.createElement("span");
            marker.addClass("task-marker");
            marker.text(input.hasAttr("checked") ? "[x] " : "[ ] ");
            input.replaceWith(marker);
        }
        return doc;
    }

    /**
     * Renders a Mermaid block to a centered {@code <p class="diagram"><img></p>}
     * with an inline PNG, or returns null if it cannot be rendered.
     */
    private static Element renderDiagram(Document doc, String source) {
        if (!MermaidRenderer.isFlowchart(source))
            return null;
        try {
            MermaidRenderer.Graph graph = MermaidRenderer.parse(source);
            java.awt.image.BufferedImage image = MermaidRenderer.render(graph, DIAGRAM_SCALE);
            java.io.ByteArrayOutputStream png = new java.io.ByteArrayOutputStream();
            javax.imageio.ImageIO.write(image, "png", png);
            int cssWidth = Math.round(graph.getWidth()), cssHeight = Math.round(graph.getHeight());
            if (cssWidth > DIAGRAM_MAX_WIDTH) {
                cssHeight = Math.round(cssHeight * (float) DIAGRAM_MAX_WIDTH / cssWidth);
                cssWidth = DIAGRAM_MAX_WIDTH;
            }
            Element img = doc.createElement("img");
            img.attr("src", "data:image/png;base64," + Base64.getEncoder().encodeToString(png.toByteArray()));
            img.attr("width", String.valueOf(cssWidth));
            img.attr("height", String.valueOf(cssHeight));
            img.attr("alt", "diagram");
            Element p = doc.createElement("p");
            p.addClass("diagram");
            p.appendChild(img);
            return p;
        } catch (RuntimeException | IOException e) {
            return null; // unsupported syntax: keep the source as a code block
        }
    }

    private static void registerFonts(PdfRendererBuilder builder) {
        registerFont(builder, "Roboto-Regular.ttf", 400, BaseRendererBuilder.FontStyle.NORMAL);
        registerFont(builder, "Roboto-Bold.ttf", 700, BaseRendererBuilder.FontStyle.NORMAL);
        registerFont(builder, "Roboto-Italic.ttf", 400, BaseRendererBuilder.FontStyle.ITALIC);
        registerFont(builder, "Roboto-BoldItalic.ttf", 700, BaseRendererBuilder.FontStyle.ITALIC);
    }

    private static void registerFont(PdfRendererBuilder builder, String file, int weight,
                                     BaseRendererBuilder.FontStyle style) {
        final String resource = ROBOTO_PATH + file;
        if (MDToPDF.class.getResource(resource) == null)
            return; // font jar not on the classpath, fall back to built-in fonts
        builder.useFont(() -> {
            InputStream is = MDToPDF.class.getResourceAsStream(resource);
            if (is == null)
                throw new IllegalStateException("font resource missing: " + resource);
            return is;
        }, FONT_FAMILY, weight, style, true);
    }

    /**
     * Command line entry point: {@code md=input.md [pdf=output.pdf] [css=style.css]}.
     *
     * @param args the parameters
     */
    public static void main(String[] args) {
        try {
            ParamUtil.ParamMap params = ParamUtil.parse("=", args);
            File md = new File(params.stringValue("md"));
            String pdfName = params.stringValue("pdf", true);
            String cssName = params.stringValue("css", true);
            File pdf = pdfName != null ? new File(pdfName) : null;
            String css = cssName != null ? IOUtil.inputStreamToString(new File(cssName)) : null;
            pdf = mdToPDF(md, pdf, css);
            System.out.println("Written " + pdf.getAbsolutePath() + " (" + pdf.length() + " bytes)");
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            System.err.println("Usage: MDToPDF md=input.md [pdf=output.pdf] [css=style.css]");
            System.exit(1);
        }
    }
}
