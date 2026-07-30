package io.xlogistx.gui;

import org.commonmark.Extension;
import org.commonmark.ext.gfm.strikethrough.StrikethroughExtension;
import org.commonmark.ext.gfm.tables.TablesExtension;
import org.commonmark.ext.task.list.items.TaskListItemsExtension;
import org.commonmark.parser.Parser;
import org.commonmark.renderer.html.HtmlRenderer;
import org.zoxweb.shared.util.*;

import javax.swing.*;
import javax.swing.event.HyperlinkEvent;
import javax.swing.text.html.HTMLDocument;
import javax.swing.text.html.HTMLEditorKit;
import javax.swing.text.html.StyleSheet;
import java.awt.*;
import java.io.IOException;
import java.io.Reader;
import java.net.URL;
import java.util.Arrays;
import java.util.List;

/**
 * A read-only Markdown viewer panel. Markdown (GitHub flavored: tables,
 * strikethrough, task list items) is converted to HTML via commonmark and
 * rendered in a non-editable {@link JEditorPane} inside a scroll pane —
 * the panel scrolls on its own, do not wrap it in another scroll pane.
 *
 * <h2>Content sources</h2>
 * Content can be set three ways:
 * <ul>
 *   <li>{@link #setMarkdown(String)} — raw markdown text;</li>
 *   <li>{@link #loadMarkdown(Reader)} — markdown read from a stream;</li>
 *   <li>{@link #setMarkdown(NVGenericMap)} — an LLM prompt response parsed into
 *       an {@link NVGenericMap}; the assistant's markdown is pulled out by the
 *       {@linkplain #setNVGMDecoder(DataDecoder) pluggable response decoder}.
 *       The default decoder understands the OpenAI response shapes (see
 *       {@link #setMarkdown(NVGenericMap)}); install a custom
 *       {@code DataDecoder<NVGenericMap, String>} to support other providers
 *       or response formats.</li>
 * </ul>
 *
 * <h2>Behavior and styling</h2>
 * Clicked links are opened in the system browser (best effort); relative
 * links and images resolve against the {@linkplain #setBaseURL(URL) base URL}.
 * Styling follows the current look and feel: colors are derived from the
 * editor pane's own foreground/background so the panel works in light and
 * dark themes alike. Like any Swing component, the panel must be accessed
 * on the EDT.
 *
 * <h2>Usage</h2>
 * <pre>{@code
 * // plain markdown
 * MDViewerPanel viewer = new MDViewerPanel();
 * viewer.setMarkdown("# Title\nSome **bold** text");
 * frame.add(viewer);
 *
 * // OpenAI response (chat completions or responses api)
 * NVGenericMap response = GSONUtil.fromJSONGenericMap(json, null, null);
 * viewer.setMarkdown(response);
 * }</pre>
 */
public class MDViewerPanel extends JPanel {

    private final Parser parser;
    private final HtmlRenderer renderer;
    private final JEditorPane viewer = new JEditorPane();
    private final HTMLDocument document;
    private JScrollPane scrollPane;

    /**
     * Response-map to markdown decoder used by {@link #setMarkdown(NVGenericMap)};
     * replaceable via {@link #setNVGMDecoder(DataDecoder)}. The default implements
     * the OpenAI extraction described in {@link #setMarkdown(NVGenericMap)}.
     */
    private volatile DataDecoder<NVGenericMap, String> nvgmDecoder = (input)-> {
        if (input == null)
            return null;

        // error payload: {"error": {"message": ..., "type": ...}}
        GetNameValue<?> error = input.get("error");
        if (error instanceof NVGenericMap) {
            String message = ((NVGenericMap) error).decodedValue("message", DataDecoder.AsStringOrNull);
            return "> **Error:** " + (message != null ? message : error);
        }

        // chat completions: choices[0].message.content, legacy completions: choices[0].text
        GetNameValue<?> choices = input.get("choices");
        if (choices instanceof NVGenericMapList) {
            List<NVGenericMap> list = ((NVGenericMapList) choices).getValue();
            if (!list.isEmpty()) {
                NVGenericMap first = list.get(0);
                GetNameValue<?> message = first.get("message");
                if (message instanceof NVGenericMap) {
                    String content = ((NVGenericMap) message).decodedValue("content", DataDecoder.AsStringOrNull);
                    return content != null ? content : (((NVGenericMap) message).decodedValue("refusal", DataDecoder.AsStringOrNull));
                }
                return first.decodedValue("text", DataDecoder.AsStringOrNull);
            }
        }

        // responses api: output[] typed items (message/reasoning/function_call/...);
        // assistant text is the message items' content[] output_text parts
        GetNameValue<?> output = input.get("output");
        if (output instanceof NVGenericMapList) {
            StringBuilder sb = new StringBuilder();
            for (NVGenericMap item : ((NVGenericMapList) output).getValue()) {
                if (!"message".equals(item.getValue("type")))
                    continue;
                GetNameValue<?> content = item.get("content");
                if (content instanceof NVGenericMapList) {
                    for (NVGenericMap part : ((NVGenericMapList) content).getValue()) {
                        String text = null;
                        if ("output_text".equals(part.decodedValue("type", DataDecoder.AsStringOrNull)))
                            text = part.decodedValue("text", DataDecoder.AsStringOrNull);
                        else if ("refusal".equals(part.decodedValue("type", DataDecoder.AsStringOrNull)))
                            text = part.decodedValue("refusal", DataDecoder.AsStringOrNull);

                        if (text != null) {
                            if (sb.length() > 0)
                                sb.append("\n\n");
                            sb.append(text);
                        }
                    }
                }
            }
            if (sb.length() > 0)
                return sb.toString();
        }

        // output_text is an SDK convenience helper, not part of the raw json:
        // honored last in case the caller pre-flattened the response
        String outputText = input.decodedValue("output_text", DataDecoder.AsStringOrNull);
        if (outputText != null)
            return outputText;

        // last resort: top level content/text
        String content = input.decodedValue("content", DataDecoder.AsStringOrNull);
        return content != null ? content : input.decodedValue("text", DataDecoder.AsStringOrNull);
    };
    private String markdown;

    /**
     * Creates an empty viewer.
     */
    public MDViewerPanel() {
        this(null);
    }

    /**
     * Creates the viewer and renders the given markdown.
     *
     * @param markdown the initial content, null for empty
     */
    public MDViewerPanel(String markdown) {
        List<Extension> extensions = Arrays.asList(
                TablesExtension.create(),
                StrikethroughExtension.create(),
                TaskListItemsExtension.create());
        parser = Parser.builder().extensions(extensions).build();
        renderer = HtmlRenderer.builder().extensions(extensions).build();

        HTMLEditorKit kit = new HTMLEditorKit();
        viewer.setEditable(false);
        viewer.setEditorKit(kit);
        // honor the component font (look and feel) instead of the html default
        viewer.putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, Boolean.TRUE);
        viewer.addHyperlinkListener(this::onHyperlink);

        // rules go on the document's own stylesheet: HTMLEditorKit.setStyleSheet
        // would change the shared default for every editor pane in the app
        document = (HTMLDocument) kit.createDefaultDocument();
        applyStyles(document.getStyleSheet());
        viewer.setDocument(document);

        setLayout(new BorderLayout());
        scrollPane = new JScrollPane(viewer);
        add(scrollPane, BorderLayout.CENTER);

        setMarkdown(markdown);
    }

    /**
     * Renders the given markdown, replacing the current content; null or
     * empty clears the panel. The view is scrolled back to the top.
     *
     * @param markdown the markdown to render, null or empty to clear
     */
    public void setMarkdown(String markdown) {
        this.markdown = markdown;
        String html = (markdown == null || markdown.isEmpty())
                ? ""
                : renderer.render(parser.parse(markdown));
        viewer.setText("<html><body>" + html + "</body></html>");
        viewer.setCaretPosition(0);
    }

    /**
     * Renders the assistant content of an OpenAI prompt response (parsed into an
     * {@link NVGenericMap}, e.g. via {@code GSONUtil.fromJSONGenericMap}). Supports
     * both API shapes per
     * <a href="https://developers.openai.com/api/docs/guides/migrate-to-responses">
     * the migrate-to-responses guide</a>: Chat Completions
     * ({@code choices[0].message.content}, falling back to {@code refusal}) and the
     * Responses API ({@code output[]} message items' {@code output_text}/{@code refusal}
     * content parts), plus legacy completions ({@code choices[0].text}) and the
     * {@code output_text} SDK convenience field. An {@code error.message} payload is
     * rendered as an error blockquote. Null or an unrecognized map clears the panel.
     * <p>
     * The extraction is performed by the current {@linkplain #setNVGMDecoder(DataDecoder)
     * response decoder}; the behavior above is the default decoder's.
     *
     * @param response the parsed prompt response, null to clear
     */
    public void setMarkdown(NVGenericMap response) {
        setMarkdown(nvgmDecoder.decode(response));
    }

    /**
     * Reads the whole reader and renders it via {@link #setMarkdown(String)}.
     * The reader is not closed.
     *
     * @param reader the markdown source
     * @throws IOException if reading fails
     */
    public void loadMarkdown(Reader reader) throws IOException {
        StringBuilder sb = new StringBuilder();
        char[] buffer = new char[4096];
        int read;
        while ((read = reader.read(buffer)) != -1)
            sb.append(buffer, 0, read);

        setMarkdown(sb.toString());
    }

    /**
     * @return the last markdown set, null if none
     */
    public String getMarkdown() {
        return markdown;
    }

    /**
     * Sets the base URL used to resolve relative links and images in the markdown.
     *
     * @param base the base URL
     */
    public void setBaseURL(URL base) {
        document.setBase(base);
    }

    /**
     * @return the underlying editor pane, for further customization (font, caret, ...)
     */
    public JEditorPane getEditorPane() {
        return viewer;
    }

    /**
     * @return the scroll pane currently hosting the viewer
     */
    public JScrollPane getScrollPane() {
        return scrollPane;
    }

    /**
     * Replaces the internal scroll pane with the given one at
     * {@link BorderLayout#CENTER}; see
     * {@link #overrideScrollPane(JScrollPane, String)}.
     *
     * @param external the replacement scroll pane, never null
     * @return this panel, for chaining
     * @throws NullPointerException if external is null
     */
    public MDViewerPanel overrideScrollPane(JScrollPane external) {
        return overrideScrollPane(external, BorderLayout.CENTER);
    }

    /**
     * Replaces the internal scroll pane with the given one, e.g. a subclassed or
     * pre-configured scroll pane (scrollbar policies, custom borders, ...). The
     * viewer is moved into the new scroll pane's viewport, the old scroll pane is
     * removed and discarded, and the new one is added at the given
     * {@link BorderLayout} position. Must be called on the EDT.
     *
     * @param external the replacement scroll pane, never null
     * @param borderLayoutPosition the BorderLayout constraint to add the scroll
     *        pane at (e.g. {@link BorderLayout#CENTER}), never null
     * @return this panel, for chaining
     * @throws NullPointerException if external or borderLayoutPosition is null
     */
    public MDViewerPanel overrideScrollPane(JScrollPane external, String borderLayoutPosition) {
        SUS.checkIfNull("scrollPane null", external);
        SUS.checkIfNull("borderLayoutPosition null", borderLayoutPosition);
        remove(scrollPane);
        scrollPane = external;
        scrollPane.setViewportView(viewer);
        add(scrollPane, borderLayoutPosition);
        revalidate();
        repaint();
        return this;
    }

    private void applyStyles(StyleSheet styles) {
        Color fg = viewer.getForeground();
        Color bg = viewer.getBackground();
        String codeBg = toHex(GUIUtil.interpolateColors(bg, fg, 0.08f));
        String border = toHex(GUIUtil.interpolateColors(bg, fg, 0.35f));
        String muted = toHex(GUIUtil.interpolateColors(bg, fg, 0.6f));

        styles.addRule("body { margin: 8px; }");
        styles.addRule("code, tt, pre { font-family: monospace; background-color: " + codeBg + "; }");
        styles.addRule("pre { margin-left: 8px; }");
        styles.addRule("blockquote { margin-left: 12px; font-style: italic; color: " + muted + "; }");
        styles.addRule("th, td { border-style: solid; border-width: 1px; border-color: " + border + "; padding: 3px; }");
        styles.addRule("hr { border-style: solid; border-width: 1px; border-color: " + border + "; }");
    }

    private void onHyperlink(HyperlinkEvent e) {
        if (e.getEventType() == HyperlinkEvent.EventType.ACTIVATED && e.getURL() != null) {
            try {
                if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE))
                    Desktop.getDesktop().browse(e.getURL().toURI());
            } catch (Exception ex) {
                // best effort: no browser available, leave the link inert
            }
        }
    }

    private static String toHex(Color c) {
        return String.format("#%02x%02x%02x", c.getRed(), c.getGreen(), c.getBlue());
    }

    /**
     * @return the response decoder used by {@link #setMarkdown(NVGenericMap)}
     */
    public DataDecoder<NVGenericMap, String> getNVGMDecoder() {
        return nvgmDecoder;
    }

    /**
     * Replaces the response decoder used by {@link #setMarkdown(NVGenericMap)},
     * e.g. to support a provider other than OpenAI. The decoder receives the
     * parsed response map (possibly null) and returns the markdown to render,
     * or null to clear the panel.
     *
     * @param nvgmDecoder the decoder, never null
     * @return this panel, for chaining
     * @throws NullPointerException if nvgmDecoder is null
     */
    public MDViewerPanel setNVGMDecoder(DataDecoder<NVGenericMap, String> nvgmDecoder) {
        SUS.checkIfNull("nvgmDecoder null", nvgmDecoder);
        this.nvgmDecoder = nvgmDecoder;
        return this;
    }
}
