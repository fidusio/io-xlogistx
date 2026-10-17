package io.xlogistx.editor.pdf;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.PDResources;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.PDFont;
import org.apache.pdfbox.pdmodel.graphics.color.PDColor;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationFreeText;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceDictionary;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceStream;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDBorderStyleDictionary;

import java.awt.Color;
import java.awt.Font;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Draws the normal appearance of a free text annotation itself, with the
 * chosen font embedded (see {@link EditorFonts}: the bundled Roboto by default,
 * or any installed TrueType family, a sealed subset font per appearance), so
 * non-Latin-1 text renders; PDFBox's own handler uses Helvetica and shows
 * boxes. Text colour and size come from the annotation's {@code DA}
 * ({@code /Helv 12 Tf r g b rg}), the font family and bold / italic from its
 * default style string {@code DS} ({@code font-family: Arial; font-weight:
 * bold; font-style: italic; text-decoration: underline line-through;
 * background-color: #RRGGBB} for a highlight behind the text, the CSS-like
 * form the PDF specification gives it), the box background from {@code C},
 * the border width from {@code BS}, the line alignment from {@code Q}
 * (0 left, 1 centred, 2 right).
 * Characters the font lacks are drawn as {@code ?}. Falls back to the default
 * family when the chosen one cannot be loaded, and to Helvetica when even the
 * bundled font is missing.
 */
public final class FreeTextAppearance {

    private static final Pattern DA_SIZE = Pattern.compile("([0-9.]+)\\s+Tf");
    private static final Pattern DA_RGB = Pattern.compile("([0-9.]+)\\s+([0-9.]+)\\s+([0-9.]+)\\s+rg");
    private static final Pattern DA_GRAY = Pattern.compile("([0-9.]+)\\s+g\\b");
    private static final float PADDING = 3f;
    private static final float LINE_HEIGHT = 1.2f;
    /** Underline position below the baseline and thickness, as fractions of the font size. */
    public static final float UNDERLINE_DROP = 0.12f, UNDERLINE_THICKNESS = 0.06f;
    /** Strikethrough position above the baseline, as a fraction of the font size (same thickness as the underline). */
    public static final float STRIKE_RISE = 0.28f;
    /** The highlight behind a line: from this far below the baseline, this tall, as fractions of the font size. */
    public static final float HIGHLIGHT_DESCENT = 0.25f, HIGHLIGHT_HEIGHT = 1.2f;

    private FreeTextAppearance() {
    }

    /**
     * (Re)builds the annotation's normal appearance from its dictionary.
     *
     * @param doc the document, never null
     * @param a   the annotation; needs a rectangle
     */
    public static void build(PDDocument doc, PDAnnotationFreeText a) {
        PDRectangle rect = a.getRectangle();
        if (rect == null)
            return;
        float w = Math.max(1f, rect.getWidth()), h = Math.max(1f, rect.getHeight());
        String da = a.getDefaultAppearance(), ds = a.getDefaultStyleString();
        float size = fontSize(da);
        Color text = textColor(da);
        Color fill = AnnotationFactory.awtColor(a.getColor());
        PDBorderStyleDictionary bs = a.getBorderStyle();
        float border = bs == null ? 0f : bs.getWidth();
        boolean underline = underline(ds), strike = strikethrough(ds);
        Color highlight = highlight(ds);
        int q = a.getQ();
        float align = q == 1 ? 0.5f : q == 2 ? 1f : 0f;
        try {
            PDFont font = font(doc, fontFamily(ds), fontStyle(ds));
            PDAppearanceStream ap = new PDAppearanceStream(doc);
            ap.setBBox(new PDRectangle(0, 0, w, h));
            PDResources res = new PDResources();
            res.add(font);
            ap.setResources(res);
            try (PDPageContentStream cs = new PDPageContentStream(doc, ap)) {
                if (fill != null) {
                    cs.setNonStrokingColor(fill);
                    cs.addRect(0, 0, w, h);
                    cs.fill();
                }
                if (border > 0) {
                    cs.setStrokingColor(text);
                    cs.setLineWidth(border);
                    cs.addRect(border / 2, border / 2, w - border, h - border);
                    cs.stroke();
                }
                String contents = a.getContents();
                if (contents != null && !contents.isEmpty()) {
                    float inset = PADDING + border;
                    float room = w - 2 * inset;
                    List<String> lines = wrap(font, size, contents, room);
                    float baseline = h - inset - size * 0.85f;
                    // where each line starts: left, centred or right in the room (Q)
                    float[] starts = new float[lines.size()], widths = new float[lines.size()];
                    for (int i = 0; i < lines.size(); i++) {
                        widths[i] = font.getStringWidth(lines.get(i)) / 1000f * size;
                        starts[i] = inset + Math.max(0f, room - widths[i]) * align;
                    }
                    if (highlight != null) {
                        // the highlight goes under the text: one band per line, as wide as the line
                        cs.setNonStrokingColor(highlight);
                        float y = baseline;
                        for (int i = 0; i < lines.size(); i++) {
                            if (widths[i] > 0) {
                                cs.addRect(starts[i], y - size * HIGHLIGHT_DESCENT, widths[i], size * HIGHLIGHT_HEIGHT);
                                cs.fill();
                            }
                            y -= size * LINE_HEIGHT;
                        }
                    }
                    cs.beginText();
                    cs.setFont(font, size);
                    cs.setNonStrokingColor(text);
                    float x = 0f;
                    for (int i = 0; i < lines.size(); i++) {
                        cs.newLineAtOffset(starts[i] - x, i == 0 ? baseline : -size * LINE_HEIGHT);
                        x = starts[i];
                        cs.showText(lines.get(i));
                    }
                    cs.endText();
                    if (underline || strike) {
                        // one bar per line (under the baseline / through the x-height), in the text colour
                        cs.setNonStrokingColor(text);
                        float y = baseline, thickness = Math.max(0.5f, size * UNDERLINE_THICKNESS);
                        for (int i = 0; i < lines.size(); i++) {
                            if (widths[i] > 0) {
                                if (underline) {
                                    cs.addRect(starts[i], y - size * UNDERLINE_DROP, widths[i], thickness);
                                    cs.fill();
                                }
                                if (strike) {
                                    cs.addRect(starts[i], y + size * STRIKE_RISE, widths[i], thickness);
                                    cs.fill();
                                }
                            }
                            y -= size * LINE_HEIGHT;
                        }
                    }
                }
            }
            EditorFonts.seal(doc, font); // the subset is built now, so the box renders right before any save
            PDAppearanceDictionary apd = new PDAppearanceDictionary();
            apd.setNormalAppearance(ap);
            a.setAppearance(apd);
        } catch (IOException e) {
            a.constructAppearances(doc); // PDFBox's Helvetica appearance is better than none
        }
    }

    /** @return the font size in the DA string, 12 when absent */
    public static float fontSize(String da) {
        if (da != null) {
            Matcher m = DA_SIZE.matcher(da);
            if (m.find())
                try {
                    float f = Float.parseFloat(m.group(1));
                    if (f > 0)
                        return f;
                } catch (NumberFormatException ignore) {
                    // fall through
                }
        }
        return 12f;
    }

    /** @return the fill colour in the DA string, black when absent */
    public static Color textColor(String da) {
        if (da != null) {
            Matcher m = DA_RGB.matcher(da);
            if (m.find())
                return new Color(f(m.group(1)), f(m.group(2)), f(m.group(3)));
            Matcher g = DA_GRAY.matcher(da);
            if (g.find())
                return new Color(f(g.group(1)), f(g.group(1)), f(g.group(1)));
        }
        return Color.BLACK;
    }

    private static float f(String s) {
        try {
            return Math.max(0f, Math.min(1f, Float.parseFloat(s)));
        } catch (NumberFormatException e) {
            return 0f;
        }
    }

    /**
     * The default style string ({@code DS}) carrying a style's font: family,
     * weight, style, plus size and colour for other readers.
     */
    public static String defaultStyle(AnnotationStyle style) {
        Color c = style.getStrokeColor();
        String ds = String.format(Locale.US, "font-family: %s; font-size: %.1fpt; font-weight: %s; font-style: %s; text-decoration: %s; color: #%02X%02X%02X",
                style.getFontFamily(), style.getFontSize(), style.isBold() ? "bold" : "normal", style.isItalic() ? "italic" : "normal",
                decoration(style), c.getRed(), c.getGreen(), c.getBlue());
        Color h = style.getHighlightColor();
        if (h != null)
            ds += String.format(Locale.US, "; background-color: #%02X%02X%02X", h.getRed(), h.getGreen(), h.getBlue());
        return ds;
    }

    /** @return the {@code background-color} of a DS string as the highlight behind the text ({@code #RGB} / {@code #RRGGBB}), null when absent or unreadable */
    public static Color highlight(String ds) {
        String v = property(ds, "background-color");
        if (v == null)
            return null;
        v = v.trim().toLowerCase(Locale.ROOT);
        if (v.equals("none") || v.equals("transparent"))
            return null;
        try {
            if (v.startsWith("#") && v.length() == 4)
                return new Color(Integer.parseInt(v.substring(1, 2), 16) * 17, Integer.parseInt(v.substring(2, 3), 16) * 17, Integer.parseInt(v.substring(3, 4), 16) * 17);
            if (v.startsWith("#") && v.length() == 7)
                return new Color(Integer.parseInt(v.substring(1, 7), 16));
        } catch (NumberFormatException ignore) {
            // not a colour we read
        }
        return null;
    }

    private static String decoration(AnnotationStyle style) {
        if (!style.isUnderline() && !style.isStrikethrough())
            return "none";
        return (style.isUnderline() ? "underline " : "") + (style.isStrikethrough() ? "line-through" : "").trim();
    }

    /** @return the {@code font-family} of a DS string (the first family of a list, quotes stripped), the default family when absent */
    public static String fontFamily(String ds) {
        String v = property(ds, "font-family");
        if (v == null)
            return EditorFonts.DEFAULT_FAMILY;
        int comma = v.indexOf(',');
        if (comma >= 0)
            v = v.substring(0, comma);
        v = v.trim().replace("\"", "").replace("'", "").trim();
        return EditorFonts.familyOrDefault(v);
    }

    /** @return the {@link Font} style bits a DS string's {@code font-weight} / {@code font-style} give */
    public static int fontStyle(String ds) {
        int style = Font.PLAIN;
        String weight = property(ds, "font-weight");
        if (weight != null) {
            weight = weight.trim().toLowerCase(Locale.ROOT);
            try {
                if (weight.startsWith("bold") || (weight.matches("[0-9]+") && Integer.parseInt(weight) >= 600))
                    style |= Font.BOLD;
            } catch (NumberFormatException ignore) {
                // not bold
            }
        }
        String fs = property(ds, "font-style");
        if (fs != null && (fs.trim().equalsIgnoreCase("italic") || fs.trim().equalsIgnoreCase("oblique")))
            style |= Font.ITALIC;
        return style;
    }

    /** @return the {@code Q} value for an alignment: 0 left, 1 centred, 2 right */
    public static int q(TextEditor.Alignment alignment) {
        return alignment == TextEditor.Alignment.CENTER ? 1 : alignment == TextEditor.Alignment.RIGHT ? 2 : 0;
    }

    /** @return the alignment a {@code Q} value means (anything but 1 and 2 is left) */
    public static TextEditor.Alignment alignment(int q) {
        return q == 1 ? TextEditor.Alignment.CENTER : q == 2 ? TextEditor.Alignment.RIGHT : TextEditor.Alignment.LEFT;
    }

    /** @return true when a DS string's {@code text-decoration} names an underline */
    public static boolean underline(String ds) {
        String v = property(ds, "text-decoration");
        return v != null && v.toLowerCase(Locale.ROOT).contains("underline");
    }

    /** @return true when a DS string's {@code text-decoration} names a line-through */
    public static boolean strikethrough(String ds) {
        String v = property(ds, "text-decoration");
        return v != null && v.toLowerCase(Locale.ROOT).contains("line-through");
    }

    private static String property(String ds, String name) {
        if (ds == null)
            return null;
        for (String part : ds.split(";")) {
            int colon = part.indexOf(':');
            if (colon < 0)
                continue;
            if (part.substring(0, colon).trim().equalsIgnoreCase(name))
                return part.substring(colon + 1);
        }
        return null;
    }

    /** The document's default font (bundled Roboto, or Helvetica when the resource is missing). */
    static PDFont font(PDDocument doc) throws IOException {
        return EditorFonts.load(doc, EditorFonts.DEFAULT_FAMILY, Font.PLAIN);
    }

    /** The font for a family and style, falling back to the default family when it cannot be loaded. */
    static PDFont font(PDDocument doc, String family, int style) throws IOException {
        try {
            return EditorFonts.load(doc, family, style);
        } catch (IOException e) {
            if (EditorFonts.isBundled(family))
                throw e;
            return EditorFonts.load(doc, EditorFonts.DEFAULT_FAMILY, style);
        }
    }

    /** Word-wraps the text to the width; characters without a glyph become '?'. */
    static List<String> wrap(PDFont font, float size, String text, float width) throws IOException {
        List<String> lines = new ArrayList<>();
        for (String paragraph : text.split("\\r?\\n", -1)) {
            String p = sanitize(font, paragraph);
            StringBuilder line = new StringBuilder();
            for (String word : p.split(" ", -1)) {
                String candidate = line.length() == 0 ? word : line + " " + word;
                if (line.length() > 0 && widthOf(font, size, candidate) > width) {
                    lines.add(line.toString());
                    line = new StringBuilder(word);
                } else
                    line = new StringBuilder(candidate);
                // a single word wider than the box is broken by characters
                while (widthOf(font, size, line.toString()) > width && line.length() > 1) {
                    int cut = line.length() - 1;
                    while (cut > 1 && widthOf(font, size, line.substring(0, cut)) > width)
                        cut--;
                    lines.add(line.substring(0, cut));
                    line = new StringBuilder(line.substring(cut));
                }
            }
            lines.add(line.toString());
        }
        return lines;
    }

    private static float widthOf(PDFont font, float size, String s) throws IOException {
        return font.getStringWidth(s) / 1000f * size;
    }

    private static String sanitize(PDFont font, String s) {
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); ) {
            int cp = s.codePointAt(i);
            String ch = new String(Character.toChars(cp));
            if (cp == '\t')
                ch = "    ";
            else if (Character.isISOControl(cp))
                ch = "";
            else
                try {
                    font.encode(ch);
                } catch (IOException | IllegalArgumentException e) {
                    ch = "?";
                }
            sb.append(ch);
            i += Character.charCount(cp);
        }
        return sb.toString();
    }

    /** @return the DA string's colour as a PDF colour, for callers that need one */
    public static PDColor pdTextColor(String da) {
        return AnnotationFactory.pdColor(textColor(da));
    }
}
