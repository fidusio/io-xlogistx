package io.xlogistx.editor.pdf;

import io.xlogistx.gui.pdf.PageTransform;
import org.apache.pdfbox.contentstream.PDFStreamEngine;
import org.apache.pdfbox.contentstream.operator.Operator;
import org.apache.pdfbox.contentstream.operator.color.SetNonStrokingColor;
import org.apache.pdfbox.contentstream.operator.color.SetNonStrokingColorN;
import org.apache.pdfbox.contentstream.operator.color.SetNonStrokingColorSpace;
import org.apache.pdfbox.contentstream.operator.color.SetNonStrokingDeviceCMYKColor;
import org.apache.pdfbox.contentstream.operator.color.SetNonStrokingDeviceGrayColor;
import org.apache.pdfbox.contentstream.operator.color.SetNonStrokingDeviceRGBColor;
import org.apache.pdfbox.contentstream.operator.state.Concatenate;
import org.apache.pdfbox.contentstream.operator.state.Restore;
import org.apache.pdfbox.contentstream.operator.state.Save;
import org.apache.pdfbox.contentstream.operator.state.SetGraphicsStateParameters;
import org.apache.pdfbox.contentstream.operator.state.SetMatrix;
import org.apache.pdfbox.contentstream.operator.text.BeginText;
import org.apache.pdfbox.contentstream.operator.text.EndText;
import org.apache.pdfbox.contentstream.operator.text.MoveText;
import org.apache.pdfbox.contentstream.operator.text.MoveTextSetLeading;
import org.apache.pdfbox.contentstream.operator.text.NextLine;
import org.apache.pdfbox.contentstream.operator.text.SetCharSpacing;
import org.apache.pdfbox.contentstream.operator.text.SetFontAndSize;
import org.apache.pdfbox.contentstream.operator.text.SetTextHorizontalScaling;
import org.apache.pdfbox.contentstream.operator.text.SetTextLeading;
import org.apache.pdfbox.contentstream.operator.text.SetTextRenderingMode;
import org.apache.pdfbox.contentstream.operator.text.SetTextRise;
import org.apache.pdfbox.contentstream.operator.text.SetWordSpacing;
import org.apache.pdfbox.contentstream.operator.text.ShowText;
import org.apache.pdfbox.contentstream.operator.text.ShowTextAdjusted;
import org.apache.pdfbox.contentstream.operator.text.ShowTextLine;
import org.apache.pdfbox.contentstream.operator.text.ShowTextLineAndSpace;
import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSFloat;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSString;
import org.apache.pdfbox.io.IOUtils;
import org.apache.pdfbox.pdfparser.PDFStreamParser;
import org.apache.pdfbox.pdfwriter.ContentStreamWriter;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDResources;
import org.apache.pdfbox.pdmodel.common.PDStream;
import org.apache.pdfbox.pdmodel.font.PDFont;
import org.apache.pdfbox.pdmodel.font.PDType0Font;
import org.apache.pdfbox.pdmodel.graphics.color.PDColor;
import org.apache.pdfbox.pdmodel.graphics.form.PDFormXObject;
import org.apache.pdfbox.pdmodel.graphics.state.PDTextState;
import org.apache.pdfbox.text.TextPosition;
import org.apache.pdfbox.util.Matrix;
import org.apache.pdfbox.util.Vector;
import org.zoxweb.shared.util.SUS;

import java.awt.Color;
import java.awt.Font;
import java.awt.geom.AffineTransform;
import java.awt.geom.NoninvertibleTransformException;
import java.awt.geom.Point2D;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * Rewrites text that is already on a page, in place, in the page's content
 * stream. {@link #glyphs(PDPage)} walks the page's own stream (not embedded
 * forms) and records every shown glyph with the operator, string and code
 * index that produced it plus its position, advance, font resource name and
 * fill colour; {@link #match} ties the viewer's selected {@link TextPosition}s
 * to those glyphs by position and unicode; {@link #replace} re-encodes the
 * affected string operands and writes the stream back. The replacement is
 * placed with an {@link Alignment} inside the room the old text took (left:
 * same start, right: same end, centre: same middle) and the text that follows
 * in the same string stays where it was, using {@code TJ} adjustments;
 * nothing reflows.
 * <p>
 * By default the replacement keeps the font of the text it replaces, so a
 * character the font cannot encode (a subset font only knows the glyphs the
 * document already uses) is refused with an {@link IllegalArgumentException}
 * naming it. A {@link Format} can instead give the replacement another font
 * (any of {@link EditorFonts}, embedded into the page's resources and sealed), another
 * face of the same family (bold / italic, when the family is installed),
 * another size or another colour: the replacement is then written as its
 * own text run between {@code Tf} / {@code rg} switches, and the previous
 * font, size and colour are restored after it so the rest of the line is
 * untouched (a colour in a non-device colour space is restored as its RGB
 * equivalent). An underline or strikethrough is a stroked line under /
 * through the replacement, drawn right after the text object; a highlight
 * is a filled band behind it, drawn right before the text object so the
 * text stays on top. Pure PDFBox, no Swing; call under the document lock.
 */
public final class TextEditor {

    /** Where the replacement sits inside the room the old text took. */
    public enum Alignment {
        LEFT, CENTER, RIGHT
    }

    /**
     * How a replacement is written: a font family (null = the font of the
     * replaced text) and style ({@link #KEEP_STYLE} = the face of the
     * replaced text; with a null family, bold / italic bits load another face
     * of the current font's family, which must be installed), a size in
     * points as rendered on the page (0 = the size of the replaced text), a
     * colour (null = the colour of the replaced text), whether the replacement
     * is underlined / struck through and a highlight colour behind it (null =
     * none). {@link #SAME} keeps everything.
     */
    public static final class Format {
        /** Style value that keeps the face of the replaced text. */
        public static final int KEEP_STYLE = -1;
        /** Keeps the font, face, size and colour of the replaced text, no underline or strikethrough. */
        public static final Format SAME = new Format(null, KEEP_STYLE, 0f, null, false, false, null);

        /** The family (see {@link EditorFonts#families()}), null = keep the font. */
        public final String fontFamily;
        /** {@link Font} style bits, or {@link #KEEP_STYLE}. */
        public final int fontStyle;
        /** Rendered size in points, 0 = keep. */
        public final float fontSize;
        /** Text colour, null = keep. */
        public final Color color;
        /** Whether a line is drawn under the replacement. */
        public final boolean underline;
        /** Whether a line is drawn through the replacement. */
        public final boolean strikethrough;
        /** Colour of a band painted behind the replacement, null = none. */
        public final Color highlight;

        /** A format without underline or strikethrough. */
        public Format(String fontFamily, int fontStyle, float fontSize, Color color) {
            this(fontFamily, fontStyle, fontSize, color, false, false);
        }

        /** A format without strikethrough. */
        public Format(String fontFamily, int fontStyle, float fontSize, Color color, boolean underline) {
            this(fontFamily, fontStyle, fontSize, color, underline, false);
        }

        /** A format without highlight. */
        public Format(String fontFamily, int fontStyle, float fontSize, Color color, boolean underline, boolean strikethrough) {
            this(fontFamily, fontStyle, fontSize, color, underline, strikethrough, null);
        }

        public Format(String fontFamily, int fontStyle, float fontSize, Color color, boolean underline, boolean strikethrough, Color highlight) {
            this.fontFamily = fontFamily == null || fontFamily.trim().isEmpty() ? null : fontFamily.trim();
            this.fontStyle = fontStyle < 0 ? KEEP_STYLE : fontStyle & (Font.BOLD | Font.ITALIC);
            this.fontSize = Math.max(0f, fontSize);
            this.color = color;
            this.underline = underline;
            this.strikethrough = strikethrough;
            this.highlight = highlight;
        }

        /** @return true when nothing changes (font, face, size and colour all kept, no underline) */
        public boolean isSame() {
            return fontFamily == null && fontStyle == KEEP_STYLE && fontSize <= 0 && color == null && !underline && !strikethrough && highlight == null;
        }

        @Override
        public String toString() {
            return "Format{font=" + (fontFamily == null ? "same" : fontFamily) + ", style="
                    + (fontStyle == KEEP_STYLE ? "same" : EditorFonts.describe("", fontStyle).trim())
                    + ", size=" + (fontSize <= 0 ? "same" : String.valueOf(fontSize)) + ", color=" + color
                    + (underline ? ", underlined" : "") + (strikethrough ? ", struck" : "")
                    + (highlight != null ? ", highlight=" + highlight : "") + "}";
        }
    }

    /** One glyph the page stream shows. Positions are in PDF user space. */
    public static final class Glyph {
        /** Index of the operator in the page stream (operators counted from 0). */
        public final int op;
        /** Index of the string within the operator (0 for Tj; the n-th string of a TJ array). */
        public final int string;
        /** Index of the character code within that string. */
        public final int code;
        /** The character code itself. */
        public final int codeValue;
        public final String unicode;
        public final PDFont font;
        /** Baseline origin. */
        public final float x, y;
        /** Advance and font size in user space (approximate box). */
        public final float width, height;
        /** Advance in thousandths of text space (font width units), char spacing and word spacing in text space, font size. */
        public final float advance1000, charSpacing, wordSpacing, fontSize;
        /** True when word spacing applies to this glyph (single-byte code 32). */
        public final boolean wordSpaced;
        /** The font's resource name in the page (the {@code Tf} operand), null when the font came from the graphics state. */
        public final COSName fontName;
        /** The fill colour the glyph is drawn with, as RGB; null when it cannot be told (a pattern). */
        public final Color color;
        /** The text rendering matrix at the glyph (text space scaled by the font size to user space) and the CTM. */
        public final Matrix trm, ctm;

        Glyph(int op, int string, int code, int codeValue, String unicode, PDFont font, float x, float y, float width, float height,
              float advance1000, float charSpacing, float wordSpacing, float fontSize, boolean wordSpaced, COSName fontName, Color color,
              Matrix trm, Matrix ctm) {
            this.op = op;
            this.string = string;
            this.code = code;
            this.codeValue = codeValue;
            this.unicode = unicode;
            this.font = font;
            this.x = x;
            this.y = y;
            this.width = width;
            this.height = height;
            this.advance1000 = advance1000;
            this.charSpacing = charSpacing;
            this.wordSpacing = wordSpacing;
            this.fontSize = fontSize;
            this.wordSpaced = wordSpaced;
            this.fontName = fontName;
            this.color = color;
            this.trm = trm;
            this.ctm = ctm;
        }

        /** @return the glyph's full advance in TJ units (thousandths of text space scaled by the font size) */
        float advanceTJ() {
            float extra = charSpacing + (wordSpaced ? wordSpacing : 0);
            return advance1000 + (fontSize == 0 ? 0 : extra * 1000f / fontSize);
        }

        /** @return the size the glyph is rendered at, in points (the {@code Tf} size scaled by the text and page matrices) */
        public float renderedSize() {
            return height > 0 ? height : fontSize;
        }

        @Override
        public String toString() {
            return "'" + unicode + "'@op" + op + "/" + string + "/" + code + " (" + x + "," + y + ")";
        }
    }

    /** How far (points, view space) a text position may sit from its glyph and still match. */
    private static final float MATCH_TOLERANCE = 0.75f;

    private TextEditor() {
    }

    /**
     * Every glyph the page's own content stream shows, in stream order.
     *
     * @param page the page, never null
     * @return the glyphs; empty when the page shows no text itself
     * @throws IOException if the stream cannot be read
     */
    public static List<Glyph> glyphs(PDPage page) throws IOException {
        SUS.checkIfNull("page null", page);
        Locator locator = new Locator();
        locator.processPage(page);
        return locator.glyphs;
    }

    /**
     * Ties selected text positions (as the viewer's extractor produced them) to
     * the page's glyphs by position and unicode.
     *
     * @param glyphs    from {@link #glyphs(PDPage)}
     * @param t         the page transform
     * @param positions the selected positions, in selection order
     * @return the matched glyphs, in selection order
     * @throws IllegalArgumentException if a position has no glyph (text drawn by a form XObject, or the page changed)
     */
    public static List<Glyph> match(List<Glyph> glyphs, PageTransform t, List<TextPosition> positions) {
        SUS.checkIfNull("glyphs null", glyphs);
        SUS.checkIfNull("transform null", t);
        SUS.checkIfNull("positions null", positions);
        List<Glyph> ret = new ArrayList<>(positions.size());
        boolean[] used = new boolean[glyphs.size()];
        for (TextPosition tp : positions) {
            int best = -1;
            float bestDist = MATCH_TOLERANCE;
            for (int i = 0; i < glyphs.size(); i++) {
                if (used[i])
                    continue;
                Glyph g = glyphs.get(i);
                if (!g.unicode.equals(tp.getUnicode()))
                    continue;
                Point2D.Float v = t.toView(new Point2D.Float(g.x, g.y));
                float d = Math.max(Math.abs(v.x - tp.getXDirAdj()), Math.abs(v.y - tp.getYDirAdj()));
                if (d < bestDist) {
                    bestDist = d;
                    best = i;
                }
            }
            if (best < 0)
                throw new IllegalArgumentException("The selected text could not be located in the page content"
                        + " (it may be drawn by an embedded form or image, or the page changed). Reselect it and try again.");
            used[best] = true;
            ret.add(glyphs.get(best));
        }
        return ret;
    }

    /**
     * @return the glyph that comes first in the stream (the replacement is
     *         inserted at it and takes its font, size and colour); null for an empty list
     */
    public static Glyph first(List<Glyph> selected) {
        Glyph first = null;
        for (Glyph g : selected)
            if (first == null || g.op < first.op || (g.op == first.op && (g.string < first.string || (g.string == first.string && g.code < first.code))))
                first = g;
        return first;
    }

    /**
     * @return the page's content stream bytes (all parts concatenated), empty when it has none
     */
    public static byte[] originalContent(PDPage page) throws IOException {
        if (!page.hasContents())
            return new byte[0];
        try (InputStream in = page.getContents()) {
            return IOUtils.toByteArray(in);
        }
    }

    /** {@link #replace(PDPage, List, String, Alignment)} aligned left. */
    public static byte[] replace(PDPage page, List<Glyph> selected, String replacement) throws IOException {
        return replace(page, selected, replacement, Alignment.LEFT);
    }

    /** {@link #replace(PDDocument, PDPage, List, String, Alignment, Format)} keeping the font, size and colour. */
    public static byte[] replace(PDPage page, List<Glyph> selected, String replacement, Alignment alignment) throws IOException {
        return replace(null, page, selected, replacement, alignment, Format.SAME);
    }

    /**
     * Rebuilds the page's content stream with the selected glyphs replaced by
     * {@code replacement}, placed by {@code alignment} inside the room the old
     * text took; the text following in the same string keeps its position.
     * With {@link Format#SAME} the replacement is encoded with the font of the
     * first selected glyph and the page is not changed (see {@link #setContent});
     * with another font in the format, that font is embedded and added to the
     * page's resources (which stays harmless when the edit is undone).
     *
     * @param doc         the document; needed when the format names a font, may be null otherwise
     * @param page        the page
     * @param selected    the glyphs to replace, from {@link #match}; never empty
     * @param replacement the new text (empty deletes the glyphs)
     * @param alignment   where the replacement sits
     * @param format      font, size and colour of the replacement; null = {@link Format#SAME}
     * @return the new stream bytes
     * @throws IllegalArgumentException if the font lacks a glyph for a character of the replacement,
     *                                  the requested font cannot be loaded, or the font cannot be changed here
     * @throws IOException              if the stream cannot be parsed or written
     */
    public static byte[] replace(PDDocument doc, PDPage page, List<Glyph> selected, String replacement, Alignment alignment, Format format)
            throws IOException {
        SUS.checkIfNull("page null", page);
        SUS.checkIfNull("glyphs null", selected);
        if (selected.isEmpty())
            throw new IllegalArgumentException("Select the text to replace first.");
        if (alignment == null)
            alignment = Alignment.LEFT;
        Format fmt = format == null ? Format.SAME : format;
        String text = replacement == null ? "" : replacement;
        Glyph first = first(selected);

        // the run the replacement is written with
        PDFont font = first.font;
        float sizeOperand = first.fontSize;
        boolean switchFont = false;
        int style = fmt.fontStyle == Format.KEEP_STYLE ? EditorFonts.styleOf(first.font) : fmt.fontStyle;
        if (fmt.fontFamily != null) {
            if (doc == null)
                throw new IllegalArgumentException("A document is needed to change the font.");
            try {
                font = EditorFonts.load(doc, fmt.fontFamily, style);
            } catch (IOException e) {
                throw new IllegalArgumentException("The font \"" + EditorFonts.describe(fmt.fontFamily, style) + "\" cannot be used: " + e.getMessage());
            }
            switchFont = true;
        } else if (style != EditorFonts.styleOf(first.font)) {
            // another face of the same family
            if (doc == null)
                throw new IllegalArgumentException("A document is needed to change the face.");
            String family = EditorFonts.familyOf(first.font);
            if (family == null)
                throw new IllegalArgumentException("The family of \"" + first.font.getName() + "\" is not installed, so it has no "
                        + EditorFonts.describe("", style).trim().toLowerCase(java.util.Locale.ROOT) + " face here: pick a font to use one.");
            try {
                font = EditorFonts.load(doc, family, style);
            } catch (IOException e) {
                throw new IllegalArgumentException("The font \"" + EditorFonts.describe(family, style) + "\" cannot be used: " + e.getMessage());
            }
            switchFont = true;
        }
        if (fmt.fontSize > 0) {
            // the Tf operand that renders at the asked size, given how the old one was scaled
            float scale = first.height > 0 && first.fontSize > 0 ? first.fontSize / first.height : 1f;
            sizeOperand = fmt.fontSize * scale;
            switchFont = switchFont || Math.abs(sizeOperand - first.fontSize) > 0.001f;
        }
        if (switchFont && first.fontName == null)
            throw new IllegalArgumentException("The font of this text is set outside the page content (by a graphics state), so only its text can be changed here.");
        boolean switchColor = fmt.color != null && !fmt.color.equals(first.color);
        COSName fontName = first.fontName;
        if (font != first.font) {
            PDResources res = page.getResources();
            if (res == null) {
                res = new PDResources();
                page.setResources(res);
            }
            fontName = res.add(font);
        }
        byte[] insert = encode(font, text);

        // room: old advance minus new advance, in TJ units of the old font; split before/after by alignment
        float oldWidth = 0;
        for (Glyph g : selected)
            oldWidth += g.advanceTJ();
        float newWidth = advanceTJ(first, font, sizeOperand, text);
        if (font != first.font)
            EditorFonts.seal(doc, font); // all its text is encoded: build the subset now so the page renders right
        float delta = oldWidth - newWidth;
        float before = alignment == Alignment.LEFT ? 0 : alignment == Alignment.RIGHT ? delta : delta / 2;
        float after = delta - before;
        List<Object> underline = null;
        if ((fmt.underline || fmt.strikethrough) && insert.length > 0) {
            Color lineColor = fmt.color != null ? fmt.color : first.color == null ? Color.BLACK : first.color;
            underline = new ArrayList<>();
            if (fmt.underline)
                underline.addAll(lineTokens(first, before, newWidth, sizeOperand, lineColor, -FreeTextAppearance.UNDERLINE_DROP));
            if (fmt.strikethrough)
                underline.addAll(lineTokens(first, before, newWidth, sizeOperand, lineColor, FreeTextAppearance.STRIKE_RISE));
            if (underline.isEmpty())
                underline = null;
        }
        boolean underlined = false;
        List<Object> highlight = fmt.highlight != null && insert.length > 0 ? bandTokens(first, before, newWidth, sizeOperand, fmt.highlight) : null;

        // op -> string -> codes
        Map<Integer, Map<Integer, TreeSet<Integer>>> sel = new TreeMap<>();
        for (Glyph g : selected)
            sel.computeIfAbsent(g.op, k -> new TreeMap<>()).computeIfAbsent(g.string, k -> new TreeSet<>()).add(g.code);

        List<Object> tokens = new PDFStreamParser(page).parse();
        List<Object> out = new ArrayList<>(tokens.size() + 32);
        // the highlight goes before the text object the replacement sits in (page level: no path ops inside BT/ET)
        int highlightAt = -1;
        if (highlight != null && !highlight.isEmpty()) {
            int idx = -1, lastBT = -1;
            for (Object tok : tokens) {
                if (!(tok instanceof Operator))
                    continue;
                idx++;
                if ("BT".equals(((Operator) tok).getName()))
                    lastBT = idx;
                if (idx == first.op) {
                    highlightAt = lastBT;
                    break;
                }
            }
            if (highlightAt < 0)
                out.addAll(highlight); // no text object found: at the start, under everything
        }
        int opIndex = -1;
        for (Object tok : tokens) {
            if (!(tok instanceof Operator)) {
                out.add(tok);
                continue;
            }
            opIndex++;
            if (opIndex == highlightAt)
                out.addAll(highlight);
            Map<Integer, TreeSet<Integer>> strings = sel.get(opIndex);
            if (strings == null) {
                out.add(tok);
                if (underline != null && !underlined && opIndex > first.op && "ET".equals(((Operator) tok).getName())) {
                    out.addAll(underline); // right after the text object, in the same graphics state
                    underlined = true;
                }
                continue;
            }
            String name = ((Operator) tok).getName();
            if (out.isEmpty())
                throw new IllegalArgumentException("Malformed text operator in the page content.");
            Object operand = out.remove(out.size() - 1);
            boolean firstOp = opIndex == first.op;
            // the array pieces before the insert, the insert and the pieces after it
            COSArray pre = new COSArray(), ins = new COSArray(), post = new COSArray();
            boolean afterInsert = false;
            if ("TJ".equals(name) && operand instanceof COSArray) {
                COSArray arr = (COSArray) operand;
                int stringIndex = -1;
                for (int k = 0; k < arr.size(); k++) {
                    COSBase el = arr.getObject(k);
                    if (!(el instanceof COSString)) {
                        (afterInsert ? post : pre).add(el);
                        continue;
                    }
                    stringIndex++;
                    TreeSet<Integer> codes = strings.get(stringIndex);
                    if (codes == null) {
                        (afterInsert ? post : pre).add(el);
                        continue;
                    }
                    boolean insertHere = firstOp && stringIndex == first.string;
                    Pieces p = rebuild((COSString) el, first.font, codes, insertHere ? first.code : -1, insert, before, after);
                    addAll(afterInsert ? post : pre, p.pre);
                    if (insertHere) {
                        addAll(ins, p.ins);
                        addAll(post, p.post);
                        afterInsert = true;
                    }
                }
            } else if (("Tj".equals(name) || "'".equals(name) || "\"".equals(name)) && operand instanceof COSString) {
                TreeSet<Integer> codes = strings.get(0);
                Pieces p = rebuild((COSString) operand, first.font, codes == null ? new TreeSet<Integer>() : codes,
                        firstOp ? first.code : -1, insert, before, after);
                if ("\"".equals(name)) {
                    // aw ac string " = aw Tw ac Tc T* string Tj
                    Object ac = out.remove(out.size() - 1), aw = out.remove(out.size() - 1);
                    out.add(aw);
                    out.add(Operator.getOperator("Tw"));
                    out.add(ac);
                    out.add(Operator.getOperator("Tc"));
                    out.add(Operator.getOperator("T*"));
                } else if ("'".equals(name))
                    out.add(Operator.getOperator("T*"));
                addAll(pre, p.pre);
                addAll(ins, p.ins);
                addAll(post, p.post);
            } else
                throw new IllegalArgumentException("Unexpected text operator '" + name + "' in the page content.");

            if (!firstOp || (!switchFont && !switchColor)) {
                // one array, as the page had it
                COSArray all = new COSArray();
                addAll(all, pre);
                addAll(all, ins);
                addAll(all, post);
                if (all.size() == 0)
                    all.add(new COSString(new byte[0]));
                out.add(all);
                out.add(Operator.getOperator("TJ"));
                continue;
            }
            // the replacement as its own run: switch font / colour, write it, switch back
            if (pre.size() > 0) {
                out.add(pre);
                out.add(Operator.getOperator("TJ"));
            }
            if (switchFont) {
                out.add(fontName);
                out.add(new COSFloat(sizeOperand));
                out.add(Operator.getOperator("Tf"));
            }
            if (switchColor)
                addColor(out, fmt.color);
            if (ins.size() > 0) {
                out.add(ins);
                out.add(Operator.getOperator("TJ"));
            }
            if (switchFont) {
                out.add(first.fontName);
                out.add(new COSFloat(first.fontSize));
                out.add(Operator.getOperator("Tf"));
            }
            if (switchColor)
                addColor(out, first.color == null ? Color.BLACK : first.color);
            if (post.size() > 0) {
                out.add(post);
                out.add(Operator.getOperator("TJ"));
            }
        }
        if (underline != null && !underlined)
            out.addAll(underline);
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        new ContentStreamWriter(bytes).writeTokens(out);
        return bytes.toByteArray();
    }

    /**
     * The tokens of a line along the replacement: from the replacement's start
     * (the first glyph's origin shifted by the alignment room) over its advance,
     * {@code riseEm} of the new size above the baseline (negative = below:
     * {@link FreeTextAppearance#UNDERLINE_DROP} for an underline,
     * {@link FreeTextAppearance#STRIKE_RISE} for a strikethrough),
     * {@link FreeTextAppearance#UNDERLINE_THICKNESS} thick, in the text
     * colour; computed through the glyph's text rendering matrix so it follows
     * rotated or scaled text, and expressed in the glyph's CTM space because it
     * is emitted inside that state. Empty when the CTM cannot be inverted.
     *
     * @param before   alignment room before the replacement, TJ units of the old font
     * @param newWidth the replacement's advance, TJ units of the old font
     */
    private static List<Object> lineTokens(Glyph first, float before, float newWidth, float sizeOperand, Color color, float riseEm) {
        if (first.trm == null || first.ctm == null)
            return Collections.emptyList();
        float r = first.fontSize > 0 ? sizeOperand / first.fontSize : 1f; // new size relative to the old Tf size
        float rise = riseEm * r;
        Point2D.Float p1 = first.trm.transformPoint(before / 1000f, rise);
        Point2D.Float p2 = first.trm.transformPoint((before + newWidth) / 1000f, rise);
        float scale = (float) Math.sqrt(Math.abs(first.ctm.getScaleX() * first.ctm.getScaleY() - first.ctm.getShearX() * first.ctm.getShearY()));
        if (scale <= 0)
            return Collections.emptyList();
        float widthUser = Math.max(0.3f, FreeTextAppearance.UNDERLINE_THICKNESS * r * first.renderedSize());
        Point2D q1, q2;
        try {
            AffineTransform inverse = first.ctm.createAffineTransform().createInverse();
            q1 = inverse.transform(p1, null);
            q2 = inverse.transform(p2, null);
        } catch (NoninvertibleTransformException e) {
            return Collections.emptyList();
        }
        List<Object> t = new ArrayList<>(16);
        t.add(Operator.getOperator("q"));
        t.add(new COSFloat(color.getRed() / 255f));
        t.add(new COSFloat(color.getGreen() / 255f));
        t.add(new COSFloat(color.getBlue() / 255f));
        t.add(Operator.getOperator("RG"));
        t.add(new COSFloat(widthUser / scale));
        t.add(Operator.getOperator("w"));
        t.add(new COSFloat((float) q1.getX()));
        t.add(new COSFloat((float) q1.getY()));
        t.add(Operator.getOperator("m"));
        t.add(new COSFloat((float) q2.getX()));
        t.add(new COSFloat((float) q2.getY()));
        t.add(Operator.getOperator("l"));
        t.add(Operator.getOperator("S"));
        t.add(Operator.getOperator("Q"));
        return t;
    }

    /**
     * The tokens of a filled band behind the replacement: its advance wide,
     * from {@link FreeTextAppearance#HIGHLIGHT_DESCENT} below the baseline
     * {@link FreeTextAppearance#HIGHLIGHT_HEIGHT} up, in the new size; through
     * the glyph's text rendering matrix and back through the inverse CTM like
     * {@link #lineTokens}. Empty when the CTM cannot be inverted.
     */
    private static List<Object> bandTokens(Glyph first, float before, float newWidth, float sizeOperand, Color color) {
        if (first.trm == null || first.ctm == null)
            return Collections.emptyList();
        float r = first.fontSize > 0 ? sizeOperand / first.fontSize : 1f;
        float x0 = before / 1000f, x1 = (before + newWidth) / 1000f;
        float y0 = -FreeTextAppearance.HIGHLIGHT_DESCENT * r, y1 = y0 + FreeTextAppearance.HIGHLIGHT_HEIGHT * r;
        Point2D.Float[] corners = {first.trm.transformPoint(x0, y0), first.trm.transformPoint(x1, y0),
                first.trm.transformPoint(x1, y1), first.trm.transformPoint(x0, y1)};
        AffineTransform inverse;
        try {
            inverse = first.ctm.createAffineTransform().createInverse();
        } catch (NoninvertibleTransformException e) {
            return Collections.emptyList();
        }
        List<Object> t = new ArrayList<>(24);
        t.add(Operator.getOperator("q"));
        t.add(new COSFloat(color.getRed() / 255f));
        t.add(new COSFloat(color.getGreen() / 255f));
        t.add(new COSFloat(color.getBlue() / 255f));
        t.add(Operator.getOperator("rg"));
        for (int i = 0; i < corners.length; i++) {
            Point2D p = inverse.transform(corners[i], null);
            t.add(new COSFloat((float) p.getX()));
            t.add(new COSFloat((float) p.getY()));
            t.add(Operator.getOperator(i == 0 ? "m" : "l"));
        }
        t.add(Operator.getOperator("h"));
        t.add(Operator.getOperator("f"));
        t.add(Operator.getOperator("Q"));
        return t;
    }

    private static void addAll(COSArray to, COSArray from) {
        for (int i = 0; i < from.size(); i++)
            to.add(from.getObject(i));
    }

    private static void addColor(List<Object> out, Color c) {
        out.add(new COSFloat(c.getRed() / 255f));
        out.add(new COSFloat(c.getGreen() / 255f));
        out.add(new COSFloat(c.getBlue() / 255f));
        out.add(Operator.getOperator("rg"));
    }

    /**
     * Replaces the page's content stream.
     *
     * @param doc     the document
     * @param page    the page
     * @param content the new stream bytes
     */
    public static void setContent(PDDocument doc, PDPage page, byte[] content) throws IOException {
        PDStream stream = new PDStream(doc);
        try (OutputStream os = stream.createOutputStream(COSName.FLATE_DECODE)) {
            os.write(content);
        }
        page.setContents(stream);
    }

    /**
     * Encodes text with a font, naming every character the font cannot show.
     *
     * @throws IllegalArgumentException listing the unsupported characters
     */
    public static byte[] encode(PDFont font, String text) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        StringBuilder missing = new StringBuilder();
        for (int i = 0; i < text.length(); ) {
            int cp = text.codePointAt(i);
            String ch = new String(Character.toChars(cp));
            try {
                out.write(font.encode(ch));
                // a font PDFBox will subset learns its glyphs from the content stream helper, not from encode
                if (font instanceof PDType0Font && ((PDType0Font) font).willBeSubset())
                    ((PDType0Font) font).addToSubset(cp);
            } catch (IllegalArgumentException | IOException e) {
                if (missing.indexOf(ch) < 0)
                    missing.append(ch);
            }
            i += Character.charCount(cp);
        }
        if (missing.length() > 0)
            throw new IllegalArgumentException("The font \"" + font.getName() + "\" has no glyph for: " + missing
                    + ". Only characters this font already shows in the document can be typed here; pick another font to use them.");
        return out.toByteArray();
    }

    /** The advance of {@code text} in TJ units with the glyph's font, spacing and size. */
    static float advanceTJ(Glyph like, String text) throws IOException {
        return advanceTJ(like, like.font, like.fontSize, text);
    }

    /**
     * The advance of {@code text} written with {@code font} at the {@code Tf}
     * size {@code size}, in TJ units of the glyph's own font size (so the
     * room it takes compares with {@link Glyph#advanceTJ()}).
     */
    static float advanceTJ(Glyph like, PDFont font, float size, String text) throws IOException {
        if (text.isEmpty())
            return 0;
        float oldSize = like.fontSize == 0 ? 1f : like.fontSize;
        float width = font.getStringWidth(text) * (size == 0 ? 1f : size / oldSize);
        int chars = text.codePointCount(0, text.length()), spaces = 0;
        if (!(font instanceof PDType0Font))
            for (int i = 0; i < text.length(); i++)
                if (text.charAt(i) == ' ')
                    spaces++;
        float extra = chars * like.charSpacing + spaces * like.wordSpacing;
        return width + extra * 1000f / oldSize;
    }

    /** The pieces a string operand becomes: before the insert point, the insert, after it. */
    private static final class Pieces {
        final COSArray pre = new COSArray(), ins = new COSArray(), post = new COSArray();
    }

    /**
     * Splits a string operand into per-code byte runs, drops the selected codes
     * and, when {@code insertAt} is a code index of this string, puts the
     * replacement there surrounded by the alignment adjustments (which belong
     * to the old font's run, so they sit in the pre / post pieces).
     */
    private static Pieces rebuild(COSString s, PDFont font, TreeSet<Integer> codes, int insertAt, byte[] insert,
                                  float before, float after) throws IOException {
        byte[] bytes = s.getBytes();
        ByteArrayOutputStream prefix = new ByteArrayOutputStream(), suffix = new ByteArrayOutputStream();
        ByteArrayInputStream in = new ByteArrayInputStream(bytes);
        int offset = 0, index = 0;
        boolean seenInsert = false;
        while (in.available() > 0) {
            int available = in.available();
            font.readCode(in);
            int len = Math.max(1, available - in.available());
            if (index == insertAt)
                seenInsert = true;
            if (!codes.contains(index))
                (seenInsert ? suffix : prefix).write(bytes, offset, len);
            offset += len;
            index++;
        }
        Pieces p = new Pieces();
        if (insertAt < 0) {
            p.pre.add(new COSString(prefix.toByteArray()));
            return p;
        }
        if (prefix.size() > 0)
            p.pre.add(new COSString(prefix.toByteArray()));
        if (Math.abs(before) > 0.01f)
            p.pre.add(new COSFloat(-before));
        if (insert.length > 0)
            p.ins.add(new COSString(insert));
        if (Math.abs(after) > 0.01f)
            p.post.add(new COSFloat(-after));
        if (suffix.size() > 0)
            p.post.add(new COSString(suffix.toByteArray()));
        return p;
    }

    /** Walks the page stream and records every glyph with the operator / string / code that produced it. */
    private static final class Locator extends PDFStreamEngine {
        final List<Glyph> glyphs = new ArrayList<>();
        private int opIndex = -1;
        private int depth;
        private int stringIndex = -1;
        private int codeIndex;
        private COSName fontName;
        private final Deque<COSName> fontNames = new ArrayDeque<>();

        Locator() {
            addOperator(new Concatenate(this));
            addOperator(new Save(this));
            addOperator(new Restore(this));
            addOperator(new SetMatrix(this));
            addOperator(new SetGraphicsStateParameters(this));
            addOperator(new SetNonStrokingColorSpace(this));
            addOperator(new SetNonStrokingColor(this));
            addOperator(new SetNonStrokingColorN(this));
            addOperator(new SetNonStrokingDeviceGrayColor(this));
            addOperator(new SetNonStrokingDeviceRGBColor(this));
            addOperator(new SetNonStrokingDeviceCMYKColor(this));
            addOperator(new BeginText(this));
            addOperator(new EndText(this));
            addOperator(new MoveText(this));
            addOperator(new MoveTextSetLeading(this));
            addOperator(new NextLine(this));
            addOperator(new SetCharSpacing(this));
            addOperator(new SetFontAndSize(this));
            addOperator(new SetTextHorizontalScaling(this));
            addOperator(new SetTextLeading(this));
            addOperator(new SetTextRenderingMode(this));
            addOperator(new SetTextRise(this));
            addOperator(new SetWordSpacing(this));
            addOperator(new ShowText(this));
            addOperator(new ShowTextAdjusted(this));
            addOperator(new ShowTextLine(this));
            addOperator(new ShowTextLineAndSpace(this));
        }

        @Override
        protected void processOperator(Operator operator, List<COSBase> operands) throws IOException {
            // ' and " re-enter processOperator for the operators they expand to: count the page's operators only
            if (depth == 0) {
                opIndex++;
                stringIndex = -1;
                if ("Tf".equals(operator.getName()))
                    fontName = !operands.isEmpty() && operands.get(0) instanceof COSName ? (COSName) operands.get(0) : null;
            }
            depth++;
            try {
                super.processOperator(operator, operands);
            } finally {
                depth--;
            }
        }

        @Override
        public void saveGraphicsState() {
            super.saveGraphicsState();
            fontNames.push(fontName == null ? COSName.getPDFName("") : fontName);
        }

        @Override
        public void restoreGraphicsState() {
            super.restoreGraphicsState();
            if (!fontNames.isEmpty()) {
                COSName n = fontNames.pop();
                fontName = n.getName().isEmpty() ? null : n;
            }
        }

        @Override
        public void showForm(PDFormXObject form) {
            // text inside form XObjects is not editable here; the token indexes refer to the page stream
        }

        @Override
        protected void showText(byte[] string) throws IOException {
            stringIndex++;
            codeIndex = 0;
            super.showText(string);
        }

        @Override
        protected void showGlyph(Matrix trm, PDFont font, int code, Vector displacement) throws IOException {
            String unicode = font.toUnicode(code);
            Point2D.Float origin = trm.transformPoint(0, 0);
            Point2D.Float adv = trm.transformPoint(displacement.getX(), 0);
            Point2D.Float up = trm.transformPoint(0, 1);
            float width = (float) origin.distance(adv), height = (float) origin.distance(up);
            PDTextState ts = getGraphicsState().getTextState();
            boolean wordSpaced = code == 32 && !(font instanceof PDType0Font);
            glyphs.add(new Glyph(opIndex, stringIndex, codeIndex++, code, unicode == null ? "" : unicode, font, origin.x, origin.y,
                    width, height, font.getWidth(code), ts.getCharacterSpacing(), ts.getWordSpacing(), ts.getFontSize(), wordSpaced,
                    fontName, rgb(getGraphicsState().getNonStrokingColor()), trm.clone(),
                    getGraphicsState().getCurrentTransformationMatrix().clone()));
        }

        private static Color rgb(PDColor c) {
            if (c == null || c.getColorSpace() == null)
                return null;
            try {
                float[] rgb = c.getColorSpace().toRGB(c.getComponents());
                if (rgb == null || rgb.length < 3)
                    return null;
                return new Color(clamp(rgb[0]), clamp(rgb[1]), clamp(rgb[2]));
            } catch (IOException | RuntimeException e) {
                return null; // a pattern or a broken colour space
            }
        }

        private static float clamp(float v) {
            return Math.max(0f, Math.min(1f, v));
        }
    }

    /** @return the glyphs of a page, or an empty list when the stream cannot be read */
    public static List<Glyph> glyphsOrEmpty(PDPage page) {
        try {
            return glyphs(page);
        } catch (IOException e) {
            return Collections.emptyList();
        }
    }
}
