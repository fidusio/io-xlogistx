package io.xlogistx.editor.pdf;

import org.zoxweb.shared.util.SUS;

import java.awt.Color;
import java.awt.Font;
import java.util.Objects;

/**
 * Immutable look of an annotation a tool creates: stroke colour (the
 * annotation's {@code C}: highlight colour, line/shape stroke, note icon
 * colour), optional fill (interior colour of shapes, background of text
 * boxes), opacity, stroke width, font family / style / underline /
 * strikethrough / text highlight / size / alignment for text boxes and the
 * author written to the annotation's title.
 */
public final class AnnotationStyle {

    /** Text markup: yellow, fully opaque (the appearance uses a multiply blend). */
    public static final AnnotationStyle HIGHLIGHT = new AnnotationStyle(new Color(255, 230, 0), null, 1f, 1f, 12f, null);
    /** Underline / strikeout: red, 1 pt. */
    public static final AnnotationStyle UNDERLINE = new AnnotationStyle(new Color(220, 30, 30), null, 1f, 1f, 12f, null);
    /** Sticky notes: yellow icon. */
    public static final AnnotationStyle NOTE = new AnnotationStyle(new Color(255, 200, 0), null, 1f, 1f, 12f, null);
    /** Ink, shapes, lines: red 2 pt, no fill. */
    public static final AnnotationStyle DRAWING = new AnnotationStyle(new Color(220, 30, 30), null, 1f, 2f, 12f, null);
    /** Text boxes: black 12 pt {@link EditorFonts#DEFAULT_FAMILY}, no background, no border. */
    public static final AnnotationStyle TEXT = new AnnotationStyle(Color.BLACK, null, 1f, 0f, 12f, null);
    /** Image stamps: only the opacity applies. */
    public static final AnnotationStyle IMAGE = new AnnotationStyle(Color.BLACK, null, 1f, 0f, 12f, null);
    /** The text highlight colour offered first: marker yellow. */
    public static final Color MARKER_YELLOW = new Color(255, 240, 0);

    private final Color strokeColor;
    private final Color fillColor;
    private final float opacity;
    private final float strokeWidth;
    private final float fontSize;
    private final String fontFamily;
    private final int fontStyle;
    private final boolean underline;
    private final boolean strikethrough;
    private final Color highlightColor;
    private final TextEditor.Alignment alignment;
    private final String author;

    /**
     * A style in the default font ({@link EditorFonts#DEFAULT_FAMILY}, plain).
     *
     * @param strokeColor the stroke / main colour, never null
     * @param fillColor   the interior / background colour, null for none
     * @param opacity     0 (invisible) to 1 (opaque), clamped
     * @param strokeWidth border width in points, 0 for none, clamped at 0
     * @param fontSize    text size in points for text boxes, at least 1
     * @param author      written as the annotation title, null for none
     */
    public AnnotationStyle(Color strokeColor, Color fillColor, float opacity, float strokeWidth, float fontSize, String author) {
        this(strokeColor, fillColor, opacity, strokeWidth, fontSize, null, Font.PLAIN, false, false, null, author);
    }

    /** A style without underline, strikethrough or highlight; see the full constructor. */
    public AnnotationStyle(Color strokeColor, Color fillColor, float opacity, float strokeWidth, float fontSize,
                           String fontFamily, int fontStyle, String author) {
        this(strokeColor, fillColor, opacity, strokeWidth, fontSize, fontFamily, fontStyle, false, false, null, author);
    }

    /** A style without strikethrough or highlight; see the full constructor. */
    public AnnotationStyle(Color strokeColor, Color fillColor, float opacity, float strokeWidth, float fontSize,
                           String fontFamily, int fontStyle, boolean underline, String author) {
        this(strokeColor, fillColor, opacity, strokeWidth, fontSize, fontFamily, fontStyle, underline, false, null, author);
    }

    /** A style without highlight; see the full constructor. */
    public AnnotationStyle(Color strokeColor, Color fillColor, float opacity, float strokeWidth, float fontSize,
                           String fontFamily, int fontStyle, boolean underline, boolean strikethrough, String author) {
        this(strokeColor, fillColor, opacity, strokeWidth, fontSize, fontFamily, fontStyle, underline, strikethrough, null, author);
    }

    /**
     * @param strokeColor    the stroke / main colour, never null
     * @param fillColor      the interior / background colour, null for none
     * @param opacity        0 (invisible) to 1 (opaque), clamped
     * @param strokeWidth    border width in points, 0 for none, clamped at 0
     * @param fontSize       text size in points for text boxes, at least 1
     * @param fontFamily     font family for text boxes (see {@link EditorFonts#families()}), null = the default
     * @param fontStyle      {@link Font} style bits (PLAIN, BOLD, ITALIC), others masked off
     * @param underline      whether text box lines are underlined
     * @param strikethrough  whether text box lines are struck through
     * @param highlightColor colour painted behind the text itself (not the box), null for none
     * @param author         written as the annotation title, null for none
     */
    public AnnotationStyle(Color strokeColor, Color fillColor, float opacity, float strokeWidth, float fontSize,
                           String fontFamily, int fontStyle, boolean underline, boolean strikethrough, Color highlightColor, String author) {
        this(strokeColor, fillColor, opacity, strokeWidth, fontSize, fontFamily, fontStyle, underline, strikethrough, highlightColor,
                TextEditor.Alignment.LEFT, author);
    }

    /**
     * The full constructor; see the shorter ones for the defaults.
     *
     * @param alignment how text box lines sit in the box (null = left)
     */
    public AnnotationStyle(Color strokeColor, Color fillColor, float opacity, float strokeWidth, float fontSize,
                           String fontFamily, int fontStyle, boolean underline, boolean strikethrough, Color highlightColor,
                           TextEditor.Alignment alignment, String author) {
        SUS.checkIfNull("stroke color null", strokeColor);
        this.strokeColor = strokeColor;
        this.fillColor = fillColor;
        this.opacity = Math.max(0f, Math.min(1f, opacity));
        this.strokeWidth = Math.max(0f, strokeWidth);
        this.fontSize = Math.max(1f, fontSize);
        this.fontFamily = EditorFonts.familyOrDefault(fontFamily);
        this.fontStyle = fontStyle & (Font.BOLD | Font.ITALIC);
        this.underline = underline;
        this.strikethrough = strikethrough;
        this.highlightColor = highlightColor;
        this.alignment = alignment == null ? TextEditor.Alignment.LEFT : alignment;
        this.author = author;
    }

    public Color getStrokeColor() {
        return strokeColor;
    }

    /** @return the fill / background colour, null for none */
    public Color getFillColor() {
        return fillColor;
    }

    public float getOpacity() {
        return opacity;
    }

    public float getStrokeWidth() {
        return strokeWidth;
    }

    public float getFontSize() {
        return fontSize;
    }

    /** @return the font family, never null ({@link EditorFonts#DEFAULT_FAMILY} by default) */
    public String getFontFamily() {
        return fontFamily;
    }

    /** @return {@link Font} style bits: PLAIN, BOLD, ITALIC or BOLD | ITALIC */
    public int getFontStyle() {
        return fontStyle;
    }

    public boolean isBold() {
        return (fontStyle & Font.BOLD) != 0;
    }

    public boolean isItalic() {
        return (fontStyle & Font.ITALIC) != 0;
    }

    public boolean isUnderline() {
        return underline;
    }

    public boolean isStrikethrough() {
        return strikethrough;
    }

    /** @return the colour painted behind the text, null for none */
    public Color getHighlightColor() {
        return highlightColor;
    }

    /** @return how text box lines sit in the box, never null */
    public TextEditor.Alignment getAlignment() {
        return alignment;
    }

    /** @return the author, null for none */
    public String getAuthor() {
        return author;
    }

    public AnnotationStyle withStrokeColor(Color c) {
        return new AnnotationStyle(c, fillColor, opacity, strokeWidth, fontSize, fontFamily, fontStyle, underline, strikethrough, highlightColor, alignment, author);
    }

    public AnnotationStyle withFillColor(Color c) {
        return new AnnotationStyle(strokeColor, c, opacity, strokeWidth, fontSize, fontFamily, fontStyle, underline, strikethrough, highlightColor, alignment, author);
    }

    public AnnotationStyle withOpacity(float o) {
        return new AnnotationStyle(strokeColor, fillColor, o, strokeWidth, fontSize, fontFamily, fontStyle, underline, strikethrough, highlightColor, alignment, author);
    }

    public AnnotationStyle withStrokeWidth(float w) {
        return new AnnotationStyle(strokeColor, fillColor, opacity, w, fontSize, fontFamily, fontStyle, underline, strikethrough, highlightColor, alignment, author);
    }

    public AnnotationStyle withFontSize(float s) {
        return new AnnotationStyle(strokeColor, fillColor, opacity, strokeWidth, s, fontFamily, fontStyle, underline, strikethrough, highlightColor, alignment, author);
    }

    /** @param family null = the default family */
    public AnnotationStyle withFontFamily(String family) {
        return new AnnotationStyle(strokeColor, fillColor, opacity, strokeWidth, fontSize, family, fontStyle, underline, strikethrough, highlightColor, alignment, author);
    }

    /** @param style {@link Font} style bits */
    public AnnotationStyle withFontStyle(int style) {
        return new AnnotationStyle(strokeColor, fillColor, opacity, strokeWidth, fontSize, fontFamily, style, underline, strikethrough, highlightColor, alignment, author);
    }

    public AnnotationStyle withUnderline(boolean u) {
        return new AnnotationStyle(strokeColor, fillColor, opacity, strokeWidth, fontSize, fontFamily, fontStyle, u, strikethrough, highlightColor, alignment, author);
    }

    public AnnotationStyle withStrikethrough(boolean s) {
        return new AnnotationStyle(strokeColor, fillColor, opacity, strokeWidth, fontSize, fontFamily, fontStyle, underline, s, highlightColor, author);
    }

    /** @param c the colour behind the text, null for none */
    public AnnotationStyle withHighlightColor(Color c) {
        return new AnnotationStyle(strokeColor, fillColor, opacity, strokeWidth, fontSize, fontFamily, fontStyle, underline, strikethrough, c, alignment, author);
    }

    /** @param a null = left */
    public AnnotationStyle withAlignment(TextEditor.Alignment a) {
        return new AnnotationStyle(strokeColor, fillColor, opacity, strokeWidth, fontSize, fontFamily, fontStyle, underline, strikethrough, highlightColor, a, author);
    }

    public AnnotationStyle withAuthor(String a) {
        return new AnnotationStyle(strokeColor, fillColor, opacity, strokeWidth, fontSize, fontFamily, fontStyle, underline, strikethrough, highlightColor, alignment, a);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (!(o instanceof AnnotationStyle))
            return false;
        AnnotationStyle s = (AnnotationStyle) o;
        return strokeColor.equals(s.strokeColor) && Objects.equals(fillColor, s.fillColor) && opacity == s.opacity
                && strokeWidth == s.strokeWidth && fontSize == s.fontSize && fontFamily.equalsIgnoreCase(s.fontFamily)
                && fontStyle == s.fontStyle && underline == s.underline && strikethrough == s.strikethrough
                && Objects.equals(highlightColor, s.highlightColor) && alignment == s.alignment && Objects.equals(author, s.author);
    }

    @Override
    public int hashCode() {
        return Objects.hash(strokeColor, fillColor, opacity, strokeWidth, fontSize, fontFamily.toLowerCase(java.util.Locale.ROOT),
                fontStyle, underline, strikethrough, highlightColor, alignment, author);
    }

    @Override
    public String toString() {
        return "AnnotationStyle{stroke=" + strokeColor + ", fill=" + fillColor + ", opacity=" + opacity
                + ", width=" + strokeWidth + ", font=" + EditorFonts.describe(fontFamily, fontStyle) + (underline ? " underlined" : "")
                + (strikethrough ? " struck" : "") + (highlightColor != null ? " highlighted " + highlightColor : "")
                + (alignment != TextEditor.Alignment.LEFT ? " " + alignment.name().toLowerCase(java.util.Locale.ROOT) : "")
                + " " + fontSize + "pt, author=" + author + "}";
    }
}
