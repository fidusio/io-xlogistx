package io.xlogistx.editor.pdf;

import io.xlogistx.gui.MDToPDF;
import org.apache.fontbox.ttf.TrueTypeFont;
import org.apache.pdfbox.io.IOUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.font.FontMapper;
import org.apache.pdfbox.pdmodel.font.FontMappers;
import org.apache.pdfbox.pdmodel.font.FontMapping;
import org.apache.pdfbox.pdmodel.font.PDFont;
import org.apache.pdfbox.pdmodel.font.PDFontDescriptor;
import org.apache.pdfbox.pdmodel.font.PDType0Font;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;

import java.awt.Font;
import java.awt.GraphicsEnvironment;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.WeakHashMap;

/**
 * The fonts the editor can write text with, by family name and
 * {@link java.awt.Font} style bits (plain, bold, italic): {@value #DEFAULT_FAMILY}
 * ships with the application (the {@code flatlaf-fonts-roboto} TTFs, four
 * faces) and is always there; every other family is one the Java runtime
 * lists, resolved to its TrueType file through PDFBox's font mapper (the
 * family and style give the face's PostScript name, the mapper finds the file
 * the same way it does for unembedded fonts).
 * <p>
 * Fonts are embedded as subset Type 0 fonts, so any character the face has
 * can be written. PDFBox writes a subset font's program (and its ToUnicode
 * map) only when it subsets the font, which it does once, at save time; until
 * then the page shows and extracts wrong glyphs through a fallback font. So
 * every use gets a fresh font object from {@link #load} (the font data is
 * kept in memory per family and style), writes its text, and then
 * {@linkplain #seal seals} it: the subset is built at once, the font is
 * complete in memory and left alone at save. A font object must not be used
 * for new text after it is sealed.
 */
public final class EditorFonts {

    /** The bundled family, the default for text boxes. */
    public static final String DEFAULT_FAMILY = "Roboto";
    private static final String ROBOTO_DIR = "/com/formdev/flatlaf/fonts/roboto/";
    private static final Set<String> LOGICAL = new HashSet<>(Arrays.asList("Dialog", "DialogInput", "Serif", "SansSerif", "Monospaced"));
    /** Font file bytes per family|style, read once. */
    private static final Map<String, byte[]> DATA = new HashMap<>();
    private static volatile List<String> families;
    /** Fonts already sealed (a second subset() would throw). */
    private static final Map<PDFont, Boolean> SEALED = new WeakHashMap<>();

    private EditorFonts() {
    }

    /**
     * @return the family names on offer: {@value #DEFAULT_FAMILY} first, then
     *         the runtime's font families sorted (the logical Dialog / Serif /
     *         Monospaced names left out); computed once
     */
    public static List<String> families() {
        List<String> f = families;
        if (f == null) {
            List<String> list = new ArrayList<>();
            list.add(DEFAULT_FAMILY);
            String[] names;
            try {
                names = GraphicsEnvironment.getLocalGraphicsEnvironment().getAvailableFontFamilyNames(Locale.ENGLISH);
            } catch (RuntimeException | Error e) {
                names = new String[0]; // no font subsystem: the bundled family only
            }
            List<String> system = new ArrayList<>();
            for (String n : names)
                if (!LOGICAL.contains(n) && !DEFAULT_FAMILY.equalsIgnoreCase(n))
                    system.add(n);
            Collections.sort(system, String.CASE_INSENSITIVE_ORDER);
            list.addAll(system);
            families = f = Collections.unmodifiableList(list);
        }
        return f;
    }

    /** @return the family, or {@value #DEFAULT_FAMILY} when null or blank */
    public static String familyOrDefault(String family) {
        return family == null || family.trim().isEmpty() ? DEFAULT_FAMILY : family.trim();
    }

    /** @return true when the family is the bundled one (case-insensitive) */
    public static boolean isBundled(String family) {
        return DEFAULT_FAMILY.equalsIgnoreCase(familyOrDefault(family));
    }

    /**
     * @param style {@link Font} style bits
     * @return e.g. "Arial Bold Italic", for messages
     */
    public static String describe(String family, int style) {
        StringBuilder sb = new StringBuilder(familyOrDefault(family));
        if ((style & Font.BOLD) != 0)
            sb.append(" Bold");
        if ((style & Font.ITALIC) != 0)
            sb.append(" Italic");
        return sb.toString();
    }

    /**
     * A fresh embedded font for a family and style in a document: write the
     * text with it, then {@link #seal} it.
     *
     * @param doc    the document, never null
     * @param family the family; null or blank = {@value #DEFAULT_FAMILY}
     * @param style  {@link Font} style bits (PLAIN, BOLD, ITALIC, BOLD|ITALIC)
     * @return the font (a Helvetica face when even the bundled font is missing)
     * @throws IOException when the family is not installed as a TrueType font or cannot be embedded
     */
    public static PDFont load(PDDocument doc, String family, int style) throws IOException {
        if (doc == null)
            throw new IOException("no document");
        String fam = familyOrDefault(family);
        int st = style & (Font.BOLD | Font.ITALIC);
        byte[] data = data(fam, st);
        if (data == null)
            return helvetica(st);
        try {
            return PDType0Font.load(doc, new ByteArrayInputStream(data), true);
        } catch (IOException | RuntimeException e) {
            throw new IOException("the font \"" + describe(fam, st) + "\" cannot be embedded: " + e.getMessage());
        }
    }

    /**
     * Completes a font {@link #load} gave once its text is written: the subset
     * with the characters used so far is built now (program + ToUnicode), so
     * the page renders and extracts right at once, and the font is taken off
     * the document's save-time subset list (PDFBox can subset a font only
     * once). A failure leaves the font as PDFBox would have it. Does nothing
     * for other fonts (the Helvetica fallback, a page's own font).
     */
    public static synchronized void seal(PDDocument doc, PDFont font) {
        if (doc == null || !(font instanceof PDType0Font) || !((PDType0Font) font).willBeSubset() || SEALED.containsKey(font))
            return;
        SEALED.put(font, Boolean.TRUE);
        // PDFBox lists a font for its save-time subset only when a content stream's setFont saw it;
        // text encoded by hand (the in-place editor) is never listed, so subset here in every case
        Set<PDFont> pending = fontsToSubset(doc);
        if (pending != null)
            pending.remove(font);
        try {
            ((PDType0Font) font).subset();
        } catch (IOException | RuntimeException e) {
            // left as is: the viewer falls back to a substitute until the next save
        }
    }

    /**
     * PDFBox keeps the fonts it will subset at save in a package-private set;
     * null when it cannot be reached (then nothing is sealed and PDFBox keeps
     * its usual save-time behaviour).
     */
    @SuppressWarnings("unchecked")
    static Set<PDFont> fontsToSubset(PDDocument doc) {
        try {
            java.lang.reflect.Field f = PDDocument.class.getDeclaredField("fontsToSubset");
            f.setAccessible(true);
            return (Set<PDFont>) f.get(doc);
        } catch (ReflectiveOperationException | RuntimeException e) {
            return null;
        }
    }

    /**
     * The {@link Font} style bits a document font shows: bold when its name
     * says so (Bold, Black, Heavy, Semibold) or its descriptor weighs 600+ /
     * forces bold; italic when the name says Italic / Oblique or the
     * descriptor's italic flag is set.
     */
    public static int styleOf(PDFont font) {
        if (font == null)
            return Font.PLAIN;
        String name = font.getName() == null ? "" : font.getName().toLowerCase(Locale.ROOT);
        int style = Font.PLAIN;
        if (name.contains("bold") || name.contains("black") || name.contains("heavy"))
            style |= Font.BOLD;
        if (name.contains("italic") || name.contains("oblique"))
            style |= Font.ITALIC;
        PDFontDescriptor d = font.getFontDescriptor();
        if (d != null) {
            if (d.isForceBold() || d.getFontWeight() >= 600)
                style |= Font.BOLD;
            if (d.isItalic())
                style |= Font.ITALIC;
        }
        return style;
    }

    /**
     * The family of a document font as this registry knows it, so another
     * face of the same family can be loaded: the descriptor's family or the
     * base font name (subset tag, style suffix and the MT / PS / PSMT tails
     * removed) matched against {@link #families()} ignoring case and spaces.
     *
     * @return the family name as listed, null when it is not installed
     */
    public static String familyOf(PDFont font) {
        if (font == null)
            return null;
        List<String> candidates = new ArrayList<>();
        PDFontDescriptor d = font.getFontDescriptor();
        if (d != null && d.getFontFamily() != null && !d.getFontFamily().trim().isEmpty())
            candidates.add(d.getFontFamily().trim());
        String base = font.getName();
        if (base != null) {
            if (base.length() > 7 && base.charAt(6) == '+')
                base = base.substring(7);
            int cut = base.length();
            for (char c : new char[]{'-', ','})
                if (base.indexOf(c) > 0)
                    cut = Math.min(cut, base.indexOf(c));
            base = base.substring(0, cut).trim();
            candidates.add(base);
            for (String tail : new String[]{"PSMT", "MT", "PS"})
                if (base.endsWith(tail) && base.length() > tail.length() + 2)
                    candidates.add(base.substring(0, base.length() - tail.length()));
            // a face name glued to the family: ArialBold
            for (String face : new String[]{"BoldItalic", "BoldOblique", "Bold", "Italic", "Oblique", "Regular"})
                if (base.endsWith(face) && base.length() > face.length() + 2)
                    candidates.add(base.substring(0, base.length() - face.length()));
        }
        for (String c : candidates) {
            String key = c.replace(" ", "").toLowerCase(Locale.ROOT);
            if (key.isEmpty())
                continue;
            for (String f : families())
                if (f.replace(" ", "").toLowerCase(Locale.ROOT).equals(key))
                    return f;
        }
        return null;
    }

    /**
     * Kept for callers from before fonts were sealed per use; nothing is cached
     * per document any more, so this does nothing.
     */
    public static void forget(PDDocument doc) {
        // no per-document state
    }

    /** The font file bytes for a family and style, read once; null when the bundled resource is missing. */
    private static synchronized byte[] data(String family, int style) throws IOException {
        String key = family.toLowerCase(Locale.ROOT) + "|" + style;
        if (DATA.containsKey(key))
            return DATA.get(key);
        byte[] data = isBundled(family) ? bundled(style) : system(family, style);
        DATA.put(key, data);
        return data;
    }

    private static byte[] bundled(int style) throws IOException {
        boolean bold = (style & Font.BOLD) != 0, italic = (style & Font.ITALIC) != 0;
        String resource = ROBOTO_DIR + "Roboto-" + (bold && italic ? "BoldItalic" : bold ? "Bold" : italic ? "Italic" : "Regular") + ".ttf";
        if (MDToPDF.class.getResource(resource) == null)
            return null;
        try (InputStream in = MDToPDF.class.getResourceAsStream(resource)) {
            return IOUtils.toByteArray(in);
        }
    }

    private static PDFont helvetica(int style) {
        boolean bold = (style & Font.BOLD) != 0, italic = (style & Font.ITALIC) != 0;
        Standard14Fonts.FontName name = bold && italic ? Standard14Fonts.FontName.HELVETICA_BOLD_OBLIQUE
                : bold ? Standard14Fonts.FontName.HELVETICA_BOLD
                : italic ? Standard14Fonts.FontName.HELVETICA_OBLIQUE : Standard14Fonts.FontName.HELVETICA;
        return new PDType1Font(name);
    }

    /** A system family through the runtime (PostScript name of the face) and PDFBox's font mapper (its file, copied). */
    private static byte[] system(String family, int style) throws IOException {
        String psName;
        try {
            psName = new Font(family, style, 12).getPSName();
        } catch (RuntimeException | Error e) {
            throw new IOException("the font \"" + describe(family, style) + "\" is not available: " + e.getMessage());
        }
        FontMapper mapper = FontMappers.instance();
        FontMapping<TrueTypeFont> mapping = mapper.getTrueTypeFont(psName, null);
        if (mapping == null || mapping.getFont() == null || mapping.isFallback())
            throw new IOException("the font \"" + describe(family, style) + "\" (" + psName + ") is not installed as a TrueType font");
        // a copy of the file: the mapper's font object is shared and must stay untouched
        try (InputStream in = mapping.getFont().getOriginalData()) {
            return IOUtils.toByteArray(in);
        } catch (IOException | RuntimeException e) {
            throw new IOException("the font \"" + describe(family, style) + "\" cannot be read: " + e.getMessage());
        }
    }
}
