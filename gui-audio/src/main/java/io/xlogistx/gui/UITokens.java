package io.xlogistx.gui;

import com.formdev.flatlaf.FlatClientProperties;

import javax.swing.AbstractButton;
import javax.swing.UIManager;
import java.awt.Color;
import java.awt.Cursor;
import java.awt.Font;

/**
 * The semantic colours and type sizes the io.xlogistx screens are drawn with, as one place.
 * <p>
 * Every accessor asks the look and feel first ({@link UIManager} key) and falls back to the
 * design's own value, so a FlatLaf theme or a {@code FlatLaf.properties} file drives the whole
 * set: an application that sets {@code Component.accentColor} recolours every accent here. The
 * soft tints ({@code *Soft}) are the backgrounds of pills and status rows; the strong colours
 * are the text and glyphs on them, chosen to read at 4.5:1 or better on their tint.
 * <p>
 * Keys the look and feel does not define can be supplied by an application through
 * {@code UIManager.put("xlogistx.<name>", color)}; the names are the accessor names.
 */
public final class UITokens {

    private UITokens() {
    }

    /** The accent (primary buttons, selected navigation, focus). */
    public static Color accent() {
        return color("xlogistx.accent", "Component.accentColor", 0x5856D6);
    }

    /** The accent's soft tint: selected rows, accent pills. */
    public static Color accentSoft() {
        return color("xlogistx.accentSoft", null, 0xEEEEFB);
    }

    /** Accent-coloured text that reads on {@link #accentSoft()}. */
    public static Color accentText() {
        return color("xlogistx.accentText", null, 0x3E3CB4);
    }

    /** Body text. */
    public static Color text() {
        return color("xlogistx.text", "Label.foreground", 0x17171C);
    }

    /** Secondary text: hints, sublabels, timestamps. */
    public static Color muted() {
        return color("xlogistx.muted", "Label.disabledForeground", 0x5C5E66);
    }

    /** Dividers and component outlines. */
    public static Color border() {
        return color("xlogistx.border", "Component.borderColor", 0xE2E2E8);
    }

    /** Card and panel surface. */
    public static Color surface() {
        return color("xlogistx.surface", "Panel.background", 0xFFFFFF);
    }

    /** A slightly recessed surface: sidebars, table headers, code blocks. */
    public static Color surfaceAlt() {
        return color("xlogistx.surfaceAlt", null, 0xFAFAFC);
    }

    /** The ground pages sit on, behind their cards. */
    public static Color ground() {
        return color("xlogistx.ground", null, 0xF4F4F7);
    }

    /** Success text and glyphs. */
    public static Color ok() {
        return color("xlogistx.ok", null, 0x1B7A48);
    }

    /** Success tint. */
    public static Color okSoft() {
        return color("xlogistx.okSoft", null, 0xE6F4EC);
    }

    /** Warning text and glyphs. */
    public static Color warn() {
        return color("xlogistx.warn", null, 0x8A5200);
    }

    /** Warning tint. */
    public static Color warnSoft() {
        return color("xlogistx.warnSoft", null, 0xFFF4E0);
    }

    /** Error and destructive text and glyphs. */
    public static Color danger() {
        return color("xlogistx.danger", "Label.errorForeground", 0xB42318);
    }

    /** Error tint. */
    public static Color dangerSoft() {
        return color("xlogistx.dangerSoft", null, 0xFDECEA);
    }

    /** Neutral badge text. */
    public static Color neutral() {
        return color("xlogistx.neutral", null, 0x4B4D55);
    }

    /** Neutral badge tint. */
    public static Color neutralSoft() {
        return color("xlogistx.neutralSoft", null, 0xEFEFF3);
    }

    /**
     * Resolves a colour: the application override first, then the look-and-feel key, then the
     * fallback.
     *
     * @param appKey      the {@code xlogistx.*} override key (never null)
     * @param lafKey      the look-and-feel key, or null when the look and feel has no equivalent
     * @param fallbackRGB the design value as {@code 0xRRGGBB}
     * @return the colour, never null
     */
    public static Color color(String appKey, String lafKey, int fallbackRGB) {
        Color c = UIManager.getColor(appKey);
        if (c == null && lafKey != null) c = UIManager.getColor(lafKey);
        return c != null ? c : new Color(fallbackRGB);
    }

    /**
     * The base control font the look and feel is using (the label font), or a plain 13 pt
     * sans-serif when none is installed yet.
     */
    public static Font baseFont() {
        Font f = UIManager.getFont("Label.font");
        return f != null ? f : new Font(Font.SANS_SERIF, Font.PLAIN, 13);
    }

    /**
     * The base font with a style and a size offset.
     *
     * @param style a {@link Font} style constant
     * @param delta added to the base size (negative shrinks)
     */
    public static Font font(int style, float delta) {
        Font base = baseFont();
        return base.deriveFont(style, base.getSize2D() + delta);
    }

    /**
     * A monospaced font at the base size plus {@code delta}, for identifiers, paths and commands.
     * The family is {@code UIManager.getString("xlogistx.monoFamily")} when an application set one
     * (a bundled JetBrains Mono, say), else the logical {@link Font#MONOSPACED}.
     */
    public static Font mono(float delta) {
        Font base = baseFont();
        String family = UIManager.getString("xlogistx.monoFamily");
        return new Font(family != null && !family.isEmpty() ? family : Font.MONOSPACED, Font.PLAIN,
                Math.round(base.getSize2D() + delta));
    }

    /**
     * Styles a button as the one accent-filled, confirming action of a view (FlatLaf style
     * properties; a no-op look under another look and feel).
     *
     * @return the same button, for chaining
     */
    public static <B extends AbstractButton> B primary(B button) {
        button.putClientProperty(FlatClientProperties.STYLE,
                "background: $Component.accentColor; foreground: #FFFFFF; borderColor: $Component.accentColor;"
                        + " focusedBorderColor: $Component.accentColor; hoverBorderColor: $Component.accentColor;"
                        + " hoverBackground: darken($Component.accentColor,8%); pressedBackground: darken($Component.accentColor,14%);"
                        + " disabledBackground: lighten($Component.accentColor,25%); disabledText: #FFFFFF");
        return button;
    }

    /**
     * Styles a button as an inline link: no border or fill, accent text, a hand cursor. For
     * secondary actions beside a form ("Create another account", "Change").
     *
     * @return the same button, for chaining
     */
    public static <B extends AbstractButton> B link(B button) {
        button.putClientProperty(FlatClientProperties.BUTTON_TYPE, FlatClientProperties.BUTTON_TYPE_TOOLBAR_BUTTON);
        button.setForeground(accentText());
        button.setFont(font(Font.BOLD, -0.5f));
        button.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        button.setFocusPainted(false);
        return button;
    }
}
