package io.xlogistx.gui;

import javax.swing.BorderFactory;
import javax.swing.Icon;
import javax.swing.JLabel;
import java.awt.Color;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;

/**
 * A pill-shaped status label: short text (optionally with an icon) on a soft tint, coloured by
 * a {@link Tone}. Used for states ("vault unlocked", "ready", "unreachable"), roles
 * ("super-admin"), grades and counts. Colours come from {@link UITokens}, so a theme
 * recolours every badge at once.
 */
public class BadgeLabel extends JLabel {

    /** The meaning a badge carries; each tone is a text colour over a tint that reads at 4.5:1. */
    public enum Tone {
        OK, WARN, DANGER, NEUTRAL, ACCENT;

        Color foreground() {
            switch (this) {
                case OK:
                    return UITokens.ok();
                case WARN:
                    return UITokens.warn();
                case DANGER:
                    return UITokens.danger();
                case ACCENT:
                    return UITokens.accentText();
                default:
                    return UITokens.neutral();
            }
        }

        Color background() {
            switch (this) {
                case OK:
                    return UITokens.okSoft();
                case WARN:
                    return UITokens.warnSoft();
                case DANGER:
                    return UITokens.dangerSoft();
                case ACCENT:
                    return UITokens.accentSoft();
                default:
                    return UITokens.neutralSoft();
            }
        }
    }

    private Tone tone;

    /**
     * @param text the badge text
     * @param tone its meaning
     */
    public BadgeLabel(String text, Tone tone) {
        this(text, null, tone);
    }

    /**
     * @param text the badge text
     * @param icon a small icon before the text, or null
     * @param tone its meaning
     */
    public BadgeLabel(String text, Icon icon, Tone tone) {
        super(text, icon, LEFT);
        setIconTextGap(5);
        setOpaque(false);
        setBorder(BorderFactory.createEmptyBorder(2, 8, 2, 8));
        setFont(UITokens.font(Font.PLAIN, -1.5f));
        setTone(tone);
    }

    /** Recolours the badge. */
    public void setTone(Tone tone) {
        this.tone = tone != null ? tone : Tone.NEUTRAL;
        setForeground(this.tone.foreground());
        repaint();
    }

    public Tone getTone() {
        return tone;
    }

    @Override
    protected void paintComponent(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        try {
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setColor(tone.background());
            int h = getHeight();
            g2.fillRoundRect(0, 0, getWidth(), h, h, h);
        } finally {
            g2.dispose();
        }
        super.paintComponent(g);
    }
}
