package io.xlogistx.gui;

import net.miginfocom.swing.MigLayout;

import javax.swing.BorderFactory;
import javax.swing.Icon;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;

/**
 * The strip across the top of an application window: brand on the left, a mono status chip
 * (the open store, an environment), then — right-aligned — the signed-in subject (initial
 * avatar, name, an optional role badge) and action buttons such as Sign out.
 */
public class HeaderBar extends JPanel {

    private final JLabel status = new JLabel();
    private final Avatar avatar = new Avatar();
    private final JLabel subject = new JLabel();
    private final BadgeLabel badge = new BadgeLabel("", BadgeLabel.Tone.NEUTRAL);
    private final JPanel subjectBox = new JPanel(new MigLayout("insets 0, gapx 8", "[]push"));
    private final JPanel actions = new JPanel(new MigLayout("insets 0, gapx 6"));

    public HeaderBar(Icon brandIcon, String brandText) {
        super(new MigLayout("insets 0 20 0 12, gapx 16, fillx, hidemode 3", "[]16[]push[]8[]", "[48!]"));
        setBackground(UITokens.surface());
        setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, UITokens.border()));

        JLabel brand = new JLabel(brandText, brandIcon, JLabel.LEFT);
        brand.setIconTextGap(10);
        brand.setFont(UITokens.font(Font.BOLD, 2f));
        add(brand);

        status.setFont(UITokens.mono(-1.5f));
        status.setForeground(UITokens.muted());
        status.setOpaque(true);
        status.setBackground(UITokens.color("xlogistx.chip", null, 0xF4F4F7));
        status.setBorder(BorderFactory.createEmptyBorder(4, 10, 4, 10));
        status.setIconTextGap(8);
        status.setVisible(false);
        add(status);

        subjectBox.setOpaque(false);
        subject.setFont(UITokens.font(Font.BOLD, 0f));
        subjectBox.add(avatar);
        subjectBox.add(subject);
        subjectBox.add(badge);
        badge.setVisible(false);
        subjectBox.setVisible(false);
        add(subjectBox);

        actions.setOpaque(false);
        add(actions);
    }

    /** The status chip; null or empty text hides it. */
    public void setStatus(Icon icon, String text) {
        setStatus(icon, text, null);
    }

    /** The status chip with a tooltip (what the chip's words mean, a longer path); null or empty text hides it. */
    public void setStatus(Icon icon, String text, String tooltip) {
        status.setIcon(icon);
        status.setText(text != null ? text : "");
        status.setToolTipText(tooltip);
        status.setVisible(text != null && !text.isEmpty());
    }

    /** Shows the signed-in subject; {@code badgeText} (a role) may be null. */
    public void setSubject(String name, String badgeText) {
        subject.setText(name != null ? name : "");
        avatar.setInitial(name);
        badge.setText(badgeText != null ? badgeText : "");
        badge.setVisible(badgeText != null && !badgeText.isEmpty());
        subjectBox.setVisible(name != null && !name.isEmpty());
        revalidate();
        repaint();
    }

    /** Hides the subject (signed out). */
    public void clearSubject() {
        setSubject(null, null);
    }

    /** Adds a right-aligned action (a button). */
    public <C extends JComponent> C addAction(C component) {
        actions.add(component);
        return component;
    }

    /** A round accent-tinted disc with the subject's initial. */
    private static final class Avatar extends JComponent {
        private String initial = "";

        Avatar() {
            Dimension d = new Dimension(26, 26);
            setPreferredSize(d);
            setMinimumSize(d);
            setOpaque(false);
        }

        void setInitial(String name) {
            initial = name != null && !name.isEmpty() ? name.substring(0, 1).toUpperCase() : "";
            repaint();
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            try {
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
                int d = Math.min(getWidth(), getHeight());
                g2.setColor(UITokens.accentSoft());
                g2.fillOval(0, 0, d, d);
                g2.setColor(UITokens.accentText());
                g2.setFont(UITokens.font(Font.BOLD, -1f));
                java.awt.FontMetrics fm = g2.getFontMetrics();
                int tx = (d - fm.stringWidth(initial)) / 2;
                int ty = (d - fm.getHeight()) / 2 + fm.getAscent();
                g2.drawString(initial, tx, ty);
            } finally {
                g2.dispose();
            }
        }
    }

    static Color darker(Color c) {
        return c.darker();
    }
}
