package io.xlogistx.gui;

import org.zoxweb.shared.util.GetDisplayName;
import org.zoxweb.shared.util.GetName;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import java.awt.Color;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.Consumer;

/**
 * A wrapping row of removable chips (a selection of probes, skills, attachments) with an
 * optional trailing "add" chip and an empty-state text. The panel shows what it is given
 * ({@link #setChips}); removing fires {@link #onRemove} with the chip's key and the owner decides
 * what to do — the panel never edits its own list.
 */
public class ChipPanel extends JPanel {

    /**
     * One chip: the key it is removed by (its name), the label shown (its display name), an
     * optional small badge after it. Names itself, so a {@link ComponentRef} over it needs no override.
     */
    public static final class Chip implements GetName, GetDisplayName {
        public final String key;
        public final String label;
        public final String badge;

        public Chip(String key, String label) {
            this(key, label, null);
        }

        public Chip(String key, String label, String badge) {
            this.key = key;
            this.label = label;
            this.badge = badge;
        }

        @Override
        public String getName() {
            return key;
        }

        @Override
        public String getDisplayName() {
            return label;
        }
    }

    private final List<Chip> chips = new ArrayList<>();
    /** One ref per chip shown (2026-10-27): the pill is the component, the chip the source. */
    private final List<ComponentRef<Chip>> chipRefs = new ArrayList<>();
    private final List<Consumer<String>> removeListeners = new ArrayList<>();
    private JComponent addChip;
    private String emptyText;

    public ChipPanel() {
        super(new WrapLayout(FlowLayout.LEFT, 6, 6));
        setOpaque(false);
    }

    /** Replaces the chips shown. */
    public void setChips(List<Chip> list) {
        chips.clear();
        if (list != null) chips.addAll(list);
        rebuild();
    }

    public List<Chip> getChips() {
        return Collections.unmodifiableList(chips);
    }

    /** The chips shown, as refs: each one's component is its pill, its source the chip. */
    public List<ComponentRef<Chip>> chipRefs() {
        return Collections.unmodifiableList(chipRefs);
    }

    /** Called with the chip's key when its × is pressed. */
    public void onRemove(Consumer<String> listener) {
        removeListeners.add(listener);
    }

    /** A trailing chip-shaped button ("+ Add probe"). */
    public JButton addAction(String label, Runnable action) {
        JButton b = new JButton(label, IconUtil.svgIcon("io/xlogistx/gui/icons/plus.svg", 12, UITokens.text()));
        b.setFont(UITokens.font(Font.BOLD, -0.5f));
        b.setIconTextGap(6);
        b.setFocusPainted(false);
        b.putClientProperty("JButton.buttonType", "roundRect");
        b.setMargin(new java.awt.Insets(3, 10, 3, 10));
        b.addActionListener(e -> action.run());
        addChip = b;
        rebuild();
        return b;
    }

    /** Muted text shown when there are no chips. */
    public void setEmptyText(String text) {
        emptyText = text;
        rebuild();
    }

    private void rebuild() {
        removeAll();
        chipRefs.clear();
        for (Chip c : chips) {
            ChipView view = new ChipView(c);
            chipRefs.add(new ComponentRef<Chip>(view, c));
            add(view);
        }
        if (chips.isEmpty() && emptyText != null && !emptyText.isEmpty()) {
            JLabel empty = new JLabel(emptyText);
            empty.setForeground(UITokens.muted());
            empty.setFont(UITokens.font(Font.PLAIN, -0.5f));
            add(empty);
        }
        if (addChip != null) add(addChip);
        revalidate();
        repaint();
    }

    /** One pill: label, optional badge, a × that removes it. */
    private final class ChipView extends JPanel {
        ChipView(final Chip chip) {
            super(new FlowLayout(FlowLayout.LEFT, 5, 0));
            setOpaque(false);
            setBorder(BorderFactory.createEmptyBorder(3, 10, 3, 6));
            JLabel label = new JLabel(chip.label);
            label.setFont(UITokens.font(Font.BOLD, -0.5f));
            label.setForeground(UITokens.accentText());
            add(label);
            if (chip.badge != null && !chip.badge.isEmpty()) {
                BadgeLabel badge = new BadgeLabel(chip.badge, BadgeLabel.Tone.NEUTRAL);
                badge.setFont(UITokens.font(Font.PLAIN, -3f));
                badge.setBorder(BorderFactory.createEmptyBorder(0, 6, 0, 6));
                add(badge);
            }
            JButton x = new JButton(IconUtil.svgIcon("io/xlogistx/gui/icons/cancel.svg", 11, UITokens.accentText()));
            x.setToolTipText("Remove " + chip.label);
            x.setBorderPainted(false);
            x.setContentAreaFilled(false);
            x.setFocusPainted(false);
            x.setMargin(new java.awt.Insets(0, 0, 0, 0));
            x.setPreferredSize(new Dimension(18, 18));
            x.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
            x.addActionListener(e -> {
                for (Consumer<String> l : removeListeners) l.accept(chip.key);
            });
            add(x);
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            try {
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                int h = getHeight();
                g2.setColor(UITokens.accentSoft());
                g2.fillRoundRect(0, 0, getWidth(), h, h, h);
                g2.setColor(mix(UITokens.accentSoft(), UITokens.accent(), 0.25f));
                g2.drawRoundRect(0, 0, getWidth() - 1, h - 1, h, h);
            } finally {
                g2.dispose();
            }
            super.paintComponent(g);
        }
    }

    static Color mix(Color a, Color b, float t) {
        return new Color(
                Math.round(a.getRed() + (b.getRed() - a.getRed()) * t),
                Math.round(a.getGreen() + (b.getGreen() - a.getGreen()) * t),
                Math.round(a.getBlue() + (b.getBlue() - a.getBlue()) * t));
    }
}
