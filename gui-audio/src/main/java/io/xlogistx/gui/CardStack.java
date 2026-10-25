package io.xlogistx.gui;

import javax.swing.*;
import java.awt.*;

/**
 * A small {@link CardLayout} wrapper for switching sections <em>within</em> a panel
 *. Add cards by name, then show one.
 * <p>
 * The stack's preferred and minimum size are those of the <b>visible</b> card (2026-10-24), not
 * the maximum over every card as a plain {@code CardLayout} reports. A stack inside a scroll pane
 * used to be as tall as its tallest hidden card, so a small placeholder card sat below the fold
 * with a scrollbar beside it; a stack in a {@code BorderLayout} centre is unaffected, it fills
 * the centre either way.
 */
public class CardStack {
    private final CardLayout cards = new CardLayout() {
        @Override
        public Dimension preferredLayoutSize(Container parent) {
            Dimension d = visibleSize(parent, true);
            return d != null ? d : super.preferredLayoutSize(parent);
        }

        @Override
        public Dimension minimumLayoutSize(Container parent) {
            Dimension d = visibleSize(parent, false);
            return d != null ? d : super.minimumLayoutSize(parent);
        }

        private Dimension visibleSize(Container parent, boolean preferred) {
            synchronized (parent.getTreeLock()) {
                for (Component c : parent.getComponents()) {
                    if (!c.isVisible()) continue;
                    Dimension d = preferred ? c.getPreferredSize() : c.getMinimumSize();
                    Insets in = parent.getInsets();
                    return new Dimension(d.width + in.left + in.right + getHgap() * 2,
                            d.height + in.top + in.bottom + getVgap() * 2);
                }
            }
            return null;
        }
    };
    private final JPanel content = new JPanel(cards);

    /**
     * @return the panel hosting the cards; add this to your layout.
     */
    public JComponent view() {
        return content;
    }

    /**
     * Registers a card under the given name.
     *
     * @param c    the component to show as a card
     * @param name the key used to show it later
     */
    public void add(Component c, String name) {
        content.add(c, name);
    }

    /**
     * Shows the card registered under the given name.
     *
     * @param name the card key
     */
    public void show(String name) {
        cards.show(content, name);
    }
}