package io.xlogistx.gui;

import net.miginfocom.swing.MigLayout;

import javax.swing.BorderFactory;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import java.awt.BorderLayout;
import java.awt.Font;

/**
 * The frame every application page shares: a title and a one-line description over the recessed
 * ground, an optional action at the right of the title, and one or more white cards below.
 * <pre>
 * PagePanel page = new PagePanel("Backup", "Export this store, or restore one.");
 * page.action(exportButton);
 * page.card(backupForm);
 * </pre>
 * Cards stretch to the page's width; the last card added with {@link #card} takes the remaining
 * height. Everything inside a card is the caller's.
 */
public class PagePanel extends JPanel {

    private final JPanel head = new JPanel(new MigLayout("insets 0, gapx 12", "[grow][]"));
    private final JPanel titles = new JPanel(new MigLayout("insets 0, wrap 1, gapy 2"));

    public PagePanel(String title, String description) {
        super(new MigLayout("insets 20 24 24 24, wrap 1, gapy 14, fill, hidemode 3", "[grow,fill]", "[]"));
        setBackground(UITokens.ground());
        head.setOpaque(false);
        titles.setOpaque(false);
        JLabel t = new JLabel(title);
        t.setFont(UITokens.font(Font.BOLD, 8f));
        titles.add(t);
        if (description != null && !description.isEmpty()) {
            JLabel d = new JLabel(description);
            d.setForeground(UITokens.muted());
            titles.add(d);
        }
        head.add(titles, "wmin 0");
        add(head, "growx");
    }

    /** A control at the right of the title (the page's one primary action). */
    public <C extends JComponent> C action(C component) {
        head.add(component);
        return component;
    }

    /** Wraps {@code content} in a white bordered card that takes the remaining height. */
    public JPanel card(JComponent content) {
        return card(content, "grow, push");
    }

    /** Wraps {@code content} in a card added with explicit MigLayout constraints. */
    public JPanel card(JComponent content, String constraints) {
        JPanel card = new JPanel(new BorderLayout());
        card.setBackground(UITokens.surface());
        card.setBorder(BorderFactory.createLineBorder(UITokens.border()));
        card.add(content, BorderLayout.CENTER);
        add(card, constraints);
        return card;
    }

    /** Adds any component as a row between the header and the cards (a toolbar, a notice). */
    public <C extends JComponent> C row(C component) {
        add(component, "growx");
        return component;
    }
}
