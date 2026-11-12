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
 * ground, the page's actions on the title's line right after it (on the left since 2026-11-12;
 * they were at the head's right end), the description on the line under them, and one or more
 * white cards below. An action never gets narrower than its preferred width, so a narrow window
 * cuts the description, never a button's text.
 * <pre>
 * PagePanel page = new PagePanel("Backup", "Export this store, or restore one.");
 * page.action(exportButton);
 * page.card(backupForm);
 * </pre>
 * Cards stretch to the page's width; the last card added with {@link #card} takes the remaining
 * height. Everything inside a card is the caller's.
 */
public class PagePanel extends JPanel {

    private final JPanel head = new JPanel(new MigLayout("insets 0, wrap 1, gapy 2"));
    private final JPanel titleLine = new JPanel(new MigLayout("insets 0, gapx 12"));
    private boolean hasAction;

    public PagePanel(String title, String description) {
        super(new MigLayout("insets 20 24 24 24, wrap 1, gapy 14, fill, hidemode 3", "[grow,fill]", "[]"));
        setBackground(UITokens.ground());
        head.setOpaque(false);
        titleLine.setOpaque(false);
        JLabel t = new JLabel(title);
        t.setFont(UITokens.font(Font.BOLD, 8f));
        titleLine.add(t);
        head.add(titleLine);
        if (description != null && !description.isEmpty()) {
            JLabel d = new JLabel(description);
            d.setForeground(UITokens.muted());
            head.add(d, "wmin 0");
        }
        add(head, "growx, wmin 0");
    }

    /** A control on the title's line, after the title and the actions added before it. */
    public <C extends JComponent> C action(C component) {
        titleLine.add(component, hasAction ? "wmin pref" : "gapleft 16, wmin pref");
        hasAction = true;
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
