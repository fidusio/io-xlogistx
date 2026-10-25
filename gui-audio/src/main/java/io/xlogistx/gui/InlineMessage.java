package io.xlogistx.gui;

import javax.swing.JLabel;
import java.awt.Font;

/**
 * The one-line message under a form: a muted hint ({@link #info}), a confirmation
 * ({@link #ok}) or a validation error ({@link #error}). It always occupies its line (a single
 * space when cleared) so the form does not jump when a message appears.
 */
public class InlineMessage extends JLabel {

    public InlineMessage() {
        super(" ");
        setFont(UITokens.font(Font.PLAIN, -1f));
        setForeground(UITokens.muted());
    }

    /** A neutral hint in the muted colour. */
    public void info(String text) {
        setForeground(UITokens.muted());
        setText(nonEmpty(text));
    }

    /** A confirmation in the success colour. */
    public void ok(String text) {
        setForeground(UITokens.ok());
        setText(nonEmpty(text));
    }

    /** A validation or failure message in the danger colour. */
    public void error(String text) {
        setForeground(UITokens.danger());
        setText(nonEmpty(text));
    }

    /** Blanks the message while keeping the line. */
    public void clear() {
        setForeground(UITokens.muted());
        setText(" ");
    }

    /** True when a message is showing. */
    public boolean hasMessage() {
        String t = getText();
        return t != null && !t.trim().isEmpty();
    }

    private static String nonEmpty(String text) {
        return text == null || text.isEmpty() ? " " : text;
    }
}
