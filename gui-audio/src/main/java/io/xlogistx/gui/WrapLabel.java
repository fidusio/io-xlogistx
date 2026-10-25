package io.xlogistx.gui;

import javax.swing.JLabel;
import javax.swing.plaf.basic.BasicHTML;
import javax.swing.text.View;
import java.awt.Dimension;
import java.awt.Insets;

/**
 * A label whose text wraps at an explicit width. Swing has no height-for-width protocol, so a
 * wrapping {@code JTextArea} or an unconstrained HTML label reports a height for whatever width
 * it was last laid out at, and a MigLayout container ends up too tall or too short. This label
 * wraps at {@link #setWrapWidth} instead: its preferred size is computed by sizing its HTML view
 * to that width, so it is deterministic, and the owning container sets the width it has
 * (typically from its {@code doLayout()}) — a second pass only happens when that width changed.
 */
public class WrapLabel extends JLabel {

    private String plain = "";
    private int wrapWidth = 320;

    public WrapLabel(String text) {
        setVerticalAlignment(TOP);
        setText(text);
    }

    /** The text, without the HTML this label wraps it in. */
    public String getPlainText() {
        return plain;
    }

    @Override
    public void setText(String text) {
        plain = text != null ? text : "";
        super.setText("<html>" + escape(plain).replace("\n", "<br>") + "</html>");
    }

    /** The width the text wraps at, in pixels; a value below 40 is ignored. */
    public void setWrapWidth(int width) {
        if (width >= 40 && width != wrapWidth) {
            wrapWidth = width;
            revalidate();
            repaint();
        }
    }

    public int getWrapWidth() {
        return wrapWidth;
    }

    @Override
    public Dimension getPreferredSize() {
        View view = (View) getClientProperty(BasicHTML.propertyKey);
        if (view == null) return super.getPreferredSize();
        Insets in = getInsets();
        int textWidth = Math.max(1, wrapWidth - in.left - in.right);
        view.setSize(textWidth, 0);
        int h = (int) Math.ceil(view.getPreferredSpan(View.Y_AXIS));
        return new Dimension(wrapWidth, h + in.top + in.bottom);
    }

    @Override
    public Dimension getMinimumSize() {
        return getPreferredSize();
    }

    @Override
    public Dimension getMaximumSize() {
        Dimension d = getPreferredSize();
        return new Dimension(Integer.MAX_VALUE, d.height);
    }

    static String escape(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
}
