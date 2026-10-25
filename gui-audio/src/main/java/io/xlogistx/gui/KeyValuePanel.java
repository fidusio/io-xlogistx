package io.xlogistx.gui;

import net.miginfocom.swing.MigLayout;

import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import java.awt.Font;

/**
 * A two-column label / value grid for a detail pane (protocol, key exchange, certificate …):
 * muted keys on the left, values on the right, values wrapping at the panel's width. Mono values
 * for identifiers through {@link #putMono}.
 */
public class KeyValuePanel extends JPanel {

    private final java.util.List<WrapLabel> values = new java.util.ArrayList<>();
    private final int keyWidth;

    public KeyValuePanel() {
        this(120);
    }

    /** @param keyWidth the key column's width in pixels */
    public KeyValuePanel(int keyWidth) {
        super(new MigLayout("insets 0, wrap 2, gapx 12, gapy 4, fillx, hidemode 3", "[" + keyWidth + "!][grow,fill]"));
        this.keyWidth = keyWidth;
        setOpaque(false);
    }

    /** Adds a row; a null or empty value is skipped. @return the value label, or null when skipped */
    public WrapLabel put(String key, String value) {
        return put(key, value, false);
    }

    /** Adds a row whose value is set in the monospaced font. */
    public WrapLabel putMono(String key, String value) {
        return put(key, value, true);
    }

    /** Adds a row with an arbitrary component as the value. */
    public void put(String key, JComponent value) {
        add(keyLabel(key), "aligny top");
        add(value, "growx, wmin 0");
    }

    private WrapLabel put(String key, String value, boolean mono) {
        if (value == null || value.isEmpty()) return null;
        WrapLabel v = new WrapLabel(value);
        v.setFont(mono ? UITokens.mono(-1f) : UITokens.font(Font.PLAIN, -0.5f));
        values.add(v);
        add(keyLabel(key), "aligny top");
        add(v, "growx, wmin 0");
        return v;
    }

    /** Removes every row. */
    public void clear() {
        removeAll();
        values.clear();
        revalidate();
        repaint();
    }

    @Override
    public void doLayout() {
        int w = getWidth() - keyWidth - 12;
        if (w >= 40) for (WrapLabel v : values) v.setWrapWidth(w);
        super.doLayout();
    }

    private static JLabel keyLabel(String key) {
        JLabel k = new JLabel(key);
        k.setFont(UITokens.font(Font.PLAIN, -0.5f));
        k.setForeground(UITokens.muted());
        return k;
    }
}
