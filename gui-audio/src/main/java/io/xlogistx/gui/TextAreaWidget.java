package io.xlogistx.gui;

import javax.swing.*;
import javax.swing.text.Document;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.List;

/**
 * A text field that is several lines high: for a value that is one logical line but outgrows a
 * {@link JTextField} — a list of addresses, a long command. The text wraps at the field's width,
 * a fixed number of rows shows and the rest scrolls, so the field keeps its height however much
 * it holds.
 * <p>
 * It behaves like a field, not like an editor: <b>Enter</b> fires the action listeners
 * (Shift+Enter inserts a line break), <b>Tab</b> moves the focus, and a placeholder shows while
 * it is empty. {@code GUIUtil.applyProp} maps a descriptor's display name onto the placeholder,
 * as it does for a text field. The component is the scroll pane, so it takes the look and feel's
 * field border and focus colour; {@link #getTextArea()} hands out the area for anything else.
 */
public class TextAreaWidget extends JScrollPane {

    private final Area area = new Area();
    private final List<ActionListener> listeners = new ArrayList<>();

    /** A field three rows high. */
    public TextAreaWidget() {
        this(3);
    }

    /** @param rows the lines that show before the field scrolls, at least 1 */
    public TextAreaWidget(int rows) {
        super(VERTICAL_SCROLLBAR_AS_NEEDED, HORIZONTAL_SCROLLBAR_NEVER);
        area.setRows(Math.max(1, rows));
        area.setColumns(20); // a stable preferred width; the layout stretches it
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        // a field: Tab leaves it, Enter submits
        area.setFocusTraversalKeys(KeyboardFocusManager.FORWARD_TRAVERSAL_KEYS, null);
        area.setFocusTraversalKeys(KeyboardFocusManager.BACKWARD_TRAVERSAL_KEYS, null);
        area.getInputMap().put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0), "textAreaWidget.submit");
        area.getInputMap().put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, InputEvent.SHIFT_DOWN_MASK), "insert-break");
        area.getActionMap().put("textAreaWidget.submit", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                fireAction();
            }
        });
        setViewportView(area);
    }

    /** The text shown, muted, while the field is empty; null or empty for none. */
    public TextAreaWidget placeholder(String text) {
        area.placeholder = text;
        area.repaint();
        return this;
    }

    public String getPlaceholder() {
        return area.placeholder;
    }

    public String getText() {
        return area.getText();
    }

    public void setText(String text) {
        area.setText(text != null ? text : "");
        area.setCaretPosition(0);
    }

    public Document getDocument() {
        return area.getDocument();
    }

    /** The area inside the scroll pane, for what this class does not forward. */
    public JTextArea getTextArea() {
        return area;
    }

    public void setEditable(boolean editable) {
        area.setEditable(editable);
    }

    /** Told when Enter is pressed in the field. */
    public void addActionListener(ActionListener l) {
        if (l != null) listeners.add(l);
    }

    public void removeActionListener(ActionListener l) {
        listeners.remove(l);
    }

    private void fireAction() {
        ActionEvent e = new ActionEvent(this, ActionEvent.ACTION_PERFORMED, area.getText());
        for (ActionListener l : new ArrayList<>(listeners)) l.actionPerformed(e);
    }

    /**
     * Never lower than its rows: a scroll pane's own minimum is a few pixels, so a layout short
     * of room squeezed the field to a line (seen in the Scan form's first render, 2026-11-10).
     */
    @Override
    public Dimension getMinimumSize() {
        Dimension min = super.getMinimumSize();
        if (!isMinimumSizeSet()) min.height = getPreferredSize().height;
        return min;
    }

    // the font, the tooltip and the focus belong to the text, not to the pane around it

    @Override
    public void setFont(Font font) {
        super.setFont(font);
        if (area != null) area.setFont(font);
    }

    @Override
    public void setToolTipText(String text) {
        super.setToolTipText(text);
        area.setToolTipText(text);
    }

    @Override
    public boolean requestFocusInWindow() {
        return area.requestFocusInWindow();
    }

    @Override
    public void setEnabled(boolean enabled) {
        super.setEnabled(enabled);
        area.setEnabled(enabled);
    }

    /** The area, painting its placeholder while empty. */
    private static final class Area extends JTextArea {
        private String placeholder;

        /** A field among fields: the text fields' background, which a theme may set apart from a text area's. */
        @Override
        public void updateUI() {
            super.updateUI();
            Color field = UIManager.getColor("TextField.background");
            if (field != null) setBackground(field);
        }

        @Override
        protected void paintComponent(Graphics g) {
            super.paintComponent(g);
            if (placeholder == null || placeholder.isEmpty() || getDocument().getLength() > 0) return;
            Graphics2D g2 = (Graphics2D) g.create();
            try {
                Object aa = getToolkit().getDesktopProperty("awt.font.desktophints");
                if (aa instanceof java.util.Map) g2.addRenderingHints((java.util.Map<?, ?>) aa);
                else g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
                Color muted = UIManager.getColor("TextField.placeholderForeground");
                g2.setColor(muted != null ? muted : getDisabledTextColor());
                g2.setFont(getFont());
                Insets in = getInsets();
                FontMetrics fm = g2.getFontMetrics();
                g2.drawString(placeholder, in.left, in.top + fm.getAscent());
            } finally {
                g2.dispose();
            }
        }
    }
}
