package io.xlogistx.gui;

import com.formdev.flatlaf.FlatClientProperties;

import javax.swing.BorderFactory;
import javax.swing.ButtonGroup;
import javax.swing.JPanel;
import javax.swing.JToggleButton;
import java.awt.Font;
import java.awt.GridLayout;
import java.util.ArrayList;
import java.util.List;
import java.util.function.IntConsumer;

/**
 * A row of mutually exclusive options drawn as one segmented bar (T0 … T5, All / Today / 7 days).
 * {@link #select} sets the choice without firing; clicks fire {@link #onChange} with the index.
 * {@link #clearSelection} is a valid state: "none of these", for a value the options do not name.
 */
public class SegmentedControl extends JPanel {

    private final ButtonGroup group = new ButtonGroup();
    private final List<JToggleButton> buttons = new ArrayList<>();
    private final List<IntConsumer> listeners = new ArrayList<>();
    private int selected = -1;

    public SegmentedControl(String... labels) {
        super(new GridLayout(1, 0, 0, 0));
        setOpaque(false);
        setBorder(BorderFactory.createLineBorder(UITokens.border()));
        for (int i = 0; i < labels.length; i++) {
            final int index = i;
            JToggleButton b = new JToggleButton(labels[i]);
            b.setFocusPainted(false);
            b.setFont(UITokens.font(Font.BOLD, -0.5f));
            b.setMargin(new java.awt.Insets(5, 12, 5, 12));
            b.putClientProperty(FlatClientProperties.BUTTON_TYPE, FlatClientProperties.BUTTON_TYPE_TOOLBAR_BUTTON);
            b.putClientProperty(FlatClientProperties.STYLE,
                    "arc: 0; toolbar.selectedBackground: " + hex(UITokens.accent())
                            + "; selectedForeground: #FFFFFF; toolbar.hoverBackground: " + hex(UITokens.accentSoft()));
            b.addActionListener(e -> {
                selected = index;
                for (IntConsumer l : listeners) l.accept(index);
            });
            group.add(b);
            buttons.add(b);
            add(b);
        }
    }

    /** Selects an option without firing; an index out of range clears the selection. */
    public void select(int index) {
        if (index < 0 || index >= buttons.size()) {
            clearSelection();
            return;
        }
        selected = index;
        buttons.get(index).setSelected(true);
    }

    public void clearSelection() {
        selected = -1;
        group.clearSelection();
    }

    /** The selected index, or -1. */
    public int getSelectedIndex() {
        return selected;
    }

    public void onChange(IntConsumer listener) {
        listeners.add(listener);
    }

    @Override
    public void setEnabled(boolean enabled) {
        super.setEnabled(enabled);
        for (JToggleButton b : buttons) b.setEnabled(enabled);
    }

    private static String hex(java.awt.Color c) {
        return String.format("#%02X%02X%02X", c.getRed(), c.getGreen(), c.getBlue());
    }
}
