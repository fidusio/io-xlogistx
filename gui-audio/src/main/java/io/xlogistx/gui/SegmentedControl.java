package io.xlogistx.gui;

import com.formdev.flatlaf.FlatClientProperties;
import org.zoxweb.shared.util.GetDisplayName;

import javax.swing.BorderFactory;
import javax.swing.ButtonGroup;
import javax.swing.JPanel;
import javax.swing.JToggleButton;
import java.awt.Font;
import java.awt.GridLayout;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.IntConsumer;

/**
 * A row of mutually exclusive options drawn as one segmented bar (T0 … T5, All / Bundled / Mine).
 * {@link #select} sets the choice without firing; clicks fire {@link #onChange} with the index.
 * {@link #clearSelection} is a valid state: "none of these", for a value the options do not name.
 * <p>
 * Every segment is a {@link ComponentRef} over the option it was built from (2026-10-27): the
 * button's text is the ref's display name and its tooltip the ref's description, so an enum that
 * implements zoxweb's {@code GetDisplayName} and {@code GetDescription} labels and explains its
 * own segments ({@code new SegmentedControl(Timing.values())}). {@link #selectedSource()} hands the
 * chosen option back and {@link #select(Object)} selects by it, so neither side maps indexes to
 * constants. A control built from plain strings has string refs with no description.
 */
public class SegmentedControl extends JPanel {

    private final ButtonGroup group = new ButtonGroup();
    private final List<JToggleButton> buttons = new ArrayList<>();
    private final List<ComponentRef<Object>> refs = new ArrayList<>();
    private final List<IntConsumer> listeners = new ArrayList<>();
    private int selected = -1;

    /** One segment per option: its display name as the label, its description as the tooltip. */
    public SegmentedControl(GetDisplayName... options) {
        this((Object[]) options);
    }

    /** One segment per label, with no description. */
    public SegmentedControl(String... labels) {
        this((Object[]) labels);
    }

    private SegmentedControl(Object[] options) {
        super(new GridLayout(1, 0, 0, 0));
        setOpaque(false);
        setBorder(BorderFactory.createLineBorder(UITokens.border()));
        for (int i = 0; i < options.length; i++) {
            final int index = i;
            JToggleButton b = new JToggleButton();
            ComponentRef<Object> ref = new ComponentRef<Object>(b, options[i]); // a string names itself, with no description
            b.setText(ref.getDisplayName());
            b.setToolTipText(ref.getDescription());
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
            refs.add(ref);
            add(b);
        }
    }

    /** The segments' refs, in order: each one's component is its button, its source the option. */
    public List<ComponentRef<Object>> refs() {
        return Collections.unmodifiableList(refs);
    }

    /** Selects the segment whose source equals {@code option}, without firing; null or unknown clears the selection. */
    public void select(Object option) {
        for (int i = 0; i < refs.size(); i++) {
            if (option != null && option.equals(refs.get(i).getSource())) {
                select(i);
                return;
            }
        }
        clearSelection();
    }

    /** The selected segment's source (the enum constant it was built from), or null. */
    @SuppressWarnings("unchecked")
    public <T> T selectedSource() {
        int i = getSelectedIndex();
        return (i >= 0 && i < refs.size()) ? (T) refs.get(i).getSource() : null;
    }

    /**
     * @param values the options this control was built from, in order
     * @return the selected one, or null when nothing is selected
     * @deprecated the control knows its options: use {@link #selectedSource()}
     */
    @Deprecated
    public <T> T selected(T[] values) {
        int i = getSelectedIndex();
        return (i >= 0 && i < values.length) ? values[i] : null;
    }

    /** Selects a segment by index without firing; an index out of range clears the selection. */
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
