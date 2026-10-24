package io.xlogistx.gui;

import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSpinner;
import javax.swing.SpinnerNumberModel;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.Font;

/**
 * A toolbar control for {@link UIFontSize}: "Aa" and a spinner with the
 * control text size in points. Turning the spinner applies the size at once.
 * <p>
 * The control has a <b>scope</b>: with none ({@link #FontSizeWidget()}) it
 * drives the whole application ({@link UIFontSize#apply(float)}) and follows a
 * size set elsewhere (a menu, a remembered setting). With a scope
 * ({@link #FontSizeWidget(Component)}) it drives that one component tree only
 * ({@link UIFontSize#apply(Component, float)}) — the way for a viewer embedded
 * in a host application to size its own controls without resizing the host,
 * and to stay as set when the host changes its size.
 * <p>
 * The control itself keeps the look and feel's base text size: it is the
 * knob, not a sample of the result, so it must not grow or shrink with the
 * setting it changes.
 */
public class FontSizeWidget extends JPanel {

    /** The tooltip of the control. */
    public static final String TIP = "Text size of the controls (menus, buttons, labels), in points";

    private final JLabel label;
    private final JSpinner spinner;
    private Component scope;
    private boolean updating;

    /** A control for the whole application's text size. */
    public FontSizeWidget() {
        this(null);
    }

    /**
     * @param scope the component tree the control sizes, or null for the whole
     *              application
     */
    public FontSizeWidget(Component scope) {
        super(new FlowLayout(FlowLayout.LEFT, 2, 0));
        setOpaque(false);
        putClientProperty(UIFontSize.PINNED, Boolean.TRUE);
        this.scope = scope;
        label = new JLabel("Aa");
        label.setToolTipText(TIP);
        add(label);
        spinner = new JSpinner(new SpinnerNumberModel(Math.round(current()), Math.round(UIFontSize.MIN), Math.round(UIFontSize.MAX), 1));
        spinner.setToolTipText(TIP);
        spinner.setName("font-size");
        ((JSpinner.DefaultEditor) spinner.getEditor()).getTextField().setColumns(2);
        spinner.addChangeListener(e -> {
            if (updating)
                return;
            float size = ((Number) spinner.getValue()).floatValue();
            if (this.scope == null)
                UIFontSize.apply(size);
            else
                UIFontSize.apply(this.scope, size);
        });
        UIFontSize.addListener(size -> {
            // the application size: ours to show only when we drive it
            if (this.scope == null)
                show(size);
            pinFonts();
        });
        add(spinner);
        pinFonts();
    }

    /** @return the tree this control sizes, or null for the whole application */
    public Component getScope() {
        return scope;
    }

    /**
     * Re-points the control: null drives the whole application, a component
     * drives that tree only. The spinner shows the size in force for the new
     * scope; nothing is applied.
     *
     * @param scope the tree, or null for the application
     * @return this
     */
    public FontSizeWidget setScope(Component scope) {
        this.scope = scope;
        show(current());
        return this;
    }

    private float current() {
        return scope == null ? UIFontSize.get() : UIFontSize.get(scope);
    }

    private void show(float size) {
        updating = true;
        try {
            spinner.setValue(Math.round(size));
        } finally {
            updating = false;
        }
    }

    /**
     * Gives the label, the spinner and its editor a plain (non-UIResource) font
     * at the base size, which {@link UIFontSize#refresh} leaves alone, so the
     * control stays the same size whatever text size it sets.
     */
    private void pinFonts() {
        float base = UIFontSize.getBase();
        Font labelFont = fixed(label.getFont(), base);
        if (labelFont != null)
            label.setFont(labelFont);
        Font spinnerFont = fixed(spinner.getFont(), base);
        if (spinnerFont != null) {
            spinner.setFont(spinnerFont);
            JComponent editor = spinner.getEditor();
            editor.setFont(spinnerFont);
            if (editor instanceof JSpinner.DefaultEditor)
                ((JSpinner.DefaultEditor) editor).getTextField().setFont(spinnerFont);
        }
        setMaximumSize(null);
        setMaximumSize(getPreferredSize());
        revalidate();
    }

    /** @return {@code font} at {@code size} as a plain {@link Font}, never a UIResource; null for null */
    private static Font fixed(Font font, float size) {
        if (font == null)
            return null;
        return new Font(font.getAttributes()).deriveFont(size);
    }

    /** @return the spinner, for tests and layout tweaks */
    public JSpinner getSpinner() {
        return spinner;
    }
}
