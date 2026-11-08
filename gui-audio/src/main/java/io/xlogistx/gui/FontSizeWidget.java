package io.xlogistx.gui;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSpinner;
import javax.swing.SpinnerNumberModel;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;

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
 * The control's own text is always the <b>application's</b> size, whatever the
 * scope: its label and spinner keep the look and feel's fonts and are left out
 * of a scoped scaling ({@link UIFontSize#PINNED}). A look and feel that sizes
 * its controls from the font (FlatLaf scales paddings, minimum widths and the
 * spinner arrows with it) draws the box and the arrows at the application's
 * size, and text held at any other size sits crooked in them: a wide box
 * around small digits, the two arrows squeezed into one.
 * <p>
 * The label and the number share a baseline, and the control reports it
 * ({@link #getBaseline(int, int)}), so a baseline-aligning layout lines it up
 * with the text beside it.
 * <p>
 * Two optional parts make it a whole settings row (2026-11-06): a <b>caption</b>
 * on the left ({@link #withLabel}, "Text size" unless told otherwise, pointed
 * at the spinner for mnemonics and screen readers) and a <b>Reset</b> link on
 * the right ({@link #withReset}, an inline {@link UITokens#link} that takes the
 * widget's scope back to the look and feel's own size). An application names
 * them for its harness through {@link #getLabel()} and {@link #getResetButton()}.
 * A bare widget, as in a tool bar, has neither.
 */
public class FontSizeWidget extends JPanel {

    /** The tooltip of the control. */
    public static final String TIP = "Text size of the controls (menus, buttons, labels), in points";
    /** The caption {@link #withLabel()} puts on the left. */
    public static final String LABEL = "Text size";
    /** The text and tooltip of the link {@link #withReset()} puts on the right. */
    public static final String RESET = "Reset", RESET_TIP = "Back to the look and feel's own size";

    private final JLabel label;
    private final JSpinner spinner;
    private JLabel caption;
    private JButton reset;
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
        super(baselineFlow());
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
            revalidate(); // our own text is the application's, so our size changed
        });
        add(spinner);
    }

    private static FlowLayout baselineFlow() {
        FlowLayout flow = new FlowLayout(FlowLayout.LEFT, 2, 0);
        flow.setAlignOnBaseline(true);
        return flow;
    }

    /** @return the tree this control sizes, or null for the whole application */
    public Component getScope() {
        return scope;
    }

    /** A {@link #LABEL} caption on the left. @return this */
    public FontSizeWidget withLabel() {
        return withLabel(LABEL);
    }

    /**
     * Puts a caption on the left of "Aa", labelling the spinner; a second call
     * replaces the text.
     *
     * @param text the caption, never null
     * @return this
     */
    public FontSizeWidget withLabel(String text) {
        if (caption == null) {
            caption = new JLabel();
            caption.setName("font-size-label");
            caption.setLabelFor(spinner);
            caption.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 6));
            add(caption, 0);
        }
        caption.setText(text);
        revalidate();
        return this;
    }

    /** A {@link #RESET} link on the right. @return this */
    public FontSizeWidget withReset() {
        return withReset(RESET, RESET_TIP);
    }

    /**
     * Puts an inline link on the right that takes the widget's scope back to
     * the base size: the whole application ({@link UIFontSize#reset()}) or the
     * one tree ({@link UIFontSize#apply(Component, float)} with the base); a
     * second call replaces the text.
     *
     * @param text    the link's text, never null
     * @param tooltip its tooltip, or null for none
     * @return this
     */
    public FontSizeWidget withReset(String text, String tooltip) {
        if (reset == null) {
            reset = UITokens.link(new JButton());
            reset.setName("font-size-reset");
            reset.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createEmptyBorder(0, 6, 0, 0), reset.getBorder()));
            reset.addActionListener(e -> reset());
            add(reset);
        }
        reset.setText(text);
        reset.setToolTipText(tooltip);
        revalidate();
        return this;
    }

    /** Takes the widget's scope back to the look and feel's own size, as the Reset link does. */
    public void reset() {
        if (scope == null)
            UIFontSize.reset();
        else
            UIFontSize.apply(scope, UIFontSize.getBase());
    }

    /** @return the caption {@link #withLabel} added, or null */
    public JLabel getLabel() {
        return caption;
    }

    /** @return the link {@link #withReset} added, or null */
    public JButton getResetButton() {
        return reset;
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
     * @return the preferred size unless a maximum was set: the control never
     *         stretches (a tool bar's box layout would), and the limit follows
     *         the text size instead of being a snapshot of one
     */
    @Override
    public Dimension getMaximumSize() {
        return isMaximumSizeSet() ? super.getMaximumSize() : getPreferredSize();
    }

    /** @return the baseline the label and the number share, -1 when neither has one */
    @Override
    public int getBaseline(int width, int height) {
        int ascent = -1;
        for (Component c : getComponents()) {
            if (!c.isVisible())
                continue;
            Dimension d = c.getPreferredSize();
            ascent = Math.max(ascent, c.getBaseline(d.width, d.height));
        }
        return ascent < 0 ? -1 : getInsets().top + ascent;
    }

    /** @return {@link java.awt.Component.BaselineResizeBehavior#CONSTANT_ASCENT}: the row sits at the top */
    @Override
    public BaselineResizeBehavior getBaselineResizeBehavior() {
        return BaselineResizeBehavior.CONSTANT_ASCENT;
    }

    /** @return the spinner, for tests and layout tweaks */
    public JSpinner getSpinner() {
        return spinner;
    }
}
