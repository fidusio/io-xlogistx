package io.xlogistx.gui;

import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSpinner;
import javax.swing.SpinnerNumberModel;
import java.awt.FlowLayout;

/**
 * A toolbar control for {@link UIFontSize}: "Aa" and a spinner with the
 * control text size in points. Turning the spinner applies the size at once;
 * a size set elsewhere (a menu, a remembered setting) shows up in the spinner.
 */
public class FontSizeWidget extends JPanel {

    /** The tooltip of the control. */
    public static final String TIP = "Text size of the controls (menus, buttons, labels), in points";

    private final JSpinner spinner;
    private boolean updating;

    public FontSizeWidget() {
        super(new FlowLayout(FlowLayout.LEFT, 2, 0));
        setOpaque(false);
        JLabel label = new JLabel("Aa");
        label.setToolTipText(TIP);
        add(label);
        spinner = new JSpinner(new SpinnerNumberModel(Math.round(UIFontSize.get()), Math.round(UIFontSize.MIN), Math.round(UIFontSize.MAX), 1));
        spinner.setToolTipText(TIP);
        spinner.setName("font-size");
        ((JSpinner.DefaultEditor) spinner.getEditor()).getTextField().setColumns(2);
        spinner.addChangeListener(e -> {
            if (!updating)
                UIFontSize.apply(((Number) spinner.getValue()).floatValue());
        });
        UIFontSize.addListener(size -> {
            updating = true;
            try {
                spinner.setValue(Math.round(size));
            } finally {
                updating = false;
            }
        });
        add(spinner);
        setMaximumSize(getPreferredSize());
    }

    /** @return the spinner, for tests and layout tweaks */
    public JSpinner getSpinner() {
        return spinner;
    }
}
