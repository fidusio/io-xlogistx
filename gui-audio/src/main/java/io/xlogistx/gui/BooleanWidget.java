package io.xlogistx.gui;

import org.zoxweb.shared.util.NVBoolean;

import javax.swing.*;
import java.awt.*;

/**
 * Check-box editor for boolean values. Used by {@link MetaToWidget} to edit
 * {@link NVBoolean} entries.
 */
public class BooleanWidget extends JCheckBox {

    /**
     * Factory used by {@link MetaToWidget}; expects param[0] to be an {@link NVBoolean}.
     *
     * @param param factory parameters, param[0] must be an NVBoolean
     * @return a new BooleanWidget initialized to the NVBoolean's value
     */
    protected static BooleanWidget create(Object... param) {
        return new BooleanWidget(null, ((NVBoolean) param[0]).getValue());
    }

    /** Creates an unchecked, unlabeled check box. */
    public BooleanWidget() {
        this(null, false);
    }

    /**
     * Creates a labeled check box.
     *
     * @param label        check box label, may be null
     * @param initialValue initial selected state
     */
    public BooleanWidget(String label, boolean initialValue) {
        super(label, initialValue);
        setFont(new Font("Arial", Font.PLAIN, 12));
        setToolTipText(label != null ? "Toggle " + label : null);
    }

    /**
     * Returns the current selected state.
     *
     * @return true if the check box is selected
     */
    public boolean getValue() {
        return isSelected();
    }

    /**
     * Sets the selected state.
     *
     * @param value selected state to apply
     */
    public void setValue(boolean value) {
        setSelected(value);
    }
}
