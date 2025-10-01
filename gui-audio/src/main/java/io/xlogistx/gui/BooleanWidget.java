package io.xlogistx.gui;

import org.zoxweb.shared.util.NVBoolean;

import javax.swing.*;
import java.awt.*;

public class BooleanWidget extends JCheckBox {
    protected static BooleanWidget create(Object... param) {
        return new BooleanWidget(null, ((NVBoolean) param[0]).getValue());
    }

    public BooleanWidget() {
        this(null, false);
    }

    public BooleanWidget(String label, boolean initialValue) {
        super(label, initialValue);
        setFont(new Font("Arial", Font.PLAIN, 12));
        setToolTipText("Toggle " + label);
    }

    public boolean getValue() {
        return isSelected();
    }

    public void setValue(boolean value) {
        setSelected(value);
    }
}
