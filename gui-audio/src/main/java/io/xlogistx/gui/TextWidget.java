package io.xlogistx.gui;

import org.zoxweb.shared.util.MappedObject;
import org.zoxweb.shared.util.SetNameValue;

import javax.swing.JTextField;

/**
 * Single-line text editor for string values: a plain {@link JTextField}. Used by
 * {@link MetaToWidget} to edit {@link org.zoxweb.shared.util.NVPair} entries; binary
 * values keep the multi-line {@link StringWidget}.
 */
public class TextWidget extends JTextField {

    /**
     * Bidirectional binding between a string {@link SetNameValue} and a TextWidget: valueToMap
     * shows the value (an empty field for null), mapToValue writes the text back.
     */
    public static final MappedObject.Setter<SetNameValue<String>, TextWidget> MAPPED_SETTER = new MappedObject.Setter<SetNameValue<String>, TextWidget>() {
        @Override
        public void valueToMap(MappedObject<SetNameValue<String>, TextWidget> nvMap) {
            Object value = nvMap.get() instanceof SetNameValue ? ((SetNameValue<?>) nvMap.get()).getValue() : null;
            nvMap.getMap().setText(value != null ? value.toString() : "");
        }

        @Override
        public void mapToValue(MappedObject<SetNameValue<String>, TextWidget> nvMap) {
            ((SetNameValue<String>) nvMap.get()).setValue(nvMap.getMap().getText());
        }
    };

    /**
     * Factory used by {@link MetaToWidget}.
     *
     * @param param factory parameters (unused)
     * @return a new TextWidget
     */
    protected static TextWidget create(Object... param) {
        return new TextWidget();
    }

    /** Creates an empty single-line text editor. */
    public TextWidget() {
        super(24);
    }
}
