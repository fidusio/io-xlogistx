package io.xlogistx.gui;

import org.zoxweb.shared.util.*;

import javax.swing.*;

/**
 * Scrollable multi-line text editor for string and binary values: a {@link JTextArea}
 * (4x32, word-wrapped) wrapped in a scroll pane. Used by {@link MetaToWidget} to edit
 * {@link NVPair} (plain text) and {@link NVBlob} (binary, rendered/parsed through the
 * registered byte[] {@link DataCodec}) entries.
 */
public class StringWidget extends JScrollPane {


    /**
     * Bidirectional binding between a {@link SetNameValue} and a StringWidget:
     * valueToMap loads the value into the text area (encoding byte[] values with the
     * registered codec), mapToValue writes the text back into the SetNameValue
     * (decoding to byte[] for blob values).
     */
    public static final MappedObject.Setter<SetNameValue<?>, StringWidget> MAPPED_SETTER = new MappedObject.Setter<SetNameValue<?>, StringWidget>() {

        @Override
        public void valueToMap(MappedObject<SetNameValue<?>, StringWidget> nvMap) {
            SetNameValue<?> snvs = nvMap.get();
            JTextArea ta = (JTextArea) nvMap.getMap().getViewport().getView();

            if (isBlob(snvs)) {
                byte[] data = (byte[]) snvs.getValue();
                DataCodec<byte[], String> codec = DataCodecRegistrar.SINGLETON.lookup(byte[].class);
                ta.setText(data != null ? codec.encode(data) : "");
            } else {
                Object value = snvs.getValue();
                ta.setText(value != null ? value.toString() : "");
            }
        }

        @Override
        public void mapToValue(MappedObject<SetNameValue<?>, StringWidget> nvMap) {
            SetNameValue<?> snvs = nvMap.get();
            String text = ((JTextArea) nvMap.getMap().getViewport().getView()).getText();

            if (isBlob(snvs)) {
                DataCodec<byte[], String> codec = DataCodecRegistrar.SINGLETON.lookup(byte[].class);
                String trimmed = text.trim();
                ((SetNameValue<byte[]>) snvs).setValue(trimmed.isEmpty() ? null : codec.decode(trimmed));
            } else {
                ((SetNameValue<String>) snvs).setValue(text);
            }
        }

        // single classifier shared by both directions so load and save can never disagree
        private boolean isBlob(SetNameValue<?> snvs) {
            return snvs instanceof NVBlob || snvs.getValue() instanceof byte[];
        }
    };

    /**
     * Factory used by {@link MetaToWidget}.
     *
     * @param param factory parameters (unused)
     * @return a new StringWidget
     */
    protected static StringWidget create(Object... param) {
        return new StringWidget();
    }

    /**
     * Creates the wrapped text area (4 rows x 32 columns, word-wrapped).
     *
     * @return the configured text area
     */
    private static JTextArea createTA() {
        JTextArea ta = new JTextArea(4, 32);
        ta.setLineWrap(true);
        ta.setWrapStyleWord(true);
        return ta;
    }

    /** Creates an empty scrollable text editor. */
    public StringWidget() {
        super(createTA());
    }
}
