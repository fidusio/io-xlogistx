package io.xlogistx.gui;

import org.zoxweb.shared.util.DataCodec;
import org.zoxweb.shared.util.MappedObject;
import org.zoxweb.shared.util.MetaValueCodec;
import org.zoxweb.shared.util.SetNameValue;

import javax.swing.*;

public class StringWidget extends JScrollPane {


    public static final MappedObject.Setter<SetNameValue<?>, StringWidget> MAPPED_SETTER = new MappedObject.Setter<SetNameValue<?>, StringWidget>() {

        @Override
        public void valueToMap(MappedObject<SetNameValue<?>, StringWidget> nvMap) {
            SetNameValue<?> snvs = nvMap.get();
            if (snvs.getValue() instanceof String)
                ((JTextArea) nvMap.getMap().getViewport().getView()).setText((String) snvs.getValue());
            else if (snvs.getValue() instanceof byte[]) {
                DataCodec<byte[], String> codec = MetaValueCodec.SINGLETON.lookupCodec(byte[].class);
//                    nvgm.build(new NVBlob(key, codec.decode(ta.getText().trim())));
                ((JTextArea) nvMap.getMap().getViewport().getView()).setText(codec.encode((byte[]) snvs.getValue()));
            }
        }

        @Override
        public void mapToValue(MappedObject<SetNameValue<?>, StringWidget> nvMap) {
            SetNameValue<?> snvs = nvMap.get();

            if (snvs.getValue() instanceof String)
//                ((JTextArea)nvMap.getMap().getViewport().getView()).setText((String)snvs.getValue());
                ((SetNameValue<String>) snvs).setValue(((JTextArea) nvMap.getMap().getViewport().getView()).getText());
            else if (snvs.getValue() instanceof byte[]) {
                DataCodec<byte[], String> codec = MetaValueCodec.SINGLETON.lookupCodec(byte[].class);
//                    nvgm.build(new NVBlob(key, codec.decode(ta.getText().trim())));
                ((SetNameValue<byte[]>) snvs).setValue(codec.decode(((JTextArea) nvMap.getMap().getViewport().getView()).getText()));

            }


        }
    };

    protected static StringWidget create(Object... param) {
        return new StringWidget();
    }

    private static JTextArea createTA() {
        JTextArea ta = new JTextArea(4, 32);
        ta.setLineWrap(true);
        ta.setWrapStyleWord(true);
        return ta;
    }

    public StringWidget() {
        super(createTA());
    }
}
