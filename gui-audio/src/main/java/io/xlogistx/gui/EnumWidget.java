package io.xlogistx.gui;


import org.zoxweb.shared.util.MappedObject;
import org.zoxweb.shared.util.NVEnum;

import javax.swing.*;

public class EnumWidget extends JComboBox<Enum<?>> {
    public static final MappedObject.Setter<NVEnum, EnumWidget> MAPPED_SETTER = new  MappedObject.Setter<NVEnum, EnumWidget>(){

        @Override
        public void valueToMap(MappedObject<NVEnum, EnumWidget> nvMap) {
            NVEnum snvs = nvMap.get();
            nvMap.getMap().setSelectedItem(snvs.getValue());
        }

        @Override
        public void mapToValue(MappedObject<NVEnum, EnumWidget> nvMap) {
            NVEnum snvs = nvMap.get();
            snvs.setValue((Enum<?>)nvMap.getMap().getSelectedItem());
        }
    };



    protected static EnumWidget create(Object ...param)
    {
        return new EnumWidget(((NVEnum)param[0]).getValue());
    }
    public EnumWidget(Enum<?> enumVal) {
        super(enumVal.getDeclaringClass().getEnumConstants());
        //JComboBox<Object> combo = new JComboBox<>(constants);
        setSelectedItem(enumVal);
    }

}
