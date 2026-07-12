package io.xlogistx.gui;


import org.zoxweb.shared.util.MappedObject;
import org.zoxweb.shared.util.NVEnum;
import org.zoxweb.shared.util.SUS;

import javax.swing.*;

/**
 * Combo-box editor for enum values: it is populated with all constants of the enum's
 * declaring class and pre-selects the supplied value. Used by {@link MetaToWidget}
 * to edit {@link NVEnum} entries.
 */
public class EnumWidget extends JComboBox<Enum<?>> {

    /**
     * Bidirectional binding between an {@link NVEnum} and an EnumWidget:
     * valueToMap selects the NVEnum's value in the combo box, mapToValue writes the
     * combo box selection back into the NVEnum.
     */
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



    /**
     * Factory used by {@link MetaToWidget}; expects param[0] to be an {@link NVEnum}
     * with a non-null value.
     *
     * @param param factory parameters, param[0] must be an NVEnum
     * @return a new EnumWidget pre-selected with the NVEnum's value
     * @throws IllegalArgumentException if the NVEnum's value is null (the enum type
     *                                  cannot be determined without a value)
     */
    protected static EnumWidget create(Object ...param)
    {
        NVEnum nvEnum = (NVEnum) param[0];
        if (nvEnum.getValue() == null)
            throw new IllegalArgumentException("NVEnum \"" + nvEnum.getName() + "\" has a null value, the enum type cannot be determined");
        return new EnumWidget(nvEnum.getValue());
    }

    /**
     * Creates a combo box containing all constants of the enum's declaring class,
     * with the given value pre-selected.
     *
     * @param enumVal enum value to select; must not be null
     * @throws NullPointerException if enumVal is null
     */
    public EnumWidget(Enum<?> enumVal) {
        super(enumConstants(enumVal));
        //JComboBox<Object> combo = new JComboBox<>(constants);
        setSelectedItem(enumVal);
    }

    /**
     * Validates the enum value and returns all constants of its declaring class
     * (needed as a helper because validation must happen before the super() call).
     *
     * @param enumVal enum value, must not be null
     * @return all constants of the enum's declaring class
     * @throws NullPointerException if enumVal is null
     */
    private static Enum<?>[] enumConstants(Enum<?> enumVal) {
        SUS.checkIfNulls("enum value can't be null", enumVal);
        return enumVal.getDeclaringClass().getEnumConstants();
    }

}
