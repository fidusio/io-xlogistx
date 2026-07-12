package io.xlogistx.gui;


import org.zoxweb.shared.util.*;

import javax.swing.*;

import static org.zoxweb.shared.util.MappedObject.Setter;


/**
 * Singleton registry mapping NV metadata types to their Swing editor widgets and
 * value binders:
 * <ul>
 *   <li>NVBoolean → {@link BooleanWidget}</li>
 *   <li>NVFloat / NVDouble → {@link DecimalWidget}</li>
 *   <li>NVInt / NVLong → {@link LongWidget}</li>
 *   <li>NVEnum → {@link EnumWidget}</li>
 *   <li>NVPair / NVBlob → {@link StringWidget}</li>
 * </ul>
 * {@link #create(GetNameValue)} bundles the NV instance, a freshly created widget and
 * the matching {@link Setter} into a {@link MappedObject} so callers (e.g.
 * {@link NVGenericMapWidget}) can move values between model and UI with
 * valueToMap()/mapToValue().
 */
public class MetaToWidget {

    /** Shared singleton instance. */
    public static final MetaToWidget SINGLETON = new MetaToWidget();
    private final RegistrarMapDefault<Class<?>, InstanceFactory.ParamsCreator<?>> metaToWidget = new RegistrarMapDefault<>();
    private final RegistrarMapDefault<Class<?>, Setter<?, ?>> metaWidgetSetter = new RegistrarMapDefault<>();


    private MetaToWidget() {
        init();
    }

    private void init() {
        metaToWidget.register(NVBoolean.class, BooleanWidget::create)
                .register(NVFloat.class, DecimalWidget::create)
                .register(NVDouble.class, DecimalWidget::create)
                .register(NVInt.class, LongWidget::create)
                .register(NVLong.class, LongWidget::create)
                .register(NVEnum.class, EnumWidget::create)
                .register(NVPair.class, StringWidget::create)
                .register(NVBlob.class, StringWidget::create);


        metaWidgetSetter.register(NVBoolean.class, new Setter<NVBoolean, BooleanWidget>() {
                    @Override
                    public void valueToMap(MappedObject<NVBoolean, BooleanWidget> nvMap) {
                        nvMap.getMap().setValue(((NVBoolean) nvMap.get()).getValue());
                    }

                    @Override
                    public void mapToValue(MappedObject<NVBoolean, BooleanWidget> nvMap) {
                        ((NVBoolean) nvMap.get()).setValue(nvMap.getMap().getValue());
                    }
                }).register(NVFloat.class, new Setter<NVFloat, DecimalWidget>() {
                    @Override
                    public void valueToMap(MappedObject<NVFloat, DecimalWidget> nvMap) {
                        nvMap.getMap().setValue(((NVFloat) nvMap.get()).getValue());
                    }

                    @Override
                    public void mapToValue(MappedObject<NVFloat, DecimalWidget> nvMap) {
                        ((NVFloat) nvMap.get()).setValue((float) nvMap.getMap().getValue());
                    }
                }).register(NVDouble.class, new Setter<NVDouble, DecimalWidget>() {
                    @Override
                    public void valueToMap(MappedObject<NVDouble, DecimalWidget> nvMap) {
                        nvMap.getMap().setValue(((NVDouble) nvMap.get()).getValue());
                    }

                    @Override
                    public void mapToValue(MappedObject<NVDouble, DecimalWidget> nvMap) {
                        ((NVDouble) nvMap.get()).setValue(nvMap.getMap().getValue());
                    }
                }).register(NVInt.class, new Setter<NVInt, LongWidget>() {
                    @Override
                    public void valueToMap(MappedObject<NVInt, LongWidget> nvMap) {
                        nvMap.getMap().setValue(((NVInt) nvMap.get()).getValue());
                    }

                    @Override
                    public void mapToValue(MappedObject<NVInt, LongWidget> nvMap) {
                        long value = nvMap.getMap().getValue();
                        if (value < Integer.MIN_VALUE || value > Integer.MAX_VALUE)
                            throw new NumberFormatException("\"" + ((NVInt) nvMap.get()).getName() + "\" out of int range: " + value);
                        ((NVInt) nvMap.get()).setValue((int) value);
                    }
                }).register(NVLong.class, new Setter<NVLong, LongWidget>() {
                    @Override
                    public void valueToMap(MappedObject<NVLong, LongWidget> nvMap) {
                        nvMap.getMap().setValue(((NVLong) nvMap.get()).getValue());
                    }

                    @Override
                    public void mapToValue(MappedObject<NVLong, LongWidget> nvMap) {
                        ((NVLong) nvMap.get()).setValue(nvMap.getMap().getValue());
                    }
                })
                .register(NVPair.class, StringWidget.MAPPED_SETTER)
                .register(NVBlob.class, StringWidget.MAPPED_SETTER)
                .register(NVEnum.class, EnumWidget.MAPPED_SETTER);

    }


    /** Binder for unregistered NV types: shows the value's toString, never writes back. */
    private static final Setter<GetNameValue<?>, JTextField> READ_ONLY_SETTER = new Setter<GetNameValue<?>, JTextField>() {
        @Override
        public void valueToMap(MappedObject<GetNameValue<?>, JTextField> nvMap) {
            Object value = ((GetNameValue<?>) nvMap.get()).getValue();
            nvMap.getMap().setText(value != null ? String.valueOf(value) : "");
        }

        @Override
        public void mapToValue(MappedObject<GetNameValue<?>, JTextField> nvMap) {
            // read-only fallback: nothing to write back
        }
    };

    /**
     * Creates an editor widget for the given NV instance and binds them together.
     * Unregistered NV types get a read-only text field showing the value's toString
     * instead of failing, so forms containing unsupported entries still render.
     *
     * @param gnv NV instance to edit
     * @return a MappedObject holding the NV instance, its editor component and the
     *         value binder
     */
    public MappedObject<?, JComponent> create(GetNameValue<?> gnv) {
        InstanceFactory.ParamsCreator<?> factory = metaToWidget.lookup(gnv.getClass());
        Setter<?, ?> setter = metaWidgetSetter.lookup(gnv.getClass());
        if (factory == null || setter == null) {
            JTextField fallback = new JTextField(24);
            fallback.setEditable(false);
            fallback.setToolTipText("Unsupported type: " + gnv.getClass().getName());
            return new MappedObject(gnv, fallback, READ_ONLY_SETTER);
        }
        return new MappedObject(gnv, factory.newInstance(gnv), setter);
    }


}
