package io.xlogistx.gui;


import org.zoxweb.shared.util.*;

import javax.swing.*;

import static org.zoxweb.shared.util.MappedObject.Setter;


public class MetaToWidget {

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
                        ((NVInt) nvMap.get()).setValue((int) nvMap.getMap().getValue());
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


    public MappedObject<?, JComponent> create(GetNameValue<?> gnv) {
        return new MappedObject(gnv, metaToWidget.lookup(gnv.getClass()).newInstance(gnv), metaWidgetSetter.lookup(gnv.getClass()));
    }


}
