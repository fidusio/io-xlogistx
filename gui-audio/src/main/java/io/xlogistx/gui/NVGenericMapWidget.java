package io.xlogistx.gui;


import org.zoxweb.shared.util.*;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

public class NVGenericMapWidget extends JPanel {

    //    private final Map<String, Object> nvgm;
// reference to caller's map
    private final NVGenericMap nvgm;
    private final Map<String, MappedObject<?,?> >editors = new HashMap<>();
    private final JLabel titleLabel;
    private final JButton cancel;
    private final JButton save;
    private Consumer<NVGenericMap> updateConsumer = null;

    public NVGenericMapWidget(NVGenericMap nvGenericMap) {
        super(new BorderLayout(10, 10));
        this.nvgm = nvGenericMap;

        titleLabel = new JLabel(nvgm.getName());
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 16f));
        add(titleLabel, BorderLayout.NORTH);

        JPanel form = new JPanel(new GridBagLayout());
        add(new JScrollPane(form,
                ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
                ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER), BorderLayout.CENTER);

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(6, 10, 6, 10);
        gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;

        for (GetNameValue<?> gnv : nvgm.values()) {


            JLabel label = new JLabel(gnv.getName() + ":");
            gbc.gridx = 0;
            gbc.weightx = 0;
            form.add(label, gbc);
            MappedObject<?, JComponent> mappedObject = createWidgetFor(gnv);

            JComponent editor = mappedObject.getMap();//createEditorFor(gnv.getValue());
            editors.put(gnv.getName(), mappedObject);

            gbc.gridx = 1;
            gbc.weightx = 1.0;
            if (editor instanceof JScrollPane) {
                form.add(editor, gbc);
            } else {
                form.add(editor, gbc);
            }
            gbc.gridy++;
            mappedObject.valueToMap();
        }

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        int size = 32;
        cancel = GUIUtil.iconButton(new GUIUtil.CancelIcon(size));
        save = GUIUtil.iconButton(new GUIUtil.SaveIcon(size));
        buttons.add(save);
        buttons.add(cancel);
        add(buttons, BorderLayout.SOUTH);

        cancel.addActionListener(this::onCancel);
        save.addActionListener(this::onSave);
    }


    public NVGenericMap getData() {
        return nvgm;
    }

    public JButton getCancel() {
        return cancel;
    }

    public JButton getSave() {
        return save;
    }

    public void setUpdateConsumer(Consumer<NVGenericMap> updateConsumer) {
        this.updateConsumer = updateConsumer;
    }

    private MappedObject<?,JComponent> createWidgetFor(GetNameValue<?> gnv)
    {
        return MetaToWidget.SINGLETON.create(gnv);
    }

    private JComponent createEditorFor(Object value) {
        if (value instanceof String) {
            JTextArea ta = new JTextArea(4, 32);
            ta.setLineWrap(true);
            ta.setWrapStyleWord(true);
            ta.setText((String) value);
            return new JScrollPane(ta);
        } else if (value instanceof Integer || value instanceof Long
                || value instanceof Float || value instanceof Double) {
            JTextField tf = new JTextField(24);
            tf.setText(String.valueOf(value));
            tf.setToolTipText("Numeric value (" + value.getClass().getSimpleName() + ")");
            return tf;
        } else if (value instanceof Boolean) {
            JCheckBox cb = new JCheckBox();
            cb.setSelected((Boolean) value);
            return cb;
        } else if (value instanceof Enum) {
            Enum<?> enumVal = (Enum<?>) value;
            Object[] constants = enumVal.getDeclaringClass().getEnumConstants();
            JComboBox<Object> combo = new JComboBox<>(constants);
            combo.setSelectedItem(enumVal);
            return combo;
        } else if (value instanceof byte[]) {
            JTextArea ta = new JTextArea(4, 32);
            ta.setLineWrap(true);
            ta.setWrapStyleWord(true);

            DataCodec<byte[], String> codec = MetaValueCodec.SINGLETON.lookupCodec(value);

            ta.setText(codec.encode((byte[]) value));
            return new JScrollPane(ta);
        } else {
            // Fallback: show toString in a disabled field
            JTextField tf = new JTextField(24);
            tf.setText(value == null ? "" : String.valueOf(value));
            tf.setEditable(false);
            tf.setToolTipText("Unsupported type: " + (value == null ? "null" : value.getClass().getName()));
            return tf;
        }
    }

    // Re-read backing map into UI (Cancel)
    private void onCancel(ActionEvent e) {
        for (GetNameValue<?> gnv : nvgm.values()) {
            MappedObject<?, ?> mappedObject = editors.get(gnv.getName());
            mappedObject.valueToMap();

//            String key = gnv.getName();
//            Object value = gnv.getValue();
//            JComponent editor = editors.get(key);
//
//            if (editor instanceof JScrollPane) {
//                Component c = ((JScrollPane) editor).getViewport().getView();
//                DataCodec codec = MetaValueCodec.SINGLETON.lookupCodec(value);
//
//                if (c instanceof JTextArea) {
//                    ((JTextArea) c).setText((String) codec.encode(value));
//                }
//            } else if (editor instanceof JTextField) {
//                ((JTextField) editor).setText(String.valueOf(value));
//            } else if (editor instanceof JCheckBox) {
//                ((JCheckBox) editor).setSelected((Boolean) value);
//            } else if (editor instanceof JComboBox) {
//                @SuppressWarnings("unchecked")
//                JComboBox<Object> combo = (JComboBox<Object>) editor;
//                if (value instanceof Enum) combo.setSelectedItem(value);
//            }
        }
    }

    // Validate & write UI back into backingMap (Save)
    private void onSave(ActionEvent e) {
        try {
            for (GetNameValue<?> gnv : nvgm.values()) {
                MappedObject<?, ?> mappedObject = editors.get(gnv.getName());
                mappedObject.mapToValue();
//                String key = gnv.getName();
//                Object current = gnv.getValue();
//                JComponent editor = editors.get(gnv.getName());
//
//                if (current instanceof String) {
//                    JTextArea ta = (JTextArea) ((JScrollPane) editor).getViewport().getView();
//                    nvgm.build(key, ta.getText());
//                } else if (current instanceof Integer) {
//                    String txt = ((JTextField) editor).getText().trim();
//                    nvgm.build(new NVInt(key, Integer.parseInt(txt)));
//                } else if (current instanceof Long) {
//                    String txt = ((JTextField) editor).getText().trim();
//                    nvgm.build(new NVLong(key, Long.parseLong(txt)));
//                } else if (current instanceof Float) {
//                    String txt = ((JTextField) editor).getText().trim();
//                    nvgm.build(new NVFloat(key, Float.parseFloat(txt)));
//                } else if (current instanceof Double) {
//                    String txt = ((JTextField) editor).getText().trim();
//                    nvgm.build(new NVDouble(key, Double.parseDouble(txt)));
//                } else if (current instanceof Boolean) {
//                    nvgm.build(new NVBoolean(key, ((JCheckBox) editor).isSelected()));
//                } else if (current instanceof byte[]) {
//                    JTextArea ta = (JTextArea) ((JScrollPane) editor).getViewport().getView();
//                    DataCodec<byte[], String> codec = MetaValueCodec.SINGLETON.lookupCodec(byte[].class);
//                    nvgm.build(new NVBlob(key, codec.decode(ta.getText().trim())));
//                } else if (current instanceof Enum) {
//                    @SuppressWarnings("unchecked")
//                    JComboBox<Object> combo = (JComboBox<Object>) editor;
//                    Object sel = combo.getSelectedItem();
//                    if (sel != null && sel.getClass().isEnum()) {
//                        nvgm.build(new NVEnum(key, (Enum) sel));
//                    }
//                } else {
//                    // Unsupported types are ignored (read-only)
//                }
            }
            if (updateConsumer != null)
                updateConsumer.accept(nvgm);

            JOptionPane.showMessageDialog(this, "Saved successfully.", "Save", JOptionPane.INFORMATION_MESSAGE);
        } catch (NumberFormatException ex) {
            JOptionPane.showMessageDialog(this, "Invalid numeric input: " + ex.getMessage(),
                    "Validation Error", JOptionPane.ERROR_MESSAGE);
        }
    }

}

