package io.xlogistx.gui;


import org.zoxweb.shared.util.*;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.util.HashMap;
import java.util.Map;

public class NVGenericMapWidget extends JPanel {

//    private final Map<String, Object> nvgm;
// reference to caller's map
    private final NVGenericMap nvgm;
    private final Map<String, JComponent> editors = new HashMap<>();
    private final JLabel titleLabel;

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

        for (GetNameValue<?> gnv: nvgm.values()) {


            JLabel label = new JLabel(gnv.getName() + ":");
            gbc.gridx = 0;
            gbc.weightx = 0;
            form.add(label, gbc);

            JComponent editor = createEditorFor(gnv.getValue());
            editors.put(gnv.getName(), editor);

            gbc.gridx = 1;
            gbc.weightx = 1.0;
            if (editor instanceof JScrollPane) {
                form.add(editor, gbc);
            } else {
                form.add(editor, gbc);
            }
            gbc.gridy++;
        }

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        int size = 32;
        JButton cancel = GUIUtil.iconButton(new GUIUtil.CancelIcon(size));
        JButton save   = GUIUtil.iconButton(new GUIUtil.SaveIcon(size));
        buttons.add(save);
        buttons.add(cancel);
        add(buttons, BorderLayout.SOUTH);

        cancel.addActionListener(this::onCancel);
        save.addActionListener(this::onSave);
    }


    public NVGenericMap getData()
    {
        return nvgm;
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
        for (GetNameValue<?> gnv: nvgm.values()) {
            String key = gnv.getName();
            Object value = gnv.getValue();
            JComponent editor = editors.get(key);

            if (editor instanceof JScrollPane) {
                Component c = ((JScrollPane) editor).getViewport().getView();
                if (c instanceof JTextArea) {
                    ((JTextArea) c).setText((String) value);
                }
            } else if (editor instanceof JTextField) {
                ((JTextField) editor).setText(String.valueOf(value));
            } else if (editor instanceof JCheckBox) {
                ((JCheckBox) editor).setSelected((Boolean) value);
            } else if (editor instanceof JComboBox) {
                @SuppressWarnings("unchecked")
                JComboBox<Object> combo = (JComboBox<Object>) editor;
                if (value instanceof Enum) combo.setSelectedItem(value);
            }
        }
    }

    // Validate & write UI back into backingMap (Save)
    private void onSave(ActionEvent e) {
        try {
            for (GetNameValue<?> gnv: nvgm.values()) {
                String key = gnv.getName();
                Object current = gnv.getValue();
                JComponent editor = editors.get(gnv.getName());

                if (current instanceof String) {
                    JTextArea ta = (JTextArea) ((JScrollPane) editor).getViewport().getView();
                    nvgm.build(key, ta.getText());
                } else if (current instanceof Integer) {
                    String txt = ((JTextField) editor).getText().trim();
                    nvgm.build(new NVInt(key, Integer.parseInt(txt)));
                } else if (current instanceof Long) {
                    String txt = ((JTextField) editor).getText().trim();
                    nvgm.build(new NVLong(key, Long.parseLong(txt)));
                } else if (current instanceof Float) {
                    String txt = ((JTextField) editor).getText().trim();
                    nvgm.build(new NVFloat(key, Float.parseFloat(txt)));
                } else if (current instanceof Double) {
                    String txt = ((JTextField) editor).getText().trim();
                    nvgm.build(new NVDouble(key, Double.parseDouble(txt)));
                } else if (current instanceof Boolean) {
                    nvgm.build(new NVBoolean(key, ((JCheckBox) editor).isSelected()));
                } else if (current instanceof Enum) {
                    @SuppressWarnings("unchecked")
                    JComboBox<Object> combo = (JComboBox<Object>) editor;
                    Object sel = combo.getSelectedItem();
                    if (sel != null && sel.getClass().isEnum()) {
                        nvgm.build(new NVEnum(key, (Enum)sel));
                    }
                } else {
                    // Unsupported types are ignored (read-only)
                }
            }
            JOptionPane.showMessageDialog(this, "Saved successfully.", "Save", JOptionPane.INFORMATION_MESSAGE);
        } catch (NumberFormatException ex) {
            JOptionPane.showMessageDialog(this, "Invalid numeric input: " + ex.getMessage(),
                    "Validation Error", JOptionPane.ERROR_MESSAGE);
        }
    }

}

