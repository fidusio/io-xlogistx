package io.xlogistx.gui;


import org.zoxweb.shared.util.*;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

/**
 * Auto-generated form editor for an {@link NVGenericMap}: renders one labeled editor
 * row per entry (widgets chosen through {@link MetaToWidget}) plus save/cancel icon
 * buttons.
 * <p>
 * Save writes every editor back into the backing map (and notifies the optional
 * consumer set via {@link #setUpdateConsumer(Consumer)}); cancel re-loads the editors
 * from the backing map, discarding UI edits. The widget keeps a live reference to the
 * caller's map — saved changes are visible to the caller immediately.
 */
public class NVGenericMapWidget extends JPanel {

    //    private final Map<String, Object> nvgm;
// reference to caller's map
    private final NVGenericMap nvgm;
    private final Map<String, MappedObject<?,?> >editors = new HashMap<>();
    private final JLabel titleLabel;
    private final JButton cancel;
    private final JButton save;
    private Consumer<NVGenericMap> updateConsumer = null;

    /**
     * Builds the form for the given map: a bold title (the map's name), one labeled
     * editor row per entry pre-loaded with the current values, and save/cancel buttons.
     *
     * @param nvGenericMap backing map to edit; kept by reference, not copied
     */
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
            form.add(editor, gbc);
            gbc.gridy++;
            mappedObject.valueToMap();
        }

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        int size = 32;
        cancel = GUIUtil.iconButton(new IconUtil.CancelIcon(size), true);
        save = GUIUtil.iconButton(new IconUtil.SaveIcon(size), true);
        buttons.add(save);
        buttons.add(cancel);
        add(buttons, BorderLayout.SOUTH);

        cancel.addActionListener(this::onCancel);
        save.addActionListener(this::onSave);
    }


    /**
     * Returns the backing map (live reference, reflects saved edits).
     *
     * @return the backing NVGenericMap
     */
    public NVGenericMap getData() {
        return nvgm;
    }

    /**
     * Returns the cancel button, e.g. to attach additional listeners or to hide it.
     *
     * @return the cancel button
     */
    public JButton getCancel() {
        return cancel;
    }

    /**
     * Returns the save button, e.g. to attach additional listeners or to hide it.
     *
     * @return the save button
     */
    public JButton getSave() {
        return save;
    }

    /**
     * Sets a callback invoked with the backing map after a successful save.
     *
     * @param updateConsumer callback, null to disable
     */
    public void setUpdateConsumer(Consumer<NVGenericMap> updateConsumer) {
        this.updateConsumer = updateConsumer;
    }

    /**
     * Creates the bound editor widget for a map entry via {@link MetaToWidget}.
     *
     * @param gnv map entry to edit
     * @return the entry/widget/binder bundle
     */
    private MappedObject<?,JComponent> createWidgetFor(GetNameValue<?> gnv)
    {
        return MetaToWidget.SINGLETON.create(gnv);
    }

    // Re-read backing map into UI (Cancel)
    private void onCancel(ActionEvent e) {
        for (GetNameValue<?> gnv : nvgm.values()) {
            MappedObject<?, ?> mappedObject = editors.get(gnv.getName());
            mappedObject.valueToMap();
        }
    }

    // Validate & write UI back into backingMap (Save)
    private void onSave(ActionEvent e) {
        try {
            for (GetNameValue<?> gnv : nvgm.values()) {
                MappedObject<?, ?> mappedObject = editors.get(gnv.getName());
                mappedObject.mapToValue();
            }
            if (updateConsumer != null)
                updateConsumer.accept(nvgm);

            JOptionPane.showMessageDialog(this, "Saved successfully.", "Save", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) {
            // catch everything (codec decode failures, range checks, ...) so a bad entry
            // surfaces as a dialog instead of silently aborting the save mid-loop
            JOptionPane.showMessageDialog(this, "Invalid input: " + ex.getMessage(),
                    "Validation Error", JOptionPane.ERROR_MESSAGE);
        }
    }

}

