package io.xlogistx.gui;

import com.formdev.flatlaf.FlatClientProperties;
import net.miginfocom.swing.MigLayout;
import org.zoxweb.shared.util.GetNameValue;
import org.zoxweb.shared.util.MappedObject;
import org.zoxweb.shared.util.NVGenericMap;

import javax.swing.AbstractButton;
import javax.swing.JCheckBox;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.ScrollPaneConstants;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.JTextComponent;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Container;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ItemEvent;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

/**
 * Auto-generated form editor for an {@link NVGenericMap}: a {@link FormPanel} with one
 * labelled editor per entry (widgets chosen through {@link MetaToWidget}; a boolean's check
 * box carries the name itself, number fields keep a modest width; a nested
 * {@link NVGenericMap} becomes an indented section under its name, recursively, its entries
 * addressed by path such as {@code getEditor("db", "url")}), an
 * {@link InlineMessage} line and a <b>Save</b> / <b>Reset</b> button row, inside a 16 px
 * margin (replace it with {@code setBorder} when the host has its own).
 * <p>
 * Save writes every editor back into the backing map and notifies the optional consumer set
 * via {@link #setUpdateConsumer(Consumer)}. An entry whose value is rejected by its binder
 * (an int out of range, a blob that does not decode, ...) is outlined and named in the
 * message, the other entries are still written, and the consumer is not called. Reset
 * re-loads the editors from the backing map, discarding UI edits. Both buttons are enabled
 * only while an editor has been touched since the last save or reset.
 * <p>
 * The widget keeps a live reference to the caller's map: saved changes are visible to the
 * caller immediately. Entries added to the map after construction are not shown (build a
 * new widget for them).
 */
public class NVGenericMapWidget extends JPanel {

    /** Client property on an outlined editor: the message its binder threw, null when valid. */
    public static final String ERROR_PROPERTY = "io.xlogistx.gui.NVGenericMapWidget.error";
    /** Joins the names of a nested entry's path in {@link #getEntryNames()}. */
    public static final String PATH_SEPARATOR = "/";
    /** Widest a number field grows; longer text still scrolls inside it. */
    public static final int NUMBER_FIELD_WIDTH = 220;

    // reference to caller's map
    private final NVGenericMap nvgm;
    // entry path (names joined by PATH_SEPARATOR) -> binder, in the map's order at construction
    private final Map<String, MappedObject<?, JComponent>> editors = new LinkedHashMap<>();
    private final JLabel titleLabel;
    private final FormPanel form = new FormPanel();
    private final InlineMessage message = new InlineMessage();
    private final JButton cancel;
    private final JButton save;
    private Consumer<NVGenericMap> updateConsumer = null;
    private boolean dirty;
    // true while valueToMap() runs, so loading the editors does not count as an edit
    private boolean loading;

    /**
     * Builds the form for the given map: a title (the map's name, hidden when it has none),
     * one labelled editor per entry pre-loaded with the current values, the message line and
     * the Save / Reset buttons.
     *
     * @param nvGenericMap backing map to edit; kept by reference, not copied
     */
    public NVGenericMapWidget(NVGenericMap nvGenericMap) {
        super(new BorderLayout(0, 8));
        this.nvgm = nvGenericMap;
        setBorder(BorderFactory.createEmptyBorder(16, 16, 16, 16));

        titleLabel = new JLabel(nvgm.getName());
        titleLabel.setFont(UITokens.font(Font.BOLD, 4f));
        titleLabel.setVisible(nvgm.getName() != null && !nvgm.getName().isEmpty());
        titleLabel.setBorder(BorderFactory.createEmptyBorder(0, 0, 4, 0));
        add(titleLabel, BorderLayout.NORTH);

        addEntries(form, nvgm, "");
        if (editors.isEmpty()) {
            form.row(FormPanel.hint("This map has no entries."));
        }

        ScrollablePanel view = new ScrollablePanel(new MigLayout("insets 0, fill", "[grow,fill]", "[]"));
        view.setOpaque(false);
        view.add(form, "growx, aligny top");
        JScrollPane scroll = new JScrollPane(view,
                ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
                ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        scroll.setBorder(null);
        scroll.getViewport().setOpaque(false);
        scroll.setOpaque(false);
        add(scroll, BorderLayout.CENTER);

        // the glyphs are tinted directly: the SaveIcon(size, color) form would also repaint
        // the button background, undoing the primary style
        save = UITokens.primary(new JButton("Save", IconUtil.svgIcon("io/xlogistx/gui/icons/save.svg", 16, Color.WHITE)));
        cancel = new JButton("Reset", new IconUtil.RollbackIcon(16));
        JPanel south = new JPanel(new MigLayout("insets 0, wrap 1, fillx, gapy 6", "[grow,fill]", "[][]"));
        south.setOpaque(false);
        south.add(message, "growx, wmin 0");
        JPanel buttons = new JPanel(new MigLayout("insets 0", "push[]8[]", "[]"));
        buttons.setOpaque(false);
        buttons.add(cancel);
        buttons.add(save);
        south.add(buttons, "growx");
        add(south, BorderLayout.SOUTH);

        cancel.addActionListener(this::onCancel);
        save.addActionListener(this::onSave);

        load();
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
     * Returns the reset button (named cancel for compatibility), e.g. to attach additional
     * listeners or to hide it.
     *
     * @return the reset button
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
     * Returns the message line under the form, for a host that wants to show its own text
     * there.
     *
     * @return the inline message
     */
    public InlineMessage getMessage() {
        return message;
    }

    /**
     * Returns the editor component bound to an entry.
     *
     * @param path the entry name, preceded by the names of the nested maps that hold it
     * @return the editor, null for an unknown path
     */
    public JComponent getEditor(String... path) {
        MappedObject<?, JComponent> mo = editors.get(String.join(PATH_SEPARATOR, path));
        return mo != null ? mo.getMap() : null;
    }

    /**
     * Returns the entry names in form order; a nested entry is its path, the names joined by
     * {@link #PATH_SEPARATOR}.
     *
     * @return an unmodifiable list of names
     */
    public List<String> getEntryNames() {
        return Collections.unmodifiableList(new ArrayList<>(editors.keySet()));
    }

    /**
     * Tells whether an editor has been touched since the last save or reset.
     *
     * @return true while there are unsaved edits
     */
    public boolean isDirty() {
        return dirty;
    }

    /**
     * Sets a callback invoked with the backing map after a save in which every entry was
     * accepted.
     *
     * @param updateConsumer callback, null to disable
     */
    public void setUpdateConsumer(Consumer<NVGenericMap> updateConsumer) {
        this.updateConsumer = updateConsumer;
    }

    // one row per entry of the map into the target form; nested maps become sections
    private void addEntries(FormPanel target, NVGenericMap map, String prefix) {
        for (GetNameValue<?> gnv : map.values()) {
            String path = prefix + gnv.getName();
            if (gnv instanceof NVGenericMap) {
                addSection(target, (NVGenericMap) gnv, path);
                continue;
            }
            MappedObject<?, JComponent> mappedObject = MetaToWidget.SINGLETON.create(gnv);
            editors.put(path, mappedObject);
            addRow(target, gnv.getName(), mappedObject.getMap());
            watch(mappedObject.getMap());
        }
    }

    // a nested map: its name as a heading, its entries in an indented form with a rule on the left
    private void addSection(FormPanel target, NVGenericMap map, String path) {
        JLabel heading = new JLabel(map.getName());
        heading.setFont(UITokens.font(Font.BOLD, 1f));
        target.row(heading, "growx, gaptop 16");
        FormPanel nested = new FormPanel();
        nested.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 2, 0, 0, UITokens.border()),
                BorderFactory.createEmptyBorder(0, 12, 6, 0)));
        addEntries(nested, map, path + PATH_SEPARATOR);
        if (map.values().length == 0) nested.row(FormPanel.hint("No entries."));
        target.row(nested, "growx, gaptop 4");
    }

    // one form row per entry: a check box is its own label, a number field stays narrow
    private void addRow(FormPanel target, String name, JComponent editor) {
        if (editor instanceof JCheckBox) {
            JCheckBox box = (JCheckBox) editor;
            box.setText(name);
            box.setFont(FormPanel.fieldLabel(name, false).getFont());
            target.row(box, "gaptop 10");
            return;
        }
        if (editor instanceof LongWidget || editor instanceof DecimalWidget) {
            Dimension max = editor.getMaximumSize();
            editor.setMaximumSize(new Dimension(NUMBER_FIELD_WIDTH, max.height));
        }
        target.field(name, editor);
    }

    // model -> UI for every entry, clearing outlines, the message and the dirty flag
    private void load() {
        loading = true;
        try {
            for (MappedObject<?, JComponent> mo : editors.values()) {
                mo.valueToMap();
                markError(mo.getMap(), null);
            }
        } finally {
            loading = false;
        }
        message.clear();
        setDirty(false);
    }

    // Re-read backing map into UI (Reset)
    private void onCancel(ActionEvent e) {
        load();
    }

    // Write UI back into the backing map (Save); invalid entries are outlined and reported
    private void onSave(ActionEvent e) {
        List<String> failed = new ArrayList<>();
        JComponent first = null;
        for (MappedObject<?, JComponent> mo : editors.values()) {
            try {
                mo.mapToValue();
                markError(mo.getMap(), null);
            } catch (Exception ex) {
                // catch everything (codec decode failures, range checks, ...) so a bad entry
                // is reported instead of silently aborting the save mid-loop
                String reason = ex.getMessage() != null ? ex.getMessage() : ex.getClass().getSimpleName();
                markError(mo.getMap(), reason);
                failed.add(mo.getName());
                if (first == null) first = mo.getMap();
            }
        }
        if (failed.isEmpty()) {
            if (updateConsumer != null)
                updateConsumer.accept(nvgm);
            message.ok("Saved.");
            setDirty(false);
        } else {
            message.error(failed.size() == 1
                    ? "Invalid value for " + failed.get(0) + ": " + first.getClientProperty(ERROR_PROPERTY)
                    : "Invalid values for " + String.join(", ", failed) + ".");
            first.requestFocusInWindow();
        }
    }

    private static void markError(JComponent editor, String reason) {
        editor.putClientProperty(ERROR_PROPERTY, reason);
        editor.putClientProperty(FlatClientProperties.OUTLINE, reason == null ? null : FlatClientProperties.OUTLINE_ERROR);
        editor.setToolTipText(reason);
    }

    private void setDirty(boolean value) {
        dirty = value;
        save.setEnabled(value);
        cancel.setEnabled(value);
        if (value && !message.hasMessage()) message.info("Unsaved changes.");
    }

    private void touched() {
        if (!loading && !dirty) setDirty(true);
    }

    // Marks the form dirty on any edit of a text component, toggle or combo inside the editor
    private void watch(Component c) {
        if (c instanceof JTextComponent) {
            ((JTextComponent) c).getDocument().addDocumentListener(new DocumentListener() {
                @Override public void insertUpdate(DocumentEvent e) { touched(); }
                @Override public void removeUpdate(DocumentEvent e) { touched(); }
                @Override public void changedUpdate(DocumentEvent e) { touched(); }
            });
        } else if (c instanceof JComboBox) {
            ((JComboBox<?>) c).addItemListener(e -> { if (e.getStateChange() == ItemEvent.SELECTED) touched(); });
        } else if (c instanceof AbstractButton) {
            ((AbstractButton) c).addItemListener(e -> touched());
        }
        if (c instanceof Container) {
            for (Component child : ((Container) c).getComponents()) watch(child);
        }
    }
}
