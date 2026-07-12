package io.xlogistx.gui;

import org.zoxweb.shared.util.SUS;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ItemEvent;

/**
 * Panel combining an editable combo box with add (+), delete (-) and optionally
 * update icon buttons, letting the user maintain the item list at runtime:
 * add inserts a new empty entry, delete removes the selected entry, and
 * update/Enter commits the editor text to the selected entry (or appends it as a
 * new entry when nothing is selected).
 */
public class DynamicComboBox extends JPanel {


    //private static final Logger log = LoggerFactory.getLogger(DynamicComboBox.class);
    private final JComboBox<String> comboBox;
    private final DefaultComboBoxModel<String> comboBoxModel;
    // last index that was really selected; editing the text detaches the combo's
    // selection (selectedIndex becomes -1 because the typed text is not in the model),
    // so update must fall back to this to know which item is being edited
    private int lastSelectedIndex = -1;
    //private final JTextArea contentTA;
    // final Map<String, String> contentMap = new LinkedHashMap();


    /**
     * Creates a dynamic combo box.
     *
     * @param addUpdate if true an update button is added next to add/delete
     */
    public DynamicComboBox(boolean addUpdate) {
        this(addUpdate, false);
    }

    /**
     * Creates a dynamic combo box.
     *
     * @param addUpdate          if true an update button is added next to add/delete
     * @param addContentTextArea reserved for a companion content text area (currently unused)
     */
    public DynamicComboBox(boolean addUpdate, boolean addContentTextArea) {
        // Create the model and combo box
        comboBoxModel = new DefaultComboBoxModel<>();
        comboBox = new JComboBox<>(comboBoxModel);
        comboBox.setEditable(true); // editable so the user can type new/updated entries


        comboBox.getEditor().addActionListener((e) -> handleEditorUpdate());

        comboBox.addItemListener((e) -> {
            if (e.getStateChange() == ItemEvent.SELECTED) {
                int index = comboBox.getSelectedIndex();
                if (index >= 0)
                    lastSelectedIndex = index;
            }
        });


        int size = 16;
        // Create buttons
        JButton addButton = GUIUtil.iconButton(new IconUtil.PlusIcon(size), true);

        JButton deleteButton = GUIUtil.iconButton(new IconUtil.MinusIcon(size), true);

        JButton updateButton = null;
        if (addUpdate) {
            updateButton = GUIUtil.iconButton(new IconUtil.UpdateIcon(size),  true);
        }


        JPanel buttonsPanel = new JPanel();
        buttonsPanel.setLayout(new FlowLayout(FlowLayout.LEFT, 2, 2));

        buttonsPanel.add(addButton);
        buttonsPanel.add(deleteButton);
        if (updateButton != null)
            buttonsPanel.add(updateButton);


        setLayout(new FlowLayout(FlowLayout.LEFT, 2, 2));
        add(buttonsPanel);
        add(comboBox);

        // Button Listeners
        addButton.addActionListener((e) -> handleAdd());

        deleteButton.addActionListener((e) -> removeSelectedEntry());

        if (updateButton != null)
            updateButton.addActionListener((e) -> handleEditorUpdate());


    }


    /**
     * Adds an entry from the plus button: when the editor contains text the user typed
     * (anything other than the committed selection), that text becomes the new entry;
     * otherwise a blank entry is added for the user to type over.
     */
    private void handleAdd() {
        String text = comboBox.getEditor().getItem().toString().trim();
        int selectedIndex = comboBox.getSelectedIndex();
        String selected = selectedIndex >= 0 ? comboBoxModel.getElementAt(selectedIndex) : null;

        if (!text.isEmpty() && !text.equals(selected))
            addNewEntry(text);
        else
            addNewEntry("");
    }

    /**
     * Commits the editor text: replaces the selected item when a selection exists,
     * otherwise appends the text as a new item. Empty text is ignored.
     */
    private void handleEditorUpdate() {
        // The edited text
        String newText = comboBox.getEditor().getItem().toString().trim();
        if (newText.isEmpty()) {
            return;
        }

        int selectedIndex = comboBox.getSelectedIndex();
        if (selectedIndex < 0)
            selectedIndex = lastSelectedIndex; // selection detached by the edit, use the item being edited
        if (selectedIndex >= comboBoxModel.getSize())
            selectedIndex = -1; // stale index (items were removed since)

        if (selectedIndex >= 0) {
            // User was editing an existing item
            if (!newText.equals(comboBoxModel.getElementAt(selectedIndex))) {
                comboBoxModel.removeElementAt(selectedIndex);
                comboBoxModel.insertElementAt(newText, selectedIndex);
            }
            comboBox.setSelectedIndex(selectedIndex);
        } else {
            // Nothing was ever selected -> treat as a new item
            comboBoxModel.addElement(newText);
            comboBox.setSelectedIndex(comboBoxModel.getSize() - 1);
        }
    }


    /**
     * Adds an item to the combo box (no-op insert if it already exists) and selects it.
     *
     * @param content item text to add
     * @return this widget for chaining
     */
    public DynamicComboBox addItem(String content) {

        addNewEntry(content);


        return this;
    }


    private void addNewEntry(String toAdd) {
//        if (SUS.isNotEmpty(toAdd))
        {
            int index = comboBoxModel.getIndexOf(toAdd);
            if (index == -1)
                index = comboBox.getItemCount();

            comboBoxModel.insertElementAt(toAdd, index);
            comboBox.setSelectedIndex(index);
//            contentTA.setText(contentMap.get(toAdd));
        }
    }

    /**
     * Removes the currently selected entry from the combo box, then resets the
     * selection to the first item (or clears the editor when the list is empty).
     * The explicit reselect is required: the model only auto-selects a neighbor when
     * the selected object is the same instance as the removed element, and an editor
     * commit replaces the selection with a fresh string — leaving the deleted text
     * displayed.
     */
    private void removeSelectedEntry() {
        int selectedIndex = comboBox.getSelectedIndex();
        if (selectedIndex != -1) {
            comboBoxModel.removeElementAt(selectedIndex);
            if (comboBoxModel.getSize() > 0) {
                comboBox.setSelectedIndex(0);
            } else {
                lastSelectedIndex = -1;
                comboBox.setSelectedItem(null); // clears the editor text
            }
        }
    }


    // Accessor methods if needed
//    public JComboBox<String> getComboBox() {
//        return comboBox;
//    }

    private DefaultComboBoxModel<String> getModel() {
        return comboBoxModel;
    }

    /**
     * Returns the currently selected item.
     *
     * @return the trimmed selected item text, or null if nothing is selected or it is blank
     */
    public String getSelectedItem() {
//        if(contentTA != null)
//            return SUS.trimOrNull(contentTA.getText());

        return SUS.trimOrNull((String) getModel().getSelectedItem());
    }

    /**
     * Advances the selection to the next item, wrapping back to the first item after
     * the last.
     *
     * @return the newly selected index, or -1 if the combo box is empty
     */
    public int moveNext() {
        int count = comboBox.getItemCount();
        if (count == 0)
            return -1;
        int nextIndex = comboBox.getSelectedIndex() + 1;
        if (nextIndex >= count)
            nextIndex = 0;

        comboBox.setSelectedIndex(nextIndex);
        return nextIndex;
    }
}
