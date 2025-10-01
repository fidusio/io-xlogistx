package io.xlogistx.gui;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.zoxweb.shared.util.SUS;

import javax.swing.*;
import java.awt.*;

public class DynamicComboBox extends JPanel {


    private static final Logger log = LoggerFactory.getLogger(DynamicComboBox.class);
    private final JComboBox<String> comboBox;
    private final DefaultComboBoxModel<String> comboBoxModel;
    //private final JTextArea contentTA;
    // final Map<String, String> contentMap = new LinkedHashMap();


    public DynamicComboBox(boolean addUpdate) {
        this(addUpdate, false);
    }

    public DynamicComboBox(boolean addUpdate, boolean addContentTextArea) {
        // Layout for this panel
        setLayout(new BorderLayout(10, 10));

        // Create the model and combo box
        comboBoxModel = new DefaultComboBoxModel<>();
        comboBox = new JComboBox<>(comboBoxModel);
        comboBox.setEditable(true); // Use a non-editable combo box so user picks from the dropdown



        comboBox.getEditor().addActionListener((e) -> handleEditorUpdate());


        int size = 16;
        Dimension buttonDimension = new Dimension(size, size);
        // Create buttons
        JButton addButton = GUIUtil.iconButton(new GUIUtil.PlusIcon(size));

        JButton deleteButton =GUIUtil.iconButton(new GUIUtil.MinusIcon(size));

        JButton updateButton = null;
        if (addUpdate) {
            updateButton = GUIUtil.iconButton(new GUIUtil.UpdateIcon(size));
        }


        JPanel buttonsPanel = new JPanel();
        buttonsPanel.setLayout(new FlowLayout(FlowLayout.LEFT, 2, 2));

        buttonsPanel.add(addButton);
        buttonsPanel.add(deleteButton);
        if (updateButton != null)
            buttonsPanel.add(updateButton);



//        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
        setLayout(new FlowLayout(FlowLayout.LEFT, 2, 2));
        add(buttonsPanel);
        add(comboBox);

        // Button Listeners
        addButton.addActionListener((e) -> addNewEntry(""));

        deleteButton.addActionListener((e) -> removeSelectedEntry());

        if (updateButton != null)
            updateButton.addActionListener((e) -> handleEditorUpdate());


    }


    private void handleEditorUpdate() {
        // The edited text
        int selectedIndex = comboBox.getSelectedIndex();
        String newText = comboBox.getEditor().getItem().toString().trim();
        if (newText.isEmpty()) {
            return;
        }

        // Current selection index
        //Object currentSelection = comboBoxModel.getSelectedItem();

//        System.out.println("last selected:" + lastSelected + " selected index: " + selectedIndex);

        if (selectedIndex >= 0) {
            // User was editing an existing item
            comboBoxModel.removeElementAt(selectedIndex);
            comboBoxModel.insertElementAt(newText, selectedIndex);
            comboBox.setSelectedIndex(selectedIndex);
        } else {
            // No valid selection -> treat as a new item
            comboBoxModel.addElement(newText);
            comboBox.setSelectedIndex(comboBoxModel.getSize() - 1);
        }
    }


    public DynamicComboBox addItem(String content)
    {

        addNewEntry(content);


        return this;
    }




    private void addNewEntry(String toAdd) {
//        if (SUS.isNotEmpty(toAdd))
        {
            int index = comboBoxModel.getIndexOf(toAdd);
            if(index == -1)
                index = comboBox.getItemCount();

            comboBoxModel.insertElementAt(toAdd, index);
            comboBox.setSelectedIndex(index);
//            contentTA.setText(contentMap.get(toAdd));
        }
    }

    /**
     * Removes the currently selected entry from the combo box.
     */
    private void removeSelectedEntry() {
        int selectedIndex = comboBox.getSelectedIndex();
        if (selectedIndex != -1) {
            comboBoxModel.removeElementAt(selectedIndex);
        }
    }


    // Accessor methods if needed
//    public JComboBox<String> getComboBox() {
//        return comboBox;
//    }

    private DefaultComboBoxModel<String> getModel() {
        return comboBoxModel;
    }

    public String getSelectedItem() {
//        if(contentTA != null)
//            return SUS.trimOrNull(contentTA.getText());

        return SUS.trimOrNull((String) getModel().getSelectedItem());
    }

    public int moveNext() {
        int count = comboBox.getItemCount();
        int nextIndex = comboBox.getSelectedIndex() + 1;
        if (nextIndex + 1 > count)
            nextIndex = 0;

        comboBox.setSelectedIndex(nextIndex);
        return nextIndex;
    }
}
