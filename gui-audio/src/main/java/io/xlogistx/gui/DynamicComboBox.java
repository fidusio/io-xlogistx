package io.xlogistx.gui;

import org.zoxweb.shared.util.SUS;

import javax.swing.*;
import java.awt.*;

public class DynamicComboBox extends JPanel {

    private final JComboBox<String> comboBox;
    private final DefaultComboBoxModel<String> comboBoxModel;

    public DynamicComboBox() {
        // Layout for this panel
        setLayout(new BorderLayout(10, 10));

        // Create the model and combo box
        comboBoxModel = new DefaultComboBoxModel<>();
        comboBox = new JComboBox<>(comboBoxModel);
        comboBox.setEditable(true); // Use a non-editable combo box so user picks from the dropdown

        // Listen for selection changes
//        comboBox.addActionListener((e)-> {
//
//                // When user selects an item, copy it to the text field
//                if (comboBox.getSelectedIndex() != -1) {
//                    setSelectionIndex(comboBox.getSelectedIndex());
//
//            }
//        });


        comboBox.getEditor().addActionListener((e)->handleEditorUpdate());

        // Create the text field for new or updated entries
        //textField = new JTextField(15);

        // Create buttons
        JButton addButton =new JButton(GUIUtil.ADD_SIGN);//new JButton("Add");
        JButton deleteButton = new JButton(GUIUtil.DELETE_SIGN);
        JButton updateButton = new JButton(GUIUtil.UPDATE_SIGN); // NOT USED for now
        setLayout(new FlowLayout(FlowLayout.LEFT, 5, 5));
        add(addButton);
        add(deleteButton);
        //add(controlPanel);
        // Add components to the main panel
        add(comboBox);//, BorderLayout.CENTER);
        //add(textField);
       //, BorderLayout.SOUTH);

        // Set preferred size (optional)
       // setPreferredSize(new Dimension(360, 100));

        // Button Listeners
        addButton.addActionListener((e)-> addNewEntry(""));

        deleteButton.addActionListener((e)->removeSelectedEntry());
        updateButton.addActionListener((e)->handleEditorUpdate());


    }



    private void handleEditorUpdate() {
        // The edited text
        String newText = comboBox.getEditor().getItem().toString().trim();
        if (newText.isEmpty()) {
            return;
        }

        // Current selection index
        //Object currentSelection = comboBoxModel.getSelectedItem();
        int selectedIndex = comboBox.getSelectedIndex();

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

    public DynamicComboBox addItem(String item)
    {
        addNewEntry(item);
        return this;
    }

//    private void setSelectionIndex(int index)
//    {
//        comboBox.setSelectedIndex(index);
//    }


    private void addNewEntry(String toAdd)
    {
        if(toAdd != null)
        {
//            comboBoxModel.addElement(toAdd);
//            comboBox.setSelectedIndex(comboBox.getItemCount() -1);
            comboBoxModel.insertElementAt(toAdd, comboBox.getItemCount());
            comboBoxModel.setSelectedItem(toAdd);
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

    public String getSelectedItem()
    {
        return SUS.trimOrNull((String) getModel().getSelectedItem());
    }

    public int moveNext()
    {
        int count = comboBox.getItemCount();
        int nextIndex = comboBox.getSelectedIndex() + 1;
        if(nextIndex + 1 > count)
            nextIndex = 0;

        comboBox.setSelectedIndex(nextIndex);
        return  nextIndex;
    }
}
