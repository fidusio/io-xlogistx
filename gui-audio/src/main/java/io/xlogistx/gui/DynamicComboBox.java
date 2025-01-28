package io.xlogistx.gui;

import org.zoxweb.shared.util.SUS;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;

public class DynamicComboBox extends JPanel {

    private JComboBox<String> comboBox;
    private DefaultComboBoxModel<String> comboBoxModel;
    private JTextField textField;
    private JButton addButton;
    private JButton deleteButton;
    private JButton updateButton;

    public DynamicComboBox() {
        // Layout for this panel
        setLayout(new BorderLayout(10, 10));

        // Create the model and combo box
        comboBoxModel = new DefaultComboBoxModel<>();
        comboBox = new JComboBox<>(comboBoxModel);
        comboBox.setEditable(false); // Use a non-editable combo box so user picks from the dropdown

        // Listen for selection changes
        comboBox.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // When user selects an item, copy it to the text field
                if (comboBox.getSelectedIndex() != -1) {
                    setSelectionIndex(comboBox.getSelectedIndex());
//                    String selectedItem = (String) comboBox.getSelectedItem();
//                    textField.setText(selectedItem);
                }
            }
        });

        // Create the text field for new or updated entries
        textField = new JTextField(15);

        // Create buttons
        addButton = new JButton("Add");
        deleteButton = new JButton("Delete");
        updateButton = new JButton("Update");

        // Panel for controls (text field + buttons)
        JPanel controlPanel = new JPanel();
        controlPanel.setLayout(new FlowLayout(FlowLayout.LEFT, 5, 5));
       // controlPanel.add(textField);
        controlPanel.add(updateButton);
        controlPanel.add(addButton);
        controlPanel.add(deleteButton);
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));


        // Add components to the main panel
        add(comboBox);//, BorderLayout.CENTER);
        add(textField);
        add(controlPanel);//, BorderLayout.SOUTH);

        // Set preferred size (optional)
       // setPreferredSize(new Dimension(360, 100));

        // Button Listeners
        addButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                addNewEntry(null);
            }
        });

        deleteButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                removeSelectedEntry();
            }
        });

        updateButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                updateSelectedEntry();
            }
        });
    }

    public DynamicComboBox addItem(String item)
    {
        addNewEntry(item);
        return this;
    }

    private void setSelectionIndex(int index)
    {
        comboBox.setSelectedIndex(index);
        String selectedItem = (String) comboBox.getSelectedItem();
        textField.setText(selectedItem);
    }

    /**
     * Adds a new entry to the combo box from textField content.
     */
    private void addNewEntry(String toAdd) {
        if(toAdd == null)
            toAdd = textField.getText().trim();
        if (!toAdd.isEmpty()) {
            comboBoxModel.addElement(toAdd);
            textField.setText("");
        }
    }

    /**
     * Removes the currently selected entry from the combo box.
     */
    private void removeSelectedEntry() {
        int selectedIndex = comboBox.getSelectedIndex();
        if (selectedIndex != -1) {
            comboBoxModel.removeElementAt(selectedIndex);
            textField.setText("");
        }
    }

    /**
     * Updates the currently selected entry with the text in textField.
     */
    private void updateSelectedEntry() {
        int selectedIndex = comboBox.getSelectedIndex();
        if (selectedIndex != -1) {
            String updatedText = textField.getText().trim();
            if (!updatedText.isEmpty()) {
                comboBoxModel.removeElementAt(selectedIndex);
                comboBoxModel.insertElementAt(updatedText, selectedIndex);
                comboBox.setSelectedIndex(selectedIndex);
            }
        }
    }

    // Accessor methods if needed
    public JComboBox<String> getComboBox() {
        return comboBox;
    }

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

        setSelectionIndex(nextIndex);
        return  nextIndex;
    }

    // Demo main method
//    public static void main(String[] args) {
//        SwingUtilities.invokeLater(() -> {
//            JFrame frame = new JFrame("Dynamic ComboBox Panel Demo");
//            frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
//
//            DynamicComboBox dynamicComboBoxPanel = new DynamicComboBox();
//
//            // Add some initial entries (optional)
//            dynamicComboBoxPanel.getModel().addElement("Option 1");
//            dynamicComboBoxPanel.getModel().addElement("Option 2");
//            dynamicComboBoxPanel.getModel().addElement("Option 3");
//
//            frame.add(dynamicComboBoxPanel);
//            frame.pack();
//            frame.setLocationRelativeTo(null);  // Center on screen
//            frame.setVisible(true);
//        });
//    }
}
