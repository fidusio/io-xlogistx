package io.xlogistx.gui.test;

import io.xlogistx.gui.DynamicComboBox;

import javax.swing.*;

public class DynamicComboBoxTest {
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            JFrame frame = new JFrame("Dynamic ComboBox Panel Demo");
            frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

            DynamicComboBox dynamicComboBoxPanel = new DynamicComboBox();

            // Add some initial entries (optional)
            dynamicComboBoxPanel.addItem("Option 1")
                    .addItem("Option 2")
                    .addItem("Option 3");

            frame.add(dynamicComboBoxPanel);
            frame.pack();
            frame.setLocationRelativeTo(null);  // Center on screen
            frame.setVisible(true);

            System.out.println("Selected:" + dynamicComboBoxPanel.getSelectedItem() + " " + dynamicComboBoxPanel.moveNext());


        });
    }
}
