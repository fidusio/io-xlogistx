package io.xlogistx.gui.test;

import javax.swing.*;
import java.awt.*;

public class GUILayoutTest extends JFrame {
    public GUILayoutTest() {
        super("Combined Layout Example");

        // Main container uses BorderLayout
        setLayout(new BorderLayout(5, 5));

        // North panel: FlowLayout
        JPanel northPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        northPanel.add(new JLabel("North Panel: FlowLayout"));
        northPanel.add(new JButton("Button 1"));
        northPanel.add(new JButton("Button 2"));

        // Center panel: GridLayout
        JPanel centerPanel = new JPanel(new GridLayout(2, 2, 5, 5));
        centerPanel.add(new JButton("Grid1"));
        centerPanel.add(new JButton("Grid2"));
        centerPanel.add(new JButton("Grid3"));
        centerPanel.add(new JButton("Grid4"));

        // South panel: FlowLayout (centered)
        JPanel southPanel = new JPanel(new FlowLayout());
        southPanel.add(new JLabel("South Panel"));
        southPanel.add(new JButton("OK"));
        southPanel.add(new JButton("Cancel"));

        // Add sub-panels to main frame (BorderLayout)
        add(northPanel, BorderLayout.NORTH);
        add(centerPanel, BorderLayout.CENTER);
        add(southPanel, BorderLayout.SOUTH);

        setSize(400, 300);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            new GUILayoutTest().setVisible(true);
        });
    }
}

