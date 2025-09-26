package io.xlogistx.gui.test;

import io.xlogistx.gui.TreeTextWidget;

import javax.swing.*;

public class TreeTextWidgetTest{


    // Demo
    public static void main(String[] args) {

        TreeTextWidget ttw = new TreeTextWidget("Prompts");
        SwingUtilities.invokeLater(() -> {
            JFrame f = new JFrame("Tree + Text Editor Widget");
            f.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            f.setContentPane(ttw);
            f.pack();
            f.setLocationRelativeTo(null);
            f.setVisible(true);

        });

        ttw.addEntry(null, "gpt", "");
        ttw.addEntry("gpt","Programmatic Node-1", "This node was added with addEntry(1).");
        ttw.addEntry("gpt","Programmatic Node-2", "This node was added with addEntry(2).");
    }
}


