package io.xlogistx.gui.test;


import javax.swing.*;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

public class AppMenuBarTest {

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            // Optional: use system look & feel
            try {
                UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            } catch (Exception ignored) {
            }

            // macOS: show menu in system menu bar (optional)
            System.setProperty("apple.laf.useScreenMenuBar", "true");
            System.setProperty("com.apple.mrj.application.apple.menu.about.name", "MyApp");

            JFrame frame = new JFrame("Standard Menu Bar Demo");
            frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            frame.setSize(600, 400);

            // Build and set the menu bar
            frame.setJMenuBar(buildMenuBar(frame));

            frame.setLocationRelativeTo(null);
            frame.setVisible(true);
        });
    }

    private static JMenuBar buildMenuBar(JFrame owner) {
        JMenuBar menuBar = new JMenuBar();

        // Platform shortcut key (Ctrl on Win/Linux, Cmd on macOS)
//        int mask = Toolkit.getDefaultToolkit()
//                .getMenuShortcutKeyMaskEx(); // Java 9+


        int mask = InputEvent.CTRL_DOWN_MASK;
        // ===== File =====
        JMenu fileMenu = new JMenu("File");
        fileMenu.setMnemonic(KeyEvent.VK_F);

        JMenuItem newItem = new JMenuItem("New");
        newItem.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_N, mask));
        newItem.addActionListener(e -> JOptionPane.showMessageDialog(owner, "New clicked"));

        JMenuItem openItem = new JMenuItem("Open…");
        openItem.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_O, mask));
        openItem.addActionListener(e -> JOptionPane.showMessageDialog(owner, "Open clicked"));

        JMenuItem saveItem = new JMenuItem("Save");
        saveItem.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_S, mask));
        saveItem.addActionListener(e -> JOptionPane.showMessageDialog(owner, "Save clicked"));

        fileMenu.add(newItem);
        fileMenu.add(openItem);
        fileMenu.add(saveItem);
        fileMenu.addSeparator();

        JMenuItem exitItem = new JMenuItem("Exit");
        exitItem.setMnemonic(KeyEvent.VK_X);
        exitItem.addActionListener(e -> owner.dispose());
        fileMenu.add(exitItem);

        // ===== Edit =====
        JMenu editMenu = new JMenu("Edit");
        editMenu.setMnemonic(KeyEvent.VK_E);

        JMenuItem cutItem = new JMenuItem("Cut");
        cutItem.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_X, mask));
        cutItem.addActionListener(e -> JOptionPane.showMessageDialog(owner, "Cut"));

        JMenuItem copyItem = new JMenuItem("Copy");
        copyItem.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_C, mask));
        copyItem.addActionListener(e -> JOptionPane.showMessageDialog(owner, "Copy"));

        JMenuItem pasteItem = new JMenuItem("Paste");
        pasteItem.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_V, mask));
        pasteItem.addActionListener(e -> JOptionPane.showMessageDialog(owner, "Paste"));

        editMenu.add(cutItem);
        editMenu.add(copyItem);
        editMenu.add(pasteItem);

        // ===== View =====
        JMenu viewMenu = new JMenu("View");
        viewMenu.setMnemonic(KeyEvent.VK_V);

        JCheckBoxMenuItem statusBar = new JCheckBoxMenuItem("Show Status Bar", true);
        statusBar.addActionListener(e ->
                JOptionPane.showMessageDialog(owner, "Status Bar: " + (statusBar.isSelected() ? "Shown" : "Hidden")));
        viewMenu.add(statusBar);

        // Radio group for zoom preset
        viewMenu.addSeparator();
        ButtonGroup zoomGroup = new ButtonGroup();
        JRadioButtonMenuItem zoom100 = new JRadioButtonMenuItem("Zoom 100%", true);
        JRadioButtonMenuItem zoom125 = new JRadioButtonMenuItem("Zoom 125%");
        JRadioButtonMenuItem zoom150 = new JRadioButtonMenuItem("Zoom 150%");
        zoomGroup.add(zoom100);
        zoomGroup.add(zoom125);
        zoomGroup.add(zoom150);

        zoom100.addActionListener(e -> JOptionPane.showMessageDialog(owner, "Zoom set to 100%"));
        zoom125.addActionListener(e -> JOptionPane.showMessageDialog(owner, "Zoom set to 125%"));
        zoom150.addActionListener(e -> JOptionPane.showMessageDialog(owner, "Zoom set to 150%"));

        viewMenu.add(zoom100);
        viewMenu.add(zoom125);
        viewMenu.add(zoom150);

        // ===== Help =====
        JMenu helpMenu = new JMenu("Help");
        helpMenu.setMnemonic(KeyEvent.VK_H);

        JMenuItem docsItem = new JMenuItem("Documentation");
        docsItem.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_F1, 0));
        docsItem.addActionListener(e -> JOptionPane.showMessageDialog(owner, "Open docs…"));

        JMenuItem aboutItem = new JMenuItem("About");
        aboutItem.addActionListener(e -> JOptionPane.showMessageDialog(owner, "MyApp v1.0"));

        helpMenu.add(docsItem);
        helpMenu.addSeparator();
        helpMenu.add(aboutItem);

        // Attach to bar
        menuBar.add(fileMenu);
        menuBar.add(editMenu);
        menuBar.add(viewMenu);
        menuBar.add(helpMenu);

        return menuBar;
    }
}
