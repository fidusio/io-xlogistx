package io.xlogistx.gui.test;

import io.xlogistx.gui.GUIUtil;

import javax.swing.*;
import java.awt.*;

/**
 * Visual demo of all GUIUtil IconWidget icons (Plus, Minus, Save, Cancel, Update, Edit, Delete)
 * rendered at multiple sizes, both as raw icons and as icon buttons.
 */
public class IconWidgetDemo {

    private static final int[] SIZES = {16, 24, 32, 48};

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            JFrame frame = new JFrame("IconWidget Demo");
            frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            frame.setLayout(new GridLayout(0, 1, 5, 5));

            for (int size : SIZES) {
                frame.add(GUIUtil.createPanel("Size " + size, new FlowLayout(FlowLayout.LEFT, 10, 5),
                        labeled("Plus", new GUIUtil.PlusIcon(size)),
                        labeled("Minus", new GUIUtil.MinusIcon(size)),
                        labeled("Save", new GUIUtil.SaveIcon(size)),
                        labeled("Cancel", new GUIUtil.CancelIcon(size)),
                        labeled("Update", new GUIUtil.UpdateIcon(size)),
                        labeled("Edit", new GUIUtil.EditIcon(size)),
                        labeled("Delete", new GUIUtil.DeleteIcon(size))));
            }

            // as buttons, the typical usage
            frame.add(GUIUtil.createPanel("Buttons (24)", new FlowLayout(FlowLayout.LEFT, 10, 5),
                    GUIUtil.iconButton(new GUIUtil.PlusIcon(24)),
                    GUIUtil.iconButton(new GUIUtil.MinusIcon(24)),
                    GUIUtil.iconButton(new GUIUtil.SaveIcon(24)),
                    GUIUtil.iconButton(new GUIUtil.CancelIcon(24)),
                    GUIUtil.iconButton(new GUIUtil.UpdateIcon(24)),
                    GUIUtil.iconButton(new GUIUtil.EditIcon(24)),
                    GUIUtil.iconButton(new GUIUtil.DeleteIcon(24))));

            frame.pack();
            frame.setLocationRelativeTo(null);
            frame.setVisible(true);
        });
    }

    private static JComponent labeled(String name, Icon icon) {
        JLabel label = new JLabel(name, icon, SwingConstants.LEFT);
        label.setOpaque(true);
        return label;
    }
}
