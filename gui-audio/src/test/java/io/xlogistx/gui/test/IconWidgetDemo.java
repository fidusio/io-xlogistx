package io.xlogistx.gui.test;

import io.xlogistx.gui.GUIUtil;
import io.xlogistx.gui.IconUtil;

import javax.swing.*;
import java.awt.*;

/**
 * Visual demo of all IconUtil IconWidget icons (Plus, Minus, Save, Cancel, Update, Edit, Delete)
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
                        labeled("Plus", new IconUtil.PlusIcon(size)),
                        labeled("Minus", new IconUtil.MinusIcon(size)),
                        labeled("Save", new IconUtil.SaveIcon(size)),
                        labeled("Cancel", new IconUtil.CancelIcon(size)),
                        labeled("Update", new IconUtil.UpdateIcon(size)),
                        labeled("Edit", new IconUtil.EditIcon(size)),
                        labeled("Delete", new IconUtil.DeleteIcon(size))));
            }

            // as buttons, the typical usage
            frame.add(GUIUtil.createPanel("Buttons (24)", new FlowLayout(FlowLayout.LEFT, 10, 5),
                    GUIUtil.iconButton(new IconUtil.PlusIcon(24), true),
                    GUIUtil.iconButton(new IconUtil.MinusIcon(24),true),
                    GUIUtil.iconButton(new IconUtil.SaveIcon(24), true),
                    GUIUtil.iconButton(new IconUtil.CancelIcon(24), true),
                    GUIUtil.iconButton(new IconUtil.UpdateIcon(24), true),
                    GUIUtil.iconButton(new IconUtil.EditIcon(24), true),
                    GUIUtil.iconButton(new IconUtil.DeleteIcon(24), true)));

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
