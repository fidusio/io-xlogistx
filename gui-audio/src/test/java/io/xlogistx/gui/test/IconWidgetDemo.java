package io.xlogistx.gui.test;

import io.xlogistx.gui.GUIUtil;
import io.xlogistx.gui.IconUtil;

import javax.swing.*;
import java.awt.*;

/**
 * Visual demo of all IconUtil IconWidget icons (Plus, Minus, Save, Cancel, Update, Edit,
 * Delete, Back, Visible, Invisible, Copy, Search, Refresh) rendered at multiple sizes,
 * both as raw icons and as icon buttons. The SVG-based icons appear twice as buttons:
 * with the svg's own colors (single-int constructor) and tinted white on their
 * background color (two-arg constructor).
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
                        labeled("Delete", new IconUtil.DeleteIcon(size)),
                        labeled("Back", new IconUtil.BackIcon(size)),
                        labeled("Next", new IconUtil.NextIcon(size)),
                        labeled("Rollback", new IconUtil.RollbackIcon(size)),
                        labeled("Visible", new IconUtil.VisibleIcon(size)),
                        labeled("Invisible", new IconUtil.InvisibleIcon(size)),
                        labeled("Copy", new IconUtil.CopyIcon(size)),
                        labeled("Search", new IconUtil.SearchIcon(size)),
                        labeled("Refresh", new IconUtil.RefreshIcon(size))));
            }

            // as buttons, svg icons with their own default colors
            frame.add(GUIUtil.createPanel("Buttons (24)", new FlowLayout(FlowLayout.LEFT, 10, 5),
                    GUIUtil.iconButton(new IconUtil.PlusIcon(24), true),
                    GUIUtil.iconButton(new IconUtil.MinusIcon(24),true),
                    GUIUtil.iconButton(new IconUtil.SaveIcon(24), true),
                    GUIUtil.iconButton(new IconUtil.CancelIcon(24), true),
                    GUIUtil.iconButton(new IconUtil.UpdateIcon(24), true),
                    GUIUtil.iconButton(new IconUtil.EditIcon(24), true),
                    GUIUtil.iconButton(new IconUtil.DeleteIcon(24), true),
                    GUIUtil.iconButton(new IconUtil.BackIcon(24), true),
                    GUIUtil.iconButton(new IconUtil.NextIcon(24), true),
                    GUIUtil.iconButton(new IconUtil.RollbackIcon(24), true),
                    GUIUtil.iconButton(new IconUtil.VisibleIcon(24), true),
                    GUIUtil.iconButton(new IconUtil.InvisibleIcon(24), true),
                    GUIUtil.iconButton(new IconUtil.CopyIcon(24), true),
                    GUIUtil.iconButton(new IconUtil.SearchIcon(24), true),
                    GUIUtil.iconButton(new IconUtil.RefreshIcon(24), true)));

            // as buttons, svg icons tinted white on their background color
            frame.add(GUIUtil.createPanel("Tinted buttons (24)", new FlowLayout(FlowLayout.LEFT, 10, 5),
                    GUIUtil.iconButton(new IconUtil.PlusIcon(24, Color.WHITE), true),
                    GUIUtil.iconButton(new IconUtil.MinusIcon(24, Color.WHITE), true),
                    GUIUtil.iconButton(new IconUtil.CancelIcon(24, Color.WHITE), true),
                    GUIUtil.iconButton(new IconUtil.SaveIcon(24, Color.WHITE), true),
                    GUIUtil.iconButton(new IconUtil.UpdateIcon(24, Color.WHITE), true),
                    GUIUtil.iconButton(new IconUtil.EditIcon(24, Color.WHITE), true),
                    GUIUtil.iconButton(new IconUtil.DeleteIcon(24, Color.WHITE), true),
                    GUIUtil.iconButton(new IconUtil.BackIcon(24, Color.WHITE), true),
                    GUIUtil.iconButton(new IconUtil.NextIcon(24, Color.WHITE), true),
                    GUIUtil.iconButton(new IconUtil.RollbackIcon(24, Color.WHITE), true),
                    GUIUtil.iconButton(new IconUtil.VisibleIcon(24, Color.WHITE), true),
                    GUIUtil.iconButton(new IconUtil.InvisibleIcon(24, Color.WHITE), true),
                    GUIUtil.iconButton(new IconUtil.CopyIcon(24, Color.WHITE), true),
                    GUIUtil.iconButton(new IconUtil.SearchIcon(24, Color.WHITE), true),
                    GUIUtil.iconButton(new IconUtil.RefreshIcon(24, Color.WHITE), true)));

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
