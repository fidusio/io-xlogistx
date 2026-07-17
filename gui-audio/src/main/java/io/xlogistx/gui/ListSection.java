package io.xlogistx.gui;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

/**
 * A titled, refreshable list of rows with an "add" button and optional per-row
 * Edit/Remove actions. Rows are pulled from a {@link Supplier} on each {@link #refresh()},
 * so the caller owns the data source and this component just renders it.
 */
public class ListSection extends JPanel {
    /**
     * One row: a label plus optional Edit/Remove handlers (null hides that button).
     */
    public static final class Entry {
        private final String label;
        private final Runnable onEdit;
        private final Runnable onRemove;

        public Entry(String label, Runnable onEdit, Runnable onRemove) {
            this.label = label;
            this.onEdit = onEdit;
            this.onRemove = onRemove;
        }

        public String label() { return label; }
        public Runnable onEdit() { return onEdit; }
        public Runnable onRemove() { return onRemove; }
    }

    private final JPanel rows = new JPanel();
    private final Supplier<List<Entry>> source;

    public ListSection(String title, String addLabel, Runnable onAdd, Supplier<List<Entry>> source) {
        this.source = source;
        setLayout(new BorderLayout());
        // Plain outline (no embedded text) + padding, with the larger h2 title on top.
        setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createEtchedBorder(),
                BorderFactory.createEmptyBorder(6, 8, 6, 8)));
        add(PanelBuilder.title(title), BorderLayout.NORTH);

        rows.setLayout(new BoxLayout(rows, BoxLayout.Y_AXIS));

        if (onAdd != null) {
            JButton add = new JButton(addLabel);
            add.addActionListener(e -> onAdd.run());

            add(add, BorderLayout.SOUTH);
        }
        add(rows, BorderLayout.CENTER);

        refresh();
    }

    /**
     * Rebuilds the rows from the supplier. Call after any add/remove.
     */
    public void refresh() {
        rows.removeAll();
        for (Entry en : source.get()) {
            List<JButton> buttons = new ArrayList<>();
            if (en.onEdit() != null) {
                JButton edit = GUIUtil.iconButton(new IconUtil.EditIcon(16));
                edit.setToolTipText("Edit");
                edit.addActionListener(e -> en.onEdit().run());
                buttons.add(edit);
            }
            if (en.onRemove() != null) {
                JButton remove = GUIUtil.iconButton(new IconUtil.DeleteIcon(16));
                remove.setToolTipText("Remove");
                remove.addActionListener(e -> en.onRemove().run());
                buttons.add(remove);
            }
            rows.add(PanelBuilder.row(en.label(), buttons.toArray(new JButton[0])));
        }
        rows.revalidate();
        rows.repaint();
    }
}

