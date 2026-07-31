package io.xlogistx.gui;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.function.Function;
import java.util.function.Supplier;


/**
 * A bordered panel with a title, optional add button and optional search bar, over a
 * refreshable list of rows. Each row shows an item's label plus per-row action buttons.
 * Built via {@link #of(Supplier)}.
 *
 * @see #of(Supplier)
 */
public class ListSection<T> extends JPanel {

    /**
     * A per-row button: an icon, its tooltip, and a handler that maps an item to the
     * action to run when the button is clicked. The handler returning null hides the
     * button for that item.
     */
    public static class RowAction<T> {
        private final Icon icon;
        private final String tooltip;
        private final Function<T, Runnable> handler;

        public RowAction(Icon icon, String tooltip, Function<T, Runnable> handler) {
            this.icon = icon;
            this.tooltip = tooltip;
            this.handler = handler;
        }

        public static <T> RowAction<T> edit(Function<T, Runnable> handler) {
            return new RowAction<>(new IconUtil.EditIcon(16), "Edit", handler);
        }

        public static <T> RowAction<T> remove(Function<T, Runnable> handler) {
            return new RowAction<>(new IconUtil.DeleteIcon(16), "Remove", handler);
        }
    }

    private final JPanel rows = new JPanel();
    private final Supplier<List<T>> source;
    private final Function<T, String> labelFunction;
    private final List<RowAction<T>> actions;
    private final String emptyText;
    private final JTextField searchField;

    private ListSection(Builder<T> b) {
        this.source = b.source;
        this.labelFunction = Objects.requireNonNull(b.labelFunction, "Label cannot be null");
        this.actions = b.actions;
        this.emptyText = b.emptyText;

        setLayout(new BorderLayout());

        JPanel header = new JPanel();
        header.setLayout(new BoxLayout(header, BoxLayout.Y_AXIS));

        JPanel titleRow = new JPanel(new BorderLayout());
        titleRow.add(PanelBuilder.title(b.title), BorderLayout.WEST);

        setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createEtchedBorder(),
                BorderFactory.createEmptyBorder(6, 8, 6, 8)));

        if (b.onAdd != null) {
            JButton add = new JButton(b.addLabel);
            add.addActionListener(e -> b.onAdd.run());

            titleRow.add(add, BorderLayout.EAST);
        }

        header.add(titleRow);

        if (b.search) {
            searchField = PanelBuilder.textField(b.searchPlaceholder);
            searchField.putClientProperty("JTextField.leadingIcon", new IconUtil.SearchIcon(16));
            searchField.getDocument().addDocumentListener(new DocumentListener() {
                @Override public void insertUpdate(DocumentEvent e) { refresh(); }
                @Override public void removeUpdate(DocumentEvent e) { refresh(); }
                @Override public void changedUpdate(DocumentEvent e) { refresh(); }
            });
            header.add(Box.createVerticalStrut(4));
            header.add(searchField);
            header.add(Box.createVerticalStrut(4));
        } else {
            searchField = null;
        }

        header.add(separator());

        add(header, BorderLayout.NORTH);

        rows.setLayout(new BoxLayout(rows, BoxLayout.Y_AXIS));
        add(rows, BorderLayout.CENTER);

        refresh();
    }

    /**
     * A horizontal separator whose max height is pinned to its preferred height, so
     * BoxLayout can't stretch it vertically when the panel is taller than its content.
     */
    private static JSeparator separator() {
        JSeparator sep = new JSeparator();
        sep.setMaximumSize(new Dimension(Integer.MAX_VALUE, sep.getPreferredSize().height));
        return sep;
    }

    /**
     * Starts building a {@link ListSection} for the given item source. {@code source}
     * is supplied here; {@code label} is required before {@link Builder#build()}.
     * Everything else is optional.
     * <p>
     * Example Usage:
     * <pre>{@code
     * ListSection<Server> section = ListSection.of(this::getServers)
     *       .title("Servers")
     *       .addButton("Add", this::addServer)
     *       .label(Server::getName)
     *       .action(new ListSection.RowAction<>(new IconUtil.CopyIcon(16), "Copy", s -> () -> copy(s)))
     *       .onEdit(s -> () -> edit(s))
     *       .onRemove(s -> () -> remove(s))
     *       .search("Search servers")
     *       .emptyText("No servers")
     *       .build();
     * }</pre>
     */
    public static <T> Builder<T> of(Supplier<List<T>> source) {
        return new Builder<>(source);
    }

    public void refresh() {
        rows.removeAll();
        List<T> items = (source != null) ? source.get() : null;
        boolean noItems = (items == null || items.isEmpty());

        List<T> matches = noItems ? new ArrayList<>() : filter(items);

        if (matches.isEmpty()) {
            JLabel empty = new JLabel(noItems ? emptyText : "No matches");
            empty.setEnabled(false);
            empty.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));
            rows.add(empty);
        }

        for (int i = 0; i < matches.size(); i++) {
            T item = matches.get(i);
            List<JButton> buttons = new ArrayList<>();

            for (RowAction<T> action : actions) {
                Runnable r = (action.handler != null) ? action.handler.apply(item) : null;
                if (r != null) {
                    JButton b = GUIUtil.iconButton(action.icon);
                    b.setToolTipText(action.tooltip);
                    b.addActionListener(e -> r.run());
                    buttons.add(b);
                }
            }

            if (i > 0)
                rows.add(separator());
            rows.add(PanelBuilder.row(labelFunction.apply(item), buttons.toArray(new JButton[0])));
        }
        rows.revalidate();
        rows.repaint();
    }

    /**
     * Items whose label contains the search text (case-insensitive). All items when the
     * search bar is absent or blank.
     */
    private List<T> filter(List<T> items) {
        String query = (searchField != null) ? searchField.getText().trim().toLowerCase() : "";
        if (query.isEmpty())
            return items;

        List<T> matches = new ArrayList<>();
        for (T item : items) {
            String label = labelFunction.apply(item);
            if (label != null && label.toLowerCase().contains(query))
                matches.add(item);
        }
        return matches;
    }

    /**
     * Fluent builder for {@link ListSection}; obtained from {@link ListSection#of(Supplier)},
     * which carries the usage example.
     */
    public static class Builder<T> {
        private final Supplier<List<T>> source;
        private final List<RowAction<T>> actions = new ArrayList<>();
        private String title;
        private String addLabel;
        private Runnable onAdd;
        private Function<T, String> labelFunction;
        private String emptyText = "No items";
        private boolean search;
        private String searchPlaceholder = "Search";

        private Builder(Supplier<List<T>> source) {
            this.source = source;
        }

        /**
         * The title at the top left of the panel.
         */
        public Builder<T> title(String title) {
            this.title = title;
            return this;
        }

        /**
         * Adds the top-right add button; without this call no add button is shown.
         */
        public Builder<T> addButton(String addLabel, Runnable onAdd) {
            this.addLabel = addLabel;
            this.onAdd = onAdd;
            return this;
        }

        /**
         * Maps an item to its row label text. Required.
         */
        public Builder<T> label(Function<T, String> labelFunction) {
            this.labelFunction = labelFunction;
            return this;
        }

        /**
         * Appends a per-row action button (order preserved in the row).
         */
        public Builder<T> action(RowAction<T> action) {
            this.actions.add(action);
            return this;
        }

        /**
         * Convenience for {@code action(RowAction.edit(handler))}.
         */
        public Builder<T> onEdit(Function<T, Runnable> handler) {
            return action(RowAction.edit(handler));
        }

        /**
         * Convenience for {@code action(RowAction.remove(handler))}.
         */
        public Builder<T> onRemove(Function<T, Runnable> handler) {
            return action(RowAction.remove(handler));
        }

        /**
         * Text shown when the source is null or empty. Defaults to "No items".
         */
        public Builder<T> emptyText(String emptyText) {
            this.emptyText = emptyText;
            return this;
        }

        /**
         * Adds a search bar under the title that filters rows as you type
         * (case-insensitive match against the row label); without this call no
         * search bar is shown.
         */
        public Builder<T> search() {
            return search("Search");
        }

        /**
         * Same as {@link #search()} with a custom placeholder text.
         */
        public Builder<T> search(String placeholder) {
            this.search = true;
            this.searchPlaceholder = placeholder;
            return this;
        }

        public ListSection<T> build() {
            return new ListSection<>(this);
        }
    }
}