package io.xlogistx.gui;

import javax.swing.AbstractAction;
import javax.swing.AbstractListModel;
import javax.swing.ComboBoxEditor;
import javax.swing.ComboBoxModel;
import javax.swing.InputMap;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.KeyStroke;
import javax.swing.MutableComboBoxModel;
import javax.swing.SwingUtilities;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.event.PopupMenuEvent;
import javax.swing.event.PopupMenuListener;
import javax.swing.plaf.basic.ComboPopup;
import javax.swing.text.JTextComponent;
import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

/**
 * An editable combo box that is its own filter (2026-10-28): what the subject types in the
 * editor narrows the drop-down list, so one control replaces a combo plus a search field.
 * <p>
 * Behaviour, in the order a subject meets it:
 * <ul>
 * <li>Typing filters the list through the {@link Matcher} ({@link #CONTAINS} by default, a
 * case-insensitive substring test; hosts plug their own grammar with {@link #setMatcher}) and
 * opens the popup when something matches. The matcher also sees the blank text, so a host can
 * decide what an empty filter shows (everything, or a curated subset).</li>
 * <li>Arrow keys move inside the filtered list; <b>Enter</b> takes the highlighted item, or,
 * with nothing highlighted, the typed text — an item it names exactly (ignoring case), else
 * the text itself when {@link #setFreeText free text} is allowed, else nothing changes.
 * <b>Escape</b> puts the selected item's text back. Focus leaving the editor commits the typed
 * text the same way, as any editable combo does.</li>
 * <li>Once the popup closes the filter is gone and the full list is back for the next time
 * the arrow is clicked; a programmatic {@link #setSelectedItem} while the popup is closed drops
 * it too.</li>
 * </ul>
 * {@link #addItem}, {@link #removeAllItems}, {@link #getItemCount} and {@link #getItemAt} are
 * the usual {@link JComboBox} API: the count and the items are the <em>visible</em> ones; the
 * full list is {@link #getItems()}. The selection is any list item, or a String when free text
 * is on — read it with {@link #getSelectedItem()} as with any editable combo.
 *
 * @param <T> the item type; its {@code toString()} is what the editor shows and what typed text
 *            is matched against
 */
public class FilterComboBox<T> extends JComboBox<T> {

    /** Decides whether an item stays in the list for the text typed so far. */
    public interface Matcher<T> {
        /**
         * @param typed the editor text, never null, not trimmed, possibly blank
         * @param item  a list item
         * @return true to keep the item in the drop-down
         */
        boolean matches(String typed, T item);
    }

    /** The default: a case-insensitive substring test; blank text keeps everything. */
    public static final Matcher<Object> CONTAINS = new Matcher<Object>() {
        @Override
        public boolean matches(String typed, Object item) {
            if (item == null) return false;
            String t = typed == null ? "" : typed.trim();
            return t.isEmpty() || String.valueOf(item).toLowerCase().contains(t.toLowerCase());
        }
    };

    private static final String HOOKED = "FilterComboBox.hooked";
    private static final String COMMIT = "FilterComboBox.commit";

    private final FilterModel model;
    private Matcher<? super T> matcher = CONTAINS;
    private boolean freeText;
    private boolean syncing;
    private boolean refreshingPopup;
    private boolean initialized;
    private String filter = "";

    public FilterComboBox() {
        super();
        model = new FilterModel();
        super.setModel(model);
        setEditable(true);
        addPopupMenuListener(new PopupMenuListener() {
            @Override
            public void popupMenuWillBecomeVisible(PopupMenuEvent e) {
            }

            @Override
            public void popupMenuWillBecomeInvisible(PopupMenuEvent e) {
                if (!refreshingPopup) clearFilter();
            }

            @Override
            public void popupMenuCanceled(PopupMenuEvent e) {
                // Escape: the typed text goes, the selected item's text comes back
                configureEditor(getEditor(), getSelectedItem());
            }
        });
        initialized = true;
        installEditorHooks();
    }

    /** @param items the full list, replacing what was there; the selection is cleared */
    public FilterComboBox(Collection<? extends T> items) {
        this();
        setItems(items);
    }

    // ---- configuration -------------------------------------------------------------------

    /** Replaces the rule that narrows the list; null restores {@link #CONTAINS}. */
    public void setMatcher(Matcher<? super T> matcher) {
        this.matcher = matcher != null ? matcher : CONTAINS;
        model.refilter();
    }

    public Matcher<? super T> getMatcher() {
        return matcher;
    }

    /**
     * @param freeText true lets typed text that names no item become the selection (a String),
     *                 the way a plain editable combo works; false (the default) keeps the
     *                 previous selection instead
     */
    public void setFreeText(boolean freeText) {
        this.freeText = freeText;
    }

    public boolean isFreeText() {
        return freeText;
    }

    /** The full list, filtered or not. */
    public List<T> getItems() {
        return new ArrayList<T>(model.all);
    }

    /** Replaces the full list; the filter and the selection are cleared. */
    public void setItems(Collection<? extends T> items) {
        removeAllItems();
        if (items != null) for (T item : items) addItem(item);
    }

    /** The text that is narrowing the list right now; blank when the full list shows. */
    public String getFilter() {
        return filter;
    }

    // ---- JComboBox overrides -------------------------------------------------------------

    /** Items of another model are copied in; the combo keeps its own filtering model. */
    @Override
    public void setModel(ComboBoxModel<T> aModel) {
        if (aModel == model || model == null) {
            super.setModel(aModel);
            return;
        }
        List<T> items = new ArrayList<T>();
        for (int i = 0; i < aModel.getSize(); i++) items.add(aModel.getElementAt(i));
        setItems(items);
        setSelectedItem(aModel.getSelectedItem());
    }

    @Override
    public void removeAllItems() {
        filter = "";
        model.clear();
        super.removeAllItems(); // nothing left to loop over; resets the combo's own reminder and the editor
    }

    /** The look-and-feel's writes to the editor are not typing. */
    @Override
    public void configureEditor(ComboBoxEditor anEditor, Object anItem) {
        boolean was = syncing;
        syncing = true;
        try {
            super.configureEditor(anEditor, anItem);
        } finally {
            syncing = was;
        }
    }

    @Override
    public void setEditor(ComboBoxEditor anEditor) {
        super.setEditor(anEditor);
        if (initialized) installEditorHooks();
    }

    @Override
    public void updateUI() {
        super.updateUI();
        if (initialized) installEditorHooks();
    }

    // ---- the filter ----------------------------------------------------------------------

    private void installEditorHooks() {
        ComboBoxEditor editor = getEditor();
        if (editor == null) return;
        Component c = editor.getEditorComponent();
        if (!(c instanceof JTextComponent)) return;
        final JTextComponent field = (JTextComponent) c;
        if (Boolean.TRUE.equals(field.getClientProperty(HOOKED))) return;
        field.putClientProperty(HOOKED, Boolean.TRUE);

        field.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                typed(field);
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                typed(field);
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
            }
        });

        InputMap im = field.getInputMap(JComponent.WHEN_FOCUSED);
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0), COMMIT);
        field.getActionMap().put(COMMIT, new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                commit();
            }
        });
    }

    /** A document change made by the subject: filter on the next EDT turn (a document must not be touched from its own notification). */
    private void typed(final JTextComponent field) {
        if (syncing) return;
        final String text = field.getText();
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                applyTyped(field, text);
            }
        });
    }

    private void applyTyped(JTextComponent field, String text) {
        if (!text.equals(field.getText())) return; // superseded: more typing, or a selection rewrote the editor
        filter = text;
        int caret = field.getCaretPosition();
        model.refilter();
        // the model events may have let the look-and-feel rewrite the editor with the selection
        if (!text.equals(field.getText())) {
            syncing = true;
            try {
                field.setText(text);
                field.setCaretPosition(Math.min(caret, text.length()));
            } finally {
                syncing = false;
            }
        }
        if (!isShowing() || !field.isFocusOwner()) return;
        refreshingPopup = true;
        try {
            if (isPopupVisible()) setPopupVisible(false); // the popup sizes itself when it opens
            if (model.getSize() > 0) setPopupVisible(true);
        } finally {
            refreshingPopup = false;
        }
    }

    /** Enter in the editor: the highlighted item if the popup shows one, else the typed text resolved by the model. */
    private void commit() {
        Object pick = isPopupVisible() ? highlighted() : null;
        setPopupVisible(false);
        setSelectedItem(pick != null ? pick : getEditor().getItem());
    }

    private Object highlighted() {
        Object child = getUI().getAccessibleChild(this, 0);
        return (child instanceof ComboPopup) ? ((ComboPopup) child).getList().getSelectedValue() : null;
    }

    private void clearFilter() {
        if (filter.isEmpty()) return;
        filter = "";
        model.refilter();
    }

    /** Full list, visible list and selection; typed text is resolved against the full list. */
    private class FilterModel extends AbstractListModel<T> implements MutableComboBoxModel<T> {

        private final List<T> all = new ArrayList<T>();
        private List<T> visible = new ArrayList<T>();
        private Object selected;

        void refilter() {
            int before = visible.size();
            List<T> next = new ArrayList<T>();
            for (T item : all) {
                if (matcher.matches(filter, item)) next.add(item);
            }
            visible = next;
            int span = Math.max(before, next.size());
            fireContentsChanged(this, 0, Math.max(0, span - 1));
        }

        void clear() {
            int before = visible.size();
            all.clear();
            visible = new ArrayList<T>();
            selected = null;
            if (before > 0) fireIntervalRemoved(this, 0, before - 1);
            fireContentsChanged(this, -1, -1);
        }

        private Object resolve(Object candidate) {
            if (candidate == null) return null;
            if (all.contains(candidate)) return candidate;
            if (candidate instanceof String) {
                String text = ((String) candidate).trim();
                for (T item : all) {
                    if (String.valueOf(item).equalsIgnoreCase(text)) return item;
                }
                if (text.isEmpty()) return selected;
                return freeText ? text : selected;
            }
            return freeText ? candidate : selected;
        }

        @Override
        public void setSelectedItem(Object anItem) {
            Object next = resolve(anItem);
            if (!Objects.equals(selected, next)) {
                selected = next;
                fireContentsChanged(this, -1, -1);
            }
            if (!isPopupVisible()) clearFilter(); // a pick with the list closed starts the next look-up from the full list
        }

        @Override
        public Object getSelectedItem() {
            return selected;
        }

        @Override
        public int getSize() {
            return visible.size();
        }

        @Override
        public T getElementAt(int index) {
            return (index >= 0 && index < visible.size()) ? visible.get(index) : null;
        }

        @Override
        public void addElement(T item) {
            all.add(item);
            refilter();
        }

        @Override
        public void insertElementAt(T item, int index) {
            all.add(Math.min(index, all.size()), item);
            refilter();
        }

        @Override
        public void removeElement(Object obj) {
            if (all.remove(obj)) {
                if (Objects.equals(selected, obj)) selected = null;
                refilter();
            }
        }

        @Override
        public void removeElementAt(int index) {
            T item = getElementAt(index);
            if (item != null) removeElement(item);
        }
    }
}
