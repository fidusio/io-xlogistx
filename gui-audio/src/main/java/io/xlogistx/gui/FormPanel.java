package io.xlogistx.gui;

import net.miginfocom.swing.MigLayout;

import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import java.awt.Font;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A stacked form: a small bold label above each field, an optional muted hint below it, laid
 * out by MigLayout so every field stretches to the form's width. Rows can be collected into
 * named <b>groups</b> that show and hide together without leaving a gap
 * ({@code hidemode 3}), which is how a form reveals its first-run or advanced rows:
 * <pre>
 * FormPanel form = new FormPanel();
 * form.field("Vault password", vault);
 * form.group("firstRun", () -&gt; {
 *     form.requiredField("Operator username", operator);
 *     form.field("Database password", dbPassword, "Empty = generated and kept in the vault");
 * });
 * form.showGroup("firstRun", false);
 * </pre>
 * Any other component (a button row, an {@link InlineMessage}) goes in with {@link #row}.
 */
public class FormPanel extends JPanel {

    private final Map<String, List<JComponent>> groups = new LinkedHashMap<>();
    private final List<WrapLabel> hints = new ArrayList<>();
    private String currentGroup;

    public FormPanel() {
        super(new MigLayout("wrap 1, insets 0, gapy 2, hidemode 3, fillx", "[grow,fill]"));
        setOpaque(false);
    }

    /** Adds a labelled field. @return the label, for further styling */
    public JLabel field(String label, JComponent component) {
        return addField(label, component, null, false);
    }

    /** Adds a labelled field with a muted hint under it. */
    public JLabel field(String label, JComponent component, String hint) {
        return addField(label, component, hint, false);
    }

    /** Adds a labelled field marked required (a red asterisk after the label). */
    public JLabel requiredField(String label, JComponent component) {
        return addField(label, component, null, true);
    }

    /** Adds a labelled, required field with a hint. */
    public JLabel requiredField(String label, JComponent component, String hint) {
        return addField(label, component, hint, true);
    }

    /** Adds any component as a full-width row. */
    public <C extends JComponent> C row(C component) {
        return row(component, "growx, gaptop 6");
    }

    /** Adds any component with explicit MigLayout constraints. */
    public <C extends JComponent> C row(C component, String constraints) {
        add(component, constraints);
        register(component);
        return component;
    }

    /**
     * Runs {@code adder}, collecting every row it adds under {@code key}. Groups may be reopened:
     * a second call with the same key adds to it. Nesting records a row in the innermost group only.
     */
    public void group(String key, Runnable adder) {
        String previous = currentGroup;
        currentGroup = key;
        if (!groups.containsKey(key)) groups.put(key, new ArrayList<JComponent>());
        try {
            adder.run();
        } finally {
            currentGroup = previous;
        }
    }

    /** Shows or hides every row of a group; unknown keys are ignored. */
    public void showGroup(String key, boolean visible) {
        List<JComponent> rows = groups.get(key);
        if (rows == null) return;
        for (JComponent c : rows) c.setVisible(visible);
        revalidate();
        repaint();
    }

    /** True when the group exists and its first row is visible. */
    public boolean isGroupVisible(String key) {
        List<JComponent> rows = groups.get(key);
        return rows != null && !rows.isEmpty() && rows.get(0).isVisible();
    }

    /** The rows recorded under a group, in order; empty for an unknown key. */
    public List<JComponent> group(String key) {
        List<JComponent> rows = groups.get(key);
        return rows == null ? Collections.<JComponent>emptyList() : Collections.unmodifiableList(rows);
    }

    private JLabel addField(String label, JComponent component, String hint, boolean required) {
        JLabel l = fieldLabel(label, required);
        l.setLabelFor(component);
        add(l, "gaptop 8");
        register(l);
        add(component, "growx");
        register(component);
        if (hint != null && !hint.isEmpty()) {
            WrapLabel h = hint(hint);
            hints.add(h);
            add(h, "growx, wmin 0");
            register(h);
        }
        return l;
    }

    private void register(JComponent c) {
        if (currentGroup != null) groups.get(currentGroup).add(c);
    }

    /** The form's label style: small and bold. */
    public static JLabel fieldLabel(String text, boolean required) {
        JLabel l = new JLabel(required
                ? "<html>" + escape(text) + " <font color='#B42318'>*</font></html>"
                : text);
        l.setFont(UITokens.font(Font.BOLD, -1f));
        return l;
    }

    /** The form's hint style: small, muted, wrapping at the form's width. */
    public static WrapLabel hint(String text) {
        WrapLabel h = new WrapLabel(text);
        h.setFont(UITokens.font(Font.PLAIN, -1.5f));
        h.setForeground(UITokens.muted());
        return h;
    }

    /** Hints wrap at the width the form actually has. */
    @Override
    public void doLayout() {
        int w = getWidth();
        if (w >= 40) for (WrapLabel h : hints) h.setWrapWidth(w);
        super.doLayout();
    }

    private static String escape(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
}
