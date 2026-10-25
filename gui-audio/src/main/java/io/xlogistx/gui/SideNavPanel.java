package io.xlogistx.gui;

import com.formdev.flatlaf.FlatClientProperties;
import net.miginfocom.swing.MigLayout;

import javax.swing.AbstractButton;
import javax.swing.BorderFactory;
import javax.swing.ButtonGroup;
import javax.swing.Icon;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JToggleButton;
import javax.swing.SwingConstants;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

/**
 * The application's one navigation column: sections of flat toggle items keyed by a String,
 * one of which is selected, plus a footer slot for actions that are not pages (help, version).
 * It selects, it does not navigate: the host listens with {@link #onSelect} and shows the page,
 * and when the host navigates by itself it calls {@link #select}, which highlights the item
 * without firing, so the two never loop.
 * <pre>
 * SideNavPanel nav = new SideNavPanel();
 * nav.section("scan", "Scan");
 * nav.item("scan.new", scanIcon, "New scan");
 * nav.item("scan.history", clockIcon, "History");
 * nav.section("admin", "Admin");
 * nav.item("acl", shieldIcon, "Access control");
 * nav.setSectionVisible("admin", isAdmin);
 * nav.onSelect(key -&gt; navigator.show(key));
 * </pre>
 */
public class SideNavPanel extends JPanel {

    /** The column's width in pixels. */
    public static final int WIDTH = 232;

    private final ButtonGroup group = new ButtonGroup();
    private final Map<String, JToggleButton> items = new LinkedHashMap<>();
    private final Map<String, Section> sections = new LinkedHashMap<>();
    private final List<Consumer<String>> listeners = new ArrayList<>();
    private final JPanel body = new JPanel(new MigLayout("insets 10 12 8 12, wrap 1, gapy 2, fillx, hidemode 3", "[grow,fill]"));
    private final JPanel footer = new JPanel(new MigLayout("insets 0 12 14 12, wrap 1, gapy 2, fillx", "[grow,fill]"));
    private Section current;
    private String selected;

    private static final class Section {
        final JLabel header;
        final List<JToggleButton> items = new ArrayList<>();

        Section(JLabel header) {
            this.header = header;
        }
    }

    public SideNavPanel() {
        super(new BorderLayout());
        setBackground(UITokens.surfaceAlt());
        setBorder(BorderFactory.createMatteBorder(0, 0, 0, 1, UITokens.border()));
        setPreferredSize(new Dimension(WIDTH, 10));
        body.setOpaque(false);
        footer.setOpaque(false);
        add(body, BorderLayout.CENTER);
        add(footer, BorderLayout.SOUTH);
    }

    /** Starts a section: an uppercase muted heading; the items added next belong to it. */
    public void section(String key, String title) {
        JLabel header = new JLabel(title.toUpperCase());
        header.setFont(UITokens.font(Font.BOLD, -2f));
        header.setForeground(UITokens.muted());
        header.setBorder(BorderFactory.createEmptyBorder(12, 12, 4, 12));
        body.add(header);
        current = new Section(header);
        sections.put(key, current);
    }

    /** Adds a page item under the current section. @return the toggle, for tooltips or badges */
    public JToggleButton item(String key, Icon icon, String label) {
        JToggleButton b = new JToggleButton(label, icon);
        styleItem(b);
        b.addActionListener(e -> {
            selected = key;
            for (Consumer<String> l : listeners) l.accept(key);
        });
        group.add(b);
        items.put(key, b);
        body.add(b);
        if (current != null) current.items.add(b);
        return b;
    }

    /** Adds a footer action: styled like an item but not a page (help, about, sign out). */
    public JButton footerAction(Icon icon, String label, Runnable action) {
        JButton b = new JButton(label, icon);
        styleItem(b);
        b.setForeground(UITokens.muted());
        b.addActionListener(e -> action.run());
        footer.add(b);
        return b;
    }

    /** Adds any component to the footer (a version line, a badge). */
    public <C extends JComponent> C footer(C component) {
        footer.add(component, "growx");
        return component;
    }

    /** Called with the item key on every click. */
    public void onSelect(Consumer<String> listener) {
        listeners.add(listener);
    }

    /** Highlights an item without firing the listeners; unknown keys clear the selection. */
    public void select(String key) {
        JToggleButton b = items.get(key);
        if (b != null) {
            selected = key;
            b.setSelected(true);
        } else {
            selected = null;
            group.clearSelection();
        }
    }

    /** The selected item's key, or null. */
    public String getSelected() {
        return selected;
    }

    public void setItemVisible(String key, boolean visible) {
        JToggleButton b = items.get(key);
        if (b != null) b.setVisible(visible);
    }

    /** Shows or hides a section heading and every item under it. */
    public void setSectionVisible(String key, boolean visible) {
        Section s = sections.get(key);
        if (s == null) return;
        s.header.setVisible(visible);
        for (JToggleButton b : s.items) b.setVisible(visible);
        revalidate();
        repaint();
    }

    private static void styleItem(AbstractButton b) {
        b.setHorizontalAlignment(SwingConstants.LEFT);
        b.setIconTextGap(10);
        b.setFocusPainted(false);
        b.setFont(UITokens.font(Font.BOLD, 0f));
        b.putClientProperty(FlatClientProperties.BUTTON_TYPE, FlatClientProperties.BUTTON_TYPE_TOOLBAR_BUTTON);
        b.putClientProperty(FlatClientProperties.STYLE,
                "arc: 10; margin: 8,12,8,12;"
                        + " toolbar.hoverBackground: " + hex(UITokens.color("xlogistx.navHover", null, 0xECECF2)) + ";"
                        + " toolbar.pressedBackground: " + hex(UITokens.accentSoft()) + ";"
                        + " toolbar.selectedBackground: " + hex(UITokens.accentSoft()) + ";"
                        + " selectedForeground: " + hex(UITokens.accentText()));
        b.setMinimumSize(new Dimension(0, 36));
    }

    private static String hex(Color c) {
        return String.format("#%02X%02X%02X", c.getRed(), c.getGreen(), c.getBlue());
    }
}
