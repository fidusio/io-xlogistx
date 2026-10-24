package io.xlogistx.gui;

import javax.swing.JComponent;
import javax.swing.JMenu;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.plaf.FontUIResource;
import java.awt.Component;
import java.awt.Container;
import java.awt.Font;
import java.awt.Window;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.WeakHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

/**
 * The text size of the controls (menus, buttons, labels, fields, tooltips):
 * one setting a user can turn up or down. {@link #apply} scales every font
 * the look and feel defines, keeping their proportions (a title font stays
 * bigger than a label font), refreshes every open window and tells the
 * {@linkplain #addListener listeners}, so components that set their own font
 * can derive it again. The base is the look and feel's label size, read on
 * first use (never in a static initializer). Call on the EDT.
 */
public final class UIFontSize {

    /** The smallest and largest size allowed, in points. */
    public static final float MIN = 8f, MAX = 32f;
    /** What one Larger / Smaller step changes the size by. */
    public static final float STEP = 1f;

    private static final Map<Object, Font> ORIGINALS = new HashMap<>();
    private static final List<Consumer<Float>> LISTENERS = new CopyOnWriteArrayList<>();
    private static float base = -1f, current = -1f;

    private UIFontSize() {
    }

    /** @return the look and feel's own label size, the size {@link #reset()} goes back to */
    public static synchronized float getBase() {
        if (base < 0) {
            Font f = UIManager.getFont("Label.font");
            base = f == null ? 12f : f.getSize2D();
        }
        return base;
    }

    /** @return the size in force (the base until {@link #apply} was called) */
    public static synchronized float get() {
        return current < 0 ? getBase() : current;
    }

    /** @return the size kept within {@link #MIN} and {@link #MAX} */
    public static float clamp(float size) {
        return Math.max(MIN, Math.min(MAX, size));
    }

    /**
     * Sets the control text size: every font of the look and feel is scaled
     * by {@code size / base}, every open window is refreshed and the listeners
     * are told. Nothing happens when the size is the one in force.
     *
     * @param size the label size in points, clamped to {@link #MIN}..{@link #MAX}
     * @return the size in force afterwards
     */
    public static float apply(float size) {
        float s = clamp(size);
        synchronized (UIFontSize.class) {
            float factor = s / getBase();
            if (ORIGINALS.isEmpty()) {
                Set<Object> keys = new LinkedHashSet<>(UIManager.getLookAndFeelDefaults().keySet());
                keys.addAll(new ArrayList<>(UIManager.getDefaults().keySet()));
                for (Object key : keys) {
                    Object v = UIManager.get(key);
                    if (v instanceof Font)
                        ORIGINALS.put(key, (Font) v);
                }
            }
            if (s == current)
                return s;
            for (Map.Entry<Object, Font> e : ORIGINALS.entrySet()) {
                Font f = e.getValue();
                UIManager.put(e.getKey(), new FontUIResource(f.deriveFont(f.getSize2D() * factor)));
            }
            current = s;
        }
        for (Window w : Window.getWindows())
            refresh(w);
        for (Consumer<Float> l : LISTENERS)
            l.accept(s);
        return s;
    }

    /** One step bigger. @return the size in force afterwards */
    public static float larger() {
        return apply(get() + STEP);
    }

    /** One step smaller. @return the size in force afterwards */
    public static float smaller() {
        return apply(get() - STEP);
    }

    /** Back to the look and feel's own size. @return that size */
    public static float reset() {
        return apply(getBase());
    }

    /**
     * Makes a component tree pick up the current fonts (what {@link #apply}
     * does for every open window; for a tree that is not in a window yet).
     *
     * @param root the tree's root, never null
     */
    public static void refresh(Component root) {
        SwingUtilities.updateComponentTreeUI(root);
        root.invalidate();
        root.validate();
        root.repaint();
    }

    // ------------------------------------------------------------- one tree only

    /**
     * Client property a {@link JComponent} sets to {@link Boolean#TRUE} to keep
     * itself and its subtree out of a {@linkplain #apply(Component, float) scoped}
     * scaling — the {@link FontSizeWidget} does, being the knob and not a sample.
     */
    public static final String PINNED = "UIFontSize.pinned";

    private static final Map<Component, Font> ORIGINAL_FONTS = new WeakHashMap<>();
    private static final Map<Component, Float> SCOPED = new WeakHashMap<>();

    /**
     * Sets the control text size of <b>one component tree</b> and nothing else:
     * a viewer embedded in a host application scales its own controls without
     * touching the host, and the host's {@link #apply(float)} does not touch
     * the viewer afterwards. Every component under {@code root} gets a plain
     * (non-{@code UIResource}) font, its original scaled by {@code size / base},
     * which the look and feel's refresh leaves alone; subtrees marked
     * {@link #PINNED} are skipped. Setting the base size restores the original
     * fonts, so the tree follows the look and feel again. Call on the EDT.
     *
     * @param root the tree's root, never null
     * @param size the label size in points, clamped to {@link #MIN}..{@link #MAX}
     * @return the size in force for that tree afterwards
     */
    public static float apply(Component root, float size) {
        float s = clamp(size);
        float factor = s / getBase();
        boolean atBase = Math.abs(factor - 1f) < 0.001f;
        synchronized (UIFontSize.class) {
            scale(root, factor, atBase);
            if (atBase)
                SCOPED.remove(root);
            else
                SCOPED.put(root, s);
        }
        if (atBase)
            refresh(root); // back on UIResource fonts: pick up whatever the look and feel has now
        else {
            root.invalidate();
            root.validate();
            root.repaint();
        }
        return s;
    }

    /**
     * @param root a tree's root
     * @return the size {@link #apply(Component, float)} set on it, else the
     *         {@linkplain #get() application size} it follows
     */
    public static float get(Component root) {
        synchronized (UIFontSize.class) {
            Float s = SCOPED.get(root);
            return s != null ? s : get();
        }
    }

    private static void scale(Component c, float factor, boolean atBase) {
        if (c instanceof JComponent && Boolean.TRUE.equals(((JComponent) c).getClientProperty(PINNED)))
            return;
        Font original = ORIGINAL_FONTS.get(c);
        if (original == null) {
            original = c.getFont();
            if (original != null)
                ORIGINAL_FONTS.put(c, original);
        }
        if (original != null) {
            if (atBase) {
                c.setFont(original);
                ORIGINAL_FONTS.remove(c);
            } else
                c.setFont(new Font(original.getAttributes()).deriveFont(original.getSize2D() * factor));
        }
        if (c instanceof Container)
            for (Component child : ((Container) c).getComponents())
                scale(child, factor, atBase);
        if (c instanceof JMenu)
            for (Component child : ((JMenu) c).getMenuComponents())
                scale(child, factor, atBase);
    }

    /** @param listener told the new size after each change, on the EDT */
    public static void addListener(Consumer<Float> listener) {
        if (listener != null)
            LISTENERS.add(listener);
    }

    public static void removeListener(Consumer<Float> listener) {
        LISTENERS.remove(listener);
    }
}
