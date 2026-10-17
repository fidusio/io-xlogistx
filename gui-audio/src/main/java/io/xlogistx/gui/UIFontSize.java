package io.xlogistx.gui;

import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.plaf.FontUIResource;
import java.awt.Component;
import java.awt.Font;
import java.awt.Window;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
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

    /** @param listener told the new size after each change, on the EDT */
    public static void addListener(Consumer<Float> listener) {
        if (listener != null)
            LISTENERS.add(listener);
    }

    public static void removeListener(Consumer<Float> listener) {
        LISTENERS.remove(listener);
    }
}
