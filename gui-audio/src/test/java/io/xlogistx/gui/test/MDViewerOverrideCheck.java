package io.xlogistx.gui.test;

import io.xlogistx.gui.MDViewerPanel;

import javax.swing.*;
import java.awt.*;

/**
 * Headless-style verification of {@link MDViewerPanel#overrideScrollPane(JScrollPane)}
 * and {@link MDViewerPanel#overrideScrollPane(JScrollPane, String)}: no window is
 * shown, all assertions run on the EDT and the process exits 0 on success,
 * non-zero with an {@link AssertionError} on failure.
 */
public class MDViewerOverrideCheck {

    public static void main(String[] args) throws Exception {
        SwingUtilities.invokeAndWait(MDViewerOverrideCheck::run);
        System.out.println("ALL OK");
        System.exit(0);
    }

    static void run() {
        MDViewerPanel panel = new MDViewerPanel("# hello");

        // initial state: internal scroll pane hosts the viewer inside the panel
        JScrollPane original = panel.getScrollPane();
        assertTrue(original != null, "initial scroll pane present");
        assertTrue(original.getViewport().getView() == panel.getEditorPane(), "viewer in initial viewport");
        assertTrue(original.getParent() == panel, "initial scroll pane inside panel");

        // default override -> CENTER
        JScrollPane custom = new JScrollPane();
        custom.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        MDViewerPanel ret = panel.overrideScrollPane(custom);
        assertTrue(ret == panel, "fluent return");
        assertTrue(panel.getScrollPane() == custom, "getScrollPane returns override");
        assertTrue(custom.getViewport().getView() == panel.getEditorPane(), "viewer moved to new viewport");
        assertTrue(custom.getParent() == panel, "new scroll pane inside panel");
        assertTrue(original.getParent() == null, "old scroll pane detached");
        assertTrue(panel.getComponentCount() == 1, "panel holds exactly one child");
        BorderLayout layout = (BorderLayout) panel.getLayout();
        assertTrue(layout.getLayoutComponent(BorderLayout.CENTER) == custom, "override at CENTER");

        // positional override -> NORTH
        JScrollPane north = new JScrollPane();
        panel.overrideScrollPane(north, BorderLayout.NORTH);
        assertTrue(panel.getScrollPane() == north, "second override wins");
        assertTrue(north.getViewport().getView() == panel.getEditorPane(), "viewer moved again");
        assertTrue(custom.getParent() == null, "previous override detached");
        assertTrue(layout.getLayoutComponent(BorderLayout.NORTH) == north, "override at NORTH");
        assertTrue(panel.getComponentCount() == 1, "still exactly one child");

        // content still renders through the overridden scroll pane
        panel.setMarkdown("# after override\nstill **works**");
        assertTrue(panel.getEditorPane().getDocument().getLength() > 0, "content rendered after override");

        // null guards
        assertThrows(() -> panel.overrideScrollPane(null), "null scroll pane rejected");
        assertThrows(() -> panel.overrideScrollPane(new JScrollPane(), null), "null position rejected");
        assertTrue(panel.getScrollPane() == north, "state unchanged after rejected calls");

        System.out.println("all override assertions passed");
    }

    static void assertTrue(boolean condition, String label) {
        if (!condition)
            throw new AssertionError(label);
        System.out.println(label + " OK");
    }

    static void assertThrows(Runnable r, String label) {
        try {
            r.run();
        } catch (NullPointerException e) {
            System.out.println(label + " OK (" + e.getMessage() + ")");
            return;
        }
        throw new AssertionError(label + ": expected NullPointerException");
    }
}
