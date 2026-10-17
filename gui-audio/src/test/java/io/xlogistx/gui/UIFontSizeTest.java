package io.xlogistx.gui;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import java.util.concurrent.Callable;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Headless tests of the control text size: every look-and-feel font scales in
 * proportion, existing trees are refreshed on request, new components get the
 * size, listeners and the spinner widget follow, reset goes back to the base.
 */
public class UIFontSizeTest {

    @BeforeAll
    static void headless() {
        System.setProperty("java.awt.headless", "true");
    }

    @AfterEach
    void reset() throws Exception {
        onEDT(UIFontSize::reset);
    }

    @Test
    void scalesEveryFontInProportionAndRefreshesTrees() throws Exception {
        float base = UIFontSize.getBase();
        assertEquals(base, UIFontSize.get(), 0.01);
        float label0 = UIManager.getFont("Label.font").getSize2D();
        float button0 = UIManager.getFont("Button.font").getSize2D();
        float title0 = UIManager.getFont("InternalFrame.titleFont") == null ? -1 : UIManager.getFont("InternalFrame.titleFont").getSize2D();

        JPanel tree = onEDT(() -> {
            JPanel p = new JPanel();
            p.add(new JLabel("old"));
            p.add(new JButton("old"));
            return p;
        });
        float[] seen = new float[1];
        UIFontSize.addListener(s -> seen[0] = s);

        assertEquals(base + 4, onEDT(() -> UIFontSize.apply(base + 4)), 0.01);
        assertEquals(base + 4, UIFontSize.get(), 0.01);
        assertEquals(base + 4, seen[0], 0.01, "listeners hear the new size");
        float factor = (base + 4) / base;
        assertEquals(label0 * factor, UIManager.getFont("Label.font").getSize2D(), 0.01);
        assertEquals(button0 * factor, UIManager.getFont("Button.font").getSize2D(), 0.01);
        if (title0 > 0)
            assertEquals(title0 * factor, UIManager.getFont("InternalFrame.titleFont").getSize2D(), 0.01, "proportions kept");
        assertEquals(label0 * factor, onEDT(() -> new JLabel("new").getFont().getSize2D()), 0.01, "new components get the size");
        assertEquals(label0, tree.getComponent(0).getFont().getSize2D(), 0.01, "a tree outside a window keeps its fonts until refreshed");
        onEDT(() -> {
            UIFontSize.refresh(tree);
            return null;
        });
        assertEquals(label0 * factor, tree.getComponent(0).getFont().getSize2D(), 0.01);
        assertEquals(button0 * factor, tree.getComponent(1).getFont().getSize2D(), 0.01);

        // steps, clamping, reset
        assertEquals(base + 5, onEDT(UIFontSize::larger), 0.01);
        assertEquals(base + 4, onEDT(UIFontSize::smaller), 0.01);
        assertEquals(UIFontSize.MAX, onEDT(() -> UIFontSize.apply(200)), 0.01);
        assertEquals(UIFontSize.MIN, onEDT(() -> UIFontSize.apply(1)), 0.01);
        assertEquals(base, onEDT(UIFontSize::reset), 0.01);
        assertEquals(label0, UIManager.getFont("Label.font").getSize2D(), 0.01, "reset restores the originals exactly");
        assertEquals(button0, UIManager.getFont("Button.font").getSize2D(), 0.01);
    }

    @Test
    void widgetFollowsAndDrivesTheSize() throws Exception {
        float base = UIFontSize.getBase();
        FontSizeWidget w = onEDT(FontSizeWidget::new);
        assertEquals(Math.round(base), ((Number) w.getSpinner().getValue()).intValue());
        onEDT(() -> UIFontSize.apply(base + 3));
        assertEquals(Math.round(base + 3), ((Number) w.getSpinner().getValue()).intValue(), "the spinner follows");
        onEDT(() -> {
            w.getSpinner().setValue(Math.round(base + 6));
            return null;
        });
        assertEquals(Math.round(base + 6), Math.round(UIFontSize.get()), "the spinner drives");
        PDFViewerPanel panel = onEDT(PDFViewerPanel::new);
        assertNotNull(panel.getFontSizeWidget());
        assertTrue(SwingUtilities.isDescendingFrom(panel.getFontSizeWidget(), panel.getToolbar()));
    }

    private static <T> T onEDT(Callable<T> call) throws Exception {
        if (SwingUtilities.isEventDispatchThread())
            return call.call();
        Object[] result = new Object[1];
        Exception[] error = new Exception[1];
        SwingUtilities.invokeAndWait(() -> {
            try {
                result[0] = call.call();
            } catch (Exception e) {
                error[0] = e;
            }
        });
        if (error[0] != null)
            throw error[0];
        @SuppressWarnings("unchecked")
        T t = (T) result[0];
        return t;
    }
}
