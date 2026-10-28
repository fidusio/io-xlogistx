package io.xlogistx.gui;

import io.xlogistx.gui.pdf.PDFViewerPanel;
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
            UIFontSize.refresh(w);
            return null;
        });
        assertEquals(base, w.getComponent(0).getFont().getSize2D(), 0.01, "the widget's own label keeps the base size");
        assertEquals(base, w.getSpinner().getFont().getSize2D(), 0.01, "the spinner keeps the base size");
        assertEquals(base, ((javax.swing.JSpinner.DefaultEditor) w.getSpinner().getEditor()).getTextField().getFont().getSize2D(), 0.01, "the spinner's field keeps the base size");
        onEDT(() -> {
            w.getSpinner().setValue(Math.round(base + 6));
            return null;
        });
        assertEquals(Math.round(base + 6), Math.round(UIFontSize.get()), "the spinner drives");
        PDFViewerPanel panel = onEDT(PDFViewerPanel::new);
        assertNotNull(panel.getFontSizeWidget());
        assertTrue(SwingUtilities.isDescendingFrom(panel.getFontSizeWidget(), panel.getToolbar()));
    }

    @Test
    void aScopedSizeTouchesOneTreeOnlyAndSurvivesTheApplicationSize() throws Exception {
        float base = UIFontSize.getBase();
        JPanel host = onEDT(() -> {
            JPanel p = new JPanel();
            p.add(new JLabel("host"));
            return p;
        });
        JPanel viewer = onEDT(() -> {
            JPanel p = new JPanel();
            p.add(new JLabel("viewer"));
            JPanel inner = new JPanel();
            inner.add(new JButton("inner"));
            p.add(inner);
            p.add(new FontSizeWidget(p));
            return p;
        });
        float hostLabel0 = host.getComponent(0).getFont().getSize2D();
        float viewerLabel0 = viewer.getComponent(0).getFont().getSize2D();
        float innerButton0 = ((JPanel) viewer.getComponent(1)).getComponent(0).getFont().getSize2D();
        FontSizeWidget w = (FontSizeWidget) viewer.getComponent(2);
        assertEquals(Math.round(base), ((Number) w.getSpinner().getValue()).intValue());
        assertSame(viewer, w.getScope());

        // the viewer scales itself, the host and the application stay
        onEDT(() -> {
            w.getSpinner().setValue(Math.round(base + 4));
            return null;
        });
        float factor = (base + 4) / base;
        assertEquals(viewerLabel0 * factor, viewer.getComponent(0).getFont().getSize2D(), 0.01, "the viewer's label scaled");
        assertEquals(innerButton0 * factor, ((JPanel) viewer.getComponent(1)).getComponent(0).getFont().getSize2D(), 0.01, "its subtree scaled");
        assertEquals(base, w.getComponent(0).getFont().getSize2D(), 0.01, "the pinned widget did not");
        assertEquals(hostLabel0, host.getComponent(0).getFont().getSize2D(), 0.01, "the host did not");
        assertEquals(base, UIFontSize.get(), 0.01, "the application size is untouched");
        assertEquals(base + 4, UIFontSize.get(viewer), 0.01);
        assertEquals(base, UIFontSize.get(host), 0.01, "an unscoped tree reports the application size");

        // the application changing its size does not reach the scoped viewer
        onEDT(() -> UIFontSize.apply(base + 2));
        onEDT(() -> {
            UIFontSize.refresh(viewer);
            UIFontSize.refresh(host);
            return null;
        });
        assertEquals(hostLabel0 * (base + 2) / base, host.getComponent(0).getFont().getSize2D(), 0.01, "the host followed the application");
        assertEquals(viewerLabel0 * factor, viewer.getComponent(0).getFont().getSize2D(), 0.01, "the viewer kept its own size");
        assertEquals(Math.round(base + 4), ((Number) w.getSpinner().getValue()).intValue(), "a scoped spinner does not follow the application");

        // the spinner drives its scope; the base hands the tree back to the look and feel
        onEDT(() -> {
            w.getSpinner().setValue(Math.round(base));
            return null;
        });
        assertEquals(base + 2, UIFontSize.get(viewer), 0.01, "back on the application size");
        assertEquals(viewerLabel0 * (base + 2) / base, viewer.getComponent(0).getFont().getSize2D(), 0.01, "and on the look and feel's current fonts");
        assertEquals(base + 2, UIFontSize.get(), 0.01, "the application size still untouched by the scoped spinner");
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
