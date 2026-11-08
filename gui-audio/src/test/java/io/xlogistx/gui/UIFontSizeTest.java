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
        float aa0 = w.getComponent(0).getFont().getSize2D();
        onEDT(() -> UIFontSize.apply(base + 3));
        assertEquals(Math.round(base + 3), ((Number) w.getSpinner().getValue()).intValue(), "the spinner follows");
        onEDT(() -> {
            UIFontSize.refresh(w);
            return null;
        });
        // the control's own text is the application's: a look and feel that sizes the box and
        // the arrows from the font (FlatLaf) would otherwise wrap big chrome around small digits
        float factor = (base + 3) / base;
        assertEquals(aa0 * factor, w.getComponent(0).getFont().getSize2D(), 0.01, "the widget's own label follows the application size");
        javax.swing.JTextField field = ((javax.swing.JSpinner.DefaultEditor) w.getSpinner().getEditor()).getTextField();
        assertEquals(UIManager.getFont("Spinner.font").getSize2D(), w.getSpinner().getFont().getSize2D(), 0.01, "the spinner follows the application size");
        assertEquals(w.getSpinner().getFont().getSize2D(), field.getFont().getSize2D(), 0.01, "and its field with it");
        assertTrue(w.getSpinner().getFont().getSize2D() > base, "bigger than the base");
        // one baseline for "Aa" and the number, reported to the layout around the control
        onEDT(() -> {
            w.setSize(w.getPreferredSize());
            w.doLayout();
            return null;
        });
        java.awt.Component aa = w.getComponent(0);
        int labelBaseline = aa.getY() + aa.getBaseline(aa.getWidth(), aa.getHeight());
        int spinnerBaseline = w.getSpinner().getY() + w.getSpinner().getBaseline(w.getSpinner().getWidth(), w.getSpinner().getHeight());
        assertEquals(labelBaseline, spinnerBaseline, "the label and the number share a baseline");
        assertEquals(labelBaseline, w.getBaseline(w.getWidth(), w.getHeight()), "which the control reports");
        // never stretched by a box layout, and the limit follows the size
        java.awt.Dimension big = w.getPreferredSize();
        assertEquals(big, w.getMaximumSize());
        onEDT(() -> {
            UIFontSize.apply(base);
            UIFontSize.refresh(w);
            return null;
        });
        assertEquals(w.getPreferredSize(), w.getMaximumSize());
        assertTrue(w.getPreferredSize().height < big.height, "smaller text, smaller control");
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
    void theWidgetTakesACaptionAndAResetLink() throws Exception {
        float base = UIFontSize.getBase();
        FontSizeWidget app = onEDT(() -> new FontSizeWidget().withLabel().withReset());
        assertEquals(FontSizeWidget.LABEL, app.getLabel().getText());
        assertSame(app.getSpinner(), app.getLabel().getLabelFor(), "the caption labels the spinner");
        assertSame(app.getLabel(), app.getComponent(0), "caption first");
        assertSame(app.getResetButton(), app.getComponent(app.getComponentCount() - 1), "the link last");
        assertEquals(FontSizeWidget.RESET, app.getResetButton().getText());
        assertEquals(FontSizeWidget.RESET_TIP, app.getResetButton().getToolTipText());
        assertNull(onEDT(() -> new FontSizeWidget()).getLabel(), "a bare widget has no caption");
        assertNull(onEDT(() -> new FontSizeWidget()).getResetButton(), "nor a link");

        onEDT(() -> UIFontSize.apply(base + 3));
        assertEquals(Math.round(base) + 3, onEDT(() -> app.getSpinner().getValue()));
        onEDT(() -> { app.getResetButton().doClick(); return null; });
        assertEquals(base, UIFontSize.get(), 0.01, "the link resets the application");
        assertEquals(Math.round(base), onEDT(() -> app.getSpinner().getValue()));

        JPanel tree = onEDT(() -> { JPanel p = new JPanel(); p.add(new JLabel("x")); return p; });
        FontSizeWidget scoped = onEDT(() -> new FontSizeWidget(tree).withReset("Back", null));
        assertEquals("Back", scoped.getResetButton().getText());
        assertNull(scoped.getResetButton().getToolTipText());
        onEDT(() -> UIFontSize.apply(tree, base + 4));
        onEDT(() -> UIFontSize.apply(base + 1));
        onEDT(() -> { scoped.getResetButton().doClick(); return null; });
        assertEquals(base + 1, UIFontSize.get(), 0.01, "a scoped link leaves the application alone");
        assertEquals(base + 1, UIFontSize.get(tree), 0.01, "and hands its tree back to the application size");
        onEDT(() -> app.withLabel("Size").withReset("Again", "tip"));
        assertEquals("Size", app.getLabel().getText());
        assertEquals("Again", app.getResetButton().getText());
        assertEquals(3, app.getComponentCount() - 1, "a second call replaces, it does not add");
    }

    @Test
    void derivedFontsFollowTheSizeOnRefresh() throws Exception {
        float base = UIFontSize.getBase();
        JPanel tree = onEDT(() -> {
            JPanel p = new JPanel();
            JLabel heading = new JLabel("heading");
            heading.setFont(UITokens.font(java.awt.Font.BOLD, 2f));
            p.add(heading);
            JLabel value = new JLabel("value");
            value.setFont(UITokens.mono(-1f));
            p.add(value);
            p.add(UITokens.link(new JButton("Reset")));
            JLabel frozen = new JLabel("frozen");
            frozen.setFont(new java.awt.Font(java.awt.Font.SERIF, java.awt.Font.ITALIC, 9));
            p.add(frozen);
            return p;
        });
        float label0 = UIManager.getFont("Label.font").getSize2D();
        assertEquals(label0 + 2, tree.getComponent(0).getFont().getSize2D(), 0.01);
        onEDT(() -> UIFontSize.apply(base + 3));
        onEDT(() -> {
            UIFontSize.refresh(tree);
            return null;
        });
        float label1 = UIManager.getFont("Label.font").getSize2D();
        assertEquals(label0 + 3, label1, 0.01);
        java.awt.Font heading = tree.getComponent(0).getFont();
        assertEquals(label1 + 2, heading.getSize2D(), 0.01, "a heading built two points bigger is still two points bigger");
        assertTrue(heading.isBold(), "and still bold");
        java.awt.Font value = tree.getComponent(1).getFont();
        assertEquals(Math.round(label1 - 1), value.getSize2D(), 0.01, "a monospaced value follows");
        assertEquals(UITokens.mono(-1f).getFamily(), value.getFamily(), "in its family");
        java.awt.Font link = tree.getComponent(2).getFont();
        assertEquals(label1 - 0.5f, link.getSize2D(), 0.01, "a link button follows");
        assertTrue(link.isBold());
        assertEquals(9f, tree.getComponent(3).getFont().getSize2D(), 0.01, "a font set by hand is left alone");
        onEDT(UIFontSize::reset);
        onEDT(() -> {
            UIFontSize.refresh(tree);
            return null;
        });
        assertEquals(label0 + 2, tree.getComponent(0).getFont().getSize2D(), 0.01, "and back");
    }

    @Test
    void theViewerToolbarFieldsFollowTheSize() throws Exception {
        float base = UIFontSize.getBase();
        PDFViewerPanel panel = onEDT(PDFViewerPanel::new);
        javax.swing.JComboBox<?> zoom = null;
        java.util.List<javax.swing.JTextField> fields = new java.util.ArrayList<>();
        for (java.awt.Component c : panel.getToolbar().getComponents()) {
            if (c instanceof javax.swing.JComboBox)
                zoom = (javax.swing.JComboBox<?>) c;
            else if (c instanceof javax.swing.JTextField)
                fields.add((javax.swing.JTextField) c);
        }
        assertNotNull(zoom);
        assertEquals(2, fields.size(), "the page field and the search field");
        int zoomHeight0 = zoom.getPreferredSize().height;
        onEDT(() -> UIFontSize.apply(base * 2));
        onEDT(() -> {
            UIFontSize.refresh(panel);
            return null;
        });
        assertTrue(zoom.getPreferredSize().height > zoomHeight0, "bigger text, taller combo");
        assertEquals(zoom.getPreferredSize(), zoom.getMaximumSize(), "the limit follows, nothing is clipped or stretched");
        for (javax.swing.JTextField f : fields)
            assertEquals(f.getPreferredSize(), f.getMaximumSize(), "a field keeps its text visible");
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
