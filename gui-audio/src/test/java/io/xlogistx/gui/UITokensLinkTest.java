package io.xlogistx.gui;

import com.formdev.flatlaf.FlatLightLaf;
import net.miginfocom.swing.MigLayout;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.LookAndFeel;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import java.awt.Insets;

import static org.junit.jupiter.api.Assertions.*;

/**
 * A {@link UITokens#link} button in a MigLayout row under FlatLaf (2026-11-06): it gets its
 * whole preferred width, so its text is never shortened to "Re…" — FlatLaf's one-point visual
 * padding, which MigLayout takes off a regular button's bounds for the focus ring, is pinned to
 * zero on the link and stays so after the look and feel's UI is reinstalled (a text size change).
 */
public class UITokensLinkTest {

    private static LookAndFeel before;

    @BeforeAll
    static void flatLaf() throws Exception {
        System.setProperty("java.awt.headless", "true");
        before = UIManager.getLookAndFeel();
        SwingUtilities.invokeAndWait(() -> {
            FlatLightLaf.setup();
            UIManager.put("Component.focusWidth", 1); // the ring FlatLaf pads a regular button for, as no-sneak's themes set it
        });
    }

    @AfterAll
    static void restore() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            try {
                UIManager.put("Component.focusWidth", null);
                UIManager.setLookAndFeel(before);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    @Test
    void aLinkKeepsItsPreferredWidthInAMigLayoutRow() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            JPanel row = new JPanel(new MigLayout("insets 0, gapx 8", "[][]"));
            JButton plain = new JButton("Reset");
            JButton link = UITokens.link(new JButton("Reset"));
            row.add(plain);
            row.add(link);
            row.setSize(row.getPreferredSize());
            row.doLayout();

            assertEquals(new Insets(0, 0, 0, 0), link.getClientProperty(UITokens.VISUAL_PADDING), "the link's padding is pinned to zero");
            assertNotEquals(new Insets(0, 0, 0, 0), plain.getClientProperty(UITokens.VISUAL_PADDING), "FlatLaf still pads a regular button");
            assertEquals(link.getPreferredSize().width, link.getWidth(), "the link is laid out at its preferred width");
            assertTrue(plain.getWidth() < plain.getPreferredSize().width, "a regular button is laid out narrower than it asks, by the padding");

            SwingUtilities.updateComponentTreeUI(row);
            row.doLayout();
            assertEquals(new Insets(0, 0, 0, 0), link.getClientProperty(UITokens.VISUAL_PADDING), "a UI update keeps the pin");
            assertEquals(link.getPreferredSize().width, link.getWidth());
        });
    }
}
