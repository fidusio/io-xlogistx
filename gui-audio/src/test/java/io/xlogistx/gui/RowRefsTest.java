package io.xlogistx.gui;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.swing.JPanel;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The per-row refs of {@link ListSection} and the per-chip refs of {@link ChipPanel}
 * (2026-10-27): a row's ref carries the item, the label and sublabel the host gave it, and the
 * row panel; a chip's ref carries the chip (which names itself) and its pill; both follow refresh.
 */
public class RowRefsTest {

    @BeforeAll
    static void headless() {
        System.setProperty("java.awt.headless", "true");
    }

    @Test
    void listRowsAreRefsOverTheirItems() {
        List<String> items = Arrays.asList("alpha", "beta");
        ListSection<String> list = ListSection.of(() -> items)
                .title("Items")
                .label(s -> "Item " + s)
                .sublabel(s -> "sub " + s)
                .build();
        assertEquals(2, list.rowRefs().size());
        ComponentRef<String> beta = list.rowRefs().get(1);
        assertEquals("beta", beta.getSource());
        assertEquals("Item beta", beta.getDisplayName(), "the host's label, not the string itself");
        assertEquals("sub beta", beta.getDescription());
        assertEquals("beta", beta.getName(), "a string source names itself");
        assertTrue(beta.<JPanel>getComponent() instanceof JPanel);
        list.refresh();
        assertEquals(2, list.rowRefs().size(), "rebuilt, not accumulated");
    }

    @Test
    void chipsAreRefsOverTheirChips() {
        ChipPanel chips = new ChipPanel();
        chips.setChips(Arrays.asList(new ChipPanel.Chip("ssh", "SSH probe"), new ChipPanel.Chip("tls", "TLS", "3")));
        assertEquals(2, chips.chipRefs().size());
        ComponentRef<ChipPanel.Chip> tls = chips.chipRefs().get(1);
        assertEquals("tls", tls.getName());
        assertEquals("TLS", tls.getDisplayName());
        assertNull(tls.getDescription());
        assertSame(chips.getChips().get(1), tls.getSource());
        assertSame(chips.getComponent(1), tls.getComponent());
        chips.setChips(null);
        assertTrue(chips.chipRefs().isEmpty());
    }
}
