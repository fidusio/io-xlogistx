package io.xlogistx.gui;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.zoxweb.shared.util.GetDescription;
import org.zoxweb.shared.util.GetDisplayName;

import javax.swing.JToggleButton;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link SideNavPanel} items as {@link ComponentRef}s: an enum item is keyed by the constant's
 * name, labelled by its display name and explained by its description; selecting by option
 * highlights without firing; a click fires the key; the hand-keyed item still works.
 */
public class SideNavPanelTest {

    @BeforeAll
    static void headless() {
        System.setProperty("java.awt.headless", "true");
    }

    enum Page implements GetDisplayName, GetDescription {
        SCAN("Scan", "Targets and ports"), HISTORY("Scan History", "Every report");

        final String dn, d;

        Page(String dn, String d) {
            this.dn = dn;
            this.d = d;
        }

        @Override public String getDisplayName() { return dn; }
        @Override public String getDescription() { return d; }
    }

    @Test
    void enumItemsAreKeyedLabelledAndExplainedByTheEnum() {
        SideNavPanel nav = new SideNavPanel();
        nav.section("scan", "Scan");
        ComponentRef<Page> ref = nav.item(Page.HISTORY, null);
        JToggleButton b = ref.getComponent();
        assertEquals("Scan History", b.getText());
        assertEquals("Every report", b.getToolTipText());
        assertSame(Page.HISTORY, ref.getSource());
        assertSame(ref, nav.ref("HISTORY"));
        assertEquals(1, nav.refs().size());
    }

    @Test
    void selectByOptionHighlightsWithoutFiring() {
        SideNavPanel nav = new SideNavPanel();
        nav.item(Page.SCAN, null);
        nav.item(Page.HISTORY, null);
        List<String> fired = new ArrayList<>();
        nav.onSelect(fired::add);
        nav.select(Page.HISTORY);
        assertEquals("HISTORY", nav.getSelected());
        assertTrue(fired.isEmpty(), "select never fires");
        nav.select((Object) "not an item");
        assertNull(nav.getSelected());
        nav.<Page>ref("SCAN").<JToggleButton>getComponent().doClick();
        assertEquals(java.util.Arrays.asList("SCAN"), fired);
        assertEquals("SCAN", nav.getSelected());
    }

    @Test
    void handKeyedItemStillWorks() {
        SideNavPanel nav = new SideNavPanel();
        JToggleButton b = nav.item("acl", null, "Access control");
        assertEquals("Access control", b.getText());
        assertNull(b.getToolTipText());
        assertNull(nav.ref("acl").getSource());
        nav.select("acl");
        assertEquals("acl", nav.getSelected());
    }
}
