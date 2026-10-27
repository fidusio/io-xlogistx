package io.xlogistx.gui;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.zoxweb.shared.util.GetDescription;
import org.zoxweb.shared.util.GetDisplayName;

import javax.swing.JToggleButton;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link SegmentedControl} over {@link ComponentRef}s: an enum's display names are the labels and
 * its descriptions the tooltips, the selected source comes back without a values array, selecting
 * by source works and an unknown source clears, and string segments carry no tooltip.
 */
public class SegmentedControlTest {

    @BeforeAll
    static void headless() {
        System.setProperty("java.awt.headless", "true");
    }

    enum Speed implements GetDisplayName, GetDescription {
        SLOW("Slow", "1 in flight"), FAST("Fast", "256 in flight");

        final String dn, d;

        Speed(String dn, String d) {
            this.dn = dn;
            this.d = d;
        }

        @Override public String getDisplayName() { return dn; }
        @Override public String getDescription() { return d; }
    }

    @Test
    void enumSegmentsAreLabelledAndExplainedByTheEnum() {
        SegmentedControl c = new SegmentedControl(Speed.values());
        assertEquals(2, c.refs().size());
        JToggleButton fast = c.refs().get(1).getComponent();
        assertEquals("Fast", fast.getText());
        assertEquals("256 in flight", fast.getToolTipText());
        assertSame(Speed.FAST, c.refs().get(1).getSource());
    }

    @Test
    void selectionBySourceAndBack() {
        SegmentedControl c = new SegmentedControl(Speed.values());
        assertNull(c.selectedSource());
        c.select(Speed.FAST);
        assertEquals(1, c.getSelectedIndex());
        assertSame(Speed.FAST, c.<Speed>selectedSource());
        c.select("not an option");
        assertEquals(-1, c.getSelectedIndex());
        c.select((Object) null);
        assertNull(c.selectedSource());
    }

    @Test
    void stringSegmentsHaveNoTooltip() {
        SegmentedControl c = new SegmentedControl("All", "Mine");
        JToggleButton all = c.refs().get(0).getComponent();
        assertEquals("All", all.getText());
        assertNull(all.getToolTipText());
        c.select("Mine");
        assertEquals("Mine", c.<String>selectedSource());
    }
}
