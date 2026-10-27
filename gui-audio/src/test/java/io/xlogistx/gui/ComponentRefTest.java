package io.xlogistx.gui;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.zoxweb.shared.util.GetDescription;
import org.zoxweb.shared.util.GetDisplayName;
import org.zoxweb.shared.util.GetName;

import javax.swing.JButton;
import javax.swing.JToggleButton;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link ComponentRef}: a plain enum gets its constant's name as name and display name; an enum
 * with the naming interfaces is read through them, with a null falling back; the source and the
 * component come back as given; a string-only ref knows only its strings.
 */
public class ComponentRefTest {

    @BeforeAll
    static void headless() {
        System.setProperty("java.awt.headless", "true");
    }

    enum Plain { ONE, TWO }

    enum Named implements GetName, GetDescription, GetDisplayName {
        FAST("fast", "256 in flight", "T4"), BARE(null, null, null);

        final String n, d, dn;

        Named(String n, String d, String dn) {
            this.n = n;
            this.d = d;
            this.dn = dn;
        }

        @Override public String getName() { return n; }
        @Override public String getDescription() { return d; }
        @Override public String getDisplayName() { return dn; }
    }

    @Test
    void plainEnumFallsBackToItsConstantName() {
        JToggleButton b = new JToggleButton();
        ComponentRef<Plain> ref = new ComponentRef<Plain>(b, Plain.TWO);
        assertEquals("TWO", ref.getName());
        assertEquals("TWO", ref.getDisplayName(), "display name defaults to the name");
        assertNull(ref.getDescription());
        assertSame(Plain.TWO, ref.getSource());
        assertSame(b, ref.<JToggleButton>getComponent());
    }

    @Test
    void namedEnumIsReadThroughItsInterfaces() {
        ComponentRef<Named> ref = new ComponentRef<Named>(new JButton(), Named.FAST);
        assertEquals("fast", ref.getName());
        assertEquals("256 in flight", ref.getDescription());
        assertEquals("T4", ref.getDisplayName());
    }

    @Test
    void nullsFromTheSourceFallBack() {
        ComponentRef<Named> ref = new ComponentRef<Named>(new JButton(), Named.BARE);
        assertEquals("BARE", ref.getName(), "a null name falls back to the constant's name");
        assertEquals("BARE", ref.getDisplayName(), "then the display name falls back to the name");
        assertNull(ref.getDescription());
    }

    @Test
    void displayNameOverrideKeepsTheSource() {
        ComponentRef<Named> ref = new ComponentRef<Named>(new JButton(), Named.FAST, "Quick");
        assertEquals("Quick", ref.getDisplayName());
        assertEquals("fast", ref.getName());
        assertEquals("256 in flight", ref.getDescription());
        assertSame(Named.FAST, ref.getSource());
        assertEquals("T4", new ComponentRef<Named>(new JButton(), Named.FAST, null).getDisplayName(), "null keeps the source's");
    }

    @Test
    void stringRefKnowsOnlyItsStrings() {
        ComponentRef<Object> ref = new ComponentRef<Object>(new JButton(), "all", "Every row", "All");
        assertEquals("all", ref.getName());
        assertEquals("Every row", ref.getDescription());
        assertEquals("All", ref.getDisplayName());
        assertNull(ref.getSource());
        ComponentRef<Object> bare = new ComponentRef<Object>(new JButton(), "x", null, null);
        assertEquals("x", bare.getDisplayName());
    }

    @Test
    void nullComponentOrSourceIsRefused() {
        assertThrows(Exception.class, () -> new ComponentRef<Plain>(null, Plain.ONE));
        assertThrows(Exception.class, () -> new ComponentRef<Plain>(new JButton(), (Plain) null));
    }
}
