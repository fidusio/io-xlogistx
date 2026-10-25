package io.xlogistx.gui;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Headless tests of the form primitives: a group hides and shows exactly its own rows, a
 * hint and a required mark are part of their field's rows, the inline message keeps its line,
 * the stepper's states follow activate / complete / reopen, and the badge takes its tone.
 */
public class FormPanelTest {

    @BeforeAll
    static void headless() {
        System.setProperty("java.awt.headless", "true");
    }

    @Test
    void groupHidesExactlyItsRows() throws Exception {
        onEDT(() -> {
            FormPanel form = new FormPanel();
            JTextField always = new JTextField();
            JTextField operator = new JTextField();
            JTextField dbPassword = new JTextField();
            JButton button = new JButton("Create");

            form.field("Vault password", always, "Required");
            form.group("firstRun", () -> {
                form.requiredField("Operator username", operator);
                form.field("Database password", dbPassword, "Empty = generated");
            });
            form.row(button);

            List<JComponent> rows = form.group("firstRun");
            // label + field, then label + field + hint
            assertEquals(5, rows.size());
            assertTrue(rows.contains(operator));
            assertTrue(rows.contains(dbPassword));
            assertFalse(rows.contains(always));
            assertFalse(rows.contains(button));
            assertTrue(form.isGroupVisible("firstRun"));

            form.showGroup("firstRun", false);
            assertFalse(form.isGroupVisible("firstRun"));
            for (JComponent c : rows) assertFalse(c.isVisible(), c.getClass().getSimpleName() + " should be hidden");
            assertTrue(always.isVisible());
            assertTrue(button.isVisible());

            form.showGroup("firstRun", true);
            for (JComponent c : rows) assertTrue(c.isVisible());

            // an unknown key is ignored, an empty one is empty
            form.showGroup("nothing", false);
            assertTrue(form.group("nothing").isEmpty());
            assertFalse(form.isGroupVisible("nothing"));
            return null;
        });
    }

    @Test
    void requiredLabelCarriesTheMarkAndTargetsTheField() throws Exception {
        onEDT(() -> {
            FormPanel form = new FormPanel();
            JTextField f = new JTextField();
            JLabel l = form.requiredField("Name", f);
            assertSame(f, l.getLabelFor());
            assertTrue(l.getText().contains("*"));
            assertTrue(l.getText().contains("Name"));
            JLabel plain = form.field("Other", new JTextField());
            assertEquals("Other", plain.getText());
            return null;
        });
    }

    @Test
    void inlineMessageKeepsItsLine() throws Exception {
        onEDT(() -> {
            InlineMessage m = new InlineMessage();
            assertFalse(m.hasMessage());
            assertEquals(" ", m.getText());
            m.error("Passwords do not match.");
            assertTrue(m.hasMessage());
            assertEquals(UITokens.danger(), m.getForeground());
            m.info("Existing vault found.");
            assertEquals(UITokens.muted(), m.getForeground());
            m.ok("Registered.");
            assertEquals(UITokens.ok(), m.getForeground());
            m.clear();
            assertFalse(m.hasMessage());
            assertEquals(" ", m.getText());
            m.error(null);
            assertFalse(m.hasMessage());
            return null;
        });
    }

    @Test
    void stepperStatesFollowTheFlow() throws Exception {
        onEDT(() -> {
            StepperPanel steps = new StepperPanel();
            int one = steps.addStep("Open store", "Where the data lives", new JTextField());
            int two = steps.addStep("Sign in", null, new JTextField());
            assertEquals(2, steps.getStepCount());
            assertEquals(StepperPanel.State.ACTIVE, steps.getState(one));
            assertEquals(StepperPanel.State.TODO, steps.getState(two));

            AtomicReference<Boolean> changed = new AtomicReference<>(false);
            steps.complete(one, "D:\\data\\nosneak · vault unlocked", () -> changed.set(true));
            steps.activate(two);
            assertEquals(StepperPanel.State.DONE, steps.getState(one));
            assertEquals(StepperPanel.State.ACTIVE, steps.getState(two));

            // activating another step keeps a done step done
            steps.activate(one);
            assertEquals(StepperPanel.State.ACTIVE, steps.getState(one));
            assertEquals(StepperPanel.State.TODO, steps.getState(two));
            steps.complete(one, "again", null);
            steps.activate(two);
            assertEquals(StepperPanel.State.DONE, steps.getState(one));

            steps.reopen(one);
            assertEquals(StepperPanel.State.ACTIVE, steps.getState(one));
            assertEquals(StepperPanel.State.TODO, steps.getState(two));

            assertThrows(IndexOutOfBoundsException.class, () -> steps.getState(3));
            assertThrows(IndexOutOfBoundsException.class, () -> steps.getState(0));
            return null;
        });
    }

    @Test
    void badgeTakesItsTone() throws Exception {
        onEDT(() -> {
            BadgeLabel b = new BadgeLabel("ready", BadgeLabel.Tone.OK);
            assertEquals(BadgeLabel.Tone.OK, b.getTone());
            assertEquals(UITokens.ok(), b.getForeground());
            b.setTone(BadgeLabel.Tone.DANGER);
            assertEquals(UITokens.danger(), b.getForeground());
            b.setTone(null);
            assertEquals(BadgeLabel.Tone.NEUTRAL, b.getTone());
            return null;
        });
    }

    @Test
    void tokensFallBackWhenTheLookAndFeelHasNoKey() {
        assertNotNull(UITokens.accent());
        assertNotNull(UITokens.border());
        assertEquals(new java.awt.Color(0x123456), UITokens.color("xlogistx.noSuchKey", "NoSuch.key", 0x123456));
        assertNotNull(UITokens.mono(0));
        assertTrue(UITokens.font(java.awt.Font.BOLD, 2f).isBold());
    }

    private static <T> T onEDT(java.util.concurrent.Callable<T> work) throws Exception {
        AtomicReference<T> out = new AtomicReference<>();
        AtomicReference<Exception> failure = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            try {
                out.set(work.call());
            } catch (Exception e) {
                failure.set(e);
            }
        });
        if (failure.get() != null) throw failure.get();
        return out.get();
    }
}
