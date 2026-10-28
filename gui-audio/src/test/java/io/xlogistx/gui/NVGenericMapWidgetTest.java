package io.xlogistx.gui;

import com.formdev.flatlaf.FlatClientProperties;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.zoxweb.shared.util.NVBoolean;
import org.zoxweb.shared.util.NVGenericMap;
import org.zoxweb.shared.util.NVInt;
import org.zoxweb.shared.util.NVLong;
import org.zoxweb.shared.util.NVPair;

import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.SwingUtilities;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Headless tests of the map form: one editor per entry in map order, the buttons follow the
 * dirty state, Save writes the model and calls the consumer, a rejected entry is outlined
 * and named while the valid ones are still written and the consumer stays silent, Reset
 * reloads the editors from the model.
 */
public class NVGenericMapWidgetTest {

    @BeforeAll
    static void headless() {
        System.setProperty("java.awt.headless", "true");
    }

    private static NVGenericMap sample() {
        NVGenericMap data = new NVGenericMap("Service Config");
        data.build(new NVPair("title", "demo"));
        data.build(new NVInt("maxUsers", 250));
        data.build(new NVLong("timeoutMs", 15000L));
        data.build(new NVBoolean("enabled", Boolean.TRUE));
        return data;
    }

    @Test
    void oneEditorPerEntryInOrderAndCleanAtStart() throws Exception {
        onEDT(() -> {
            NVGenericMapWidget w = new NVGenericMapWidget(sample());
            assertEquals(Arrays.asList("title", "maxUsers", "timeoutMs", "enabled"), w.getEntryNames());
            assertTrue(w.getEditor("maxUsers") instanceof LongWidget);
            assertTrue(w.getEditor("enabled") instanceof BooleanWidget);
            assertTrue(w.getEditor("title") instanceof TextWidget);
            assertEquals("enabled", ((JCheckBox) w.getEditor("enabled")).getText(), "a check box is its own label");
            assertTrue(w.getEditor("maxUsers").getMaximumSize().width <= NVGenericMapWidget.NUMBER_FIELD_WIDTH);
            assertNull(w.getEditor("missing"));
            assertEquals("250", ((LongWidget) w.getEditor("maxUsers")).getText());
            assertFalse(w.isDirty());
            assertFalse(w.getSave().isEnabled());
            assertFalse(w.getCancel().isEnabled());
            assertFalse(w.getMessage().hasMessage());
        });
    }

    @Test
    void editMarksDirtyAndSaveWritesModelAndCallsConsumer() throws Exception {
        onEDT(() -> {
            NVGenericMap data = sample();
            NVGenericMapWidget w = new NVGenericMapWidget(data);
            AtomicInteger calls = new AtomicInteger();
            w.setUpdateConsumer(m -> { assertSame(data, m); calls.incrementAndGet(); });

            ((LongWidget) w.getEditor("maxUsers")).setValue(300);
            ((JCheckBox) w.getEditor("enabled")).setSelected(false);
            assertTrue(w.isDirty());
            assertTrue(w.getSave().isEnabled());
            assertTrue(w.getCancel().isEnabled());
            assertEquals(250, (Integer) data.getValue("maxUsers"));

            w.getSave().doClick();
            assertEquals(300, (Integer) data.getValue("maxUsers"));
            assertEquals(Boolean.FALSE, data.getValue("enabled"));
            assertEquals(1, calls.get());
            assertFalse(w.isDirty());
            assertFalse(w.getSave().isEnabled());
            assertEquals("Saved.", w.getMessage().getText());
        });
    }

    @Test
    void rejectedEntryIsOutlinedAndNamedWhileOthersAreWritten() throws Exception {
        onEDT(() -> {
            NVGenericMap data = sample();
            NVGenericMapWidget w = new NVGenericMapWidget(data);
            AtomicInteger calls = new AtomicInteger();
            w.setUpdateConsumer(m -> calls.incrementAndGet());

            LongWidget maxUsers = (LongWidget) w.getEditor("maxUsers");
            maxUsers.setValue(1L + Integer.MAX_VALUE);
            ((LongWidget) w.getEditor("timeoutMs")).setValue(20000L);
            w.getSave().doClick();

            assertEquals(250, (Integer) data.getValue("maxUsers"), "the rejected entry keeps its value");
            assertEquals(20000L, (Long) data.getValue("timeoutMs"), "the valid entries are written");
            assertEquals(0, calls.get(), "the consumer is not called for a partial save");
            assertTrue(w.isDirty());
            assertEquals(FlatClientProperties.OUTLINE_ERROR, maxUsers.getClientProperty(FlatClientProperties.OUTLINE));
            assertNotNull(maxUsers.getClientProperty(NVGenericMapWidget.ERROR_PROPERTY));
            assertNull(w.getEditor("timeoutMs").getClientProperty(FlatClientProperties.OUTLINE));
            assertTrue(w.getMessage().getText().contains("maxUsers"), w.getMessage().getText());

            maxUsers.setValue(400);
            w.getSave().doClick();
            assertEquals(400, (Integer) data.getValue("maxUsers"));
            assertEquals(1, calls.get());
            assertNull(maxUsers.getClientProperty(FlatClientProperties.OUTLINE));
            assertNull(maxUsers.getToolTipText());
        });
    }

    @Test
    void resetReloadsEditorsFromModel() throws Exception {
        onEDT(() -> {
            NVGenericMap data = sample();
            NVGenericMapWidget w = new NVGenericMapWidget(data);

            LongWidget maxUsers = (LongWidget) w.getEditor("maxUsers");
            maxUsers.setValue(999);
            TextWidget title = (TextWidget) w.getEditor("title");
            title.setText("changed");
            assertTrue(w.isDirty());

            w.getCancel().doClick();
            assertEquals("250", maxUsers.getText());
            assertEquals("demo", title.getText());
            assertEquals("demo", data.getValue("title"));
            assertFalse(w.isDirty());
            assertFalse(w.getSave().isEnabled());
            assertFalse(w.getMessage().hasMessage());
        });
    }

    @Test
    void nestedMapIsASectionWithItsOwnEditors() throws Exception {
        onEDT(() -> {
            NVGenericMap data = sample();
            NVGenericMap db = new NVGenericMap("db");
            db.build(new NVPair("url", "jdbc:h2:mem:x"));
            db.build(new NVInt("maxUsers", 5));
            data.build(db);
            NVGenericMapWidget w = new NVGenericMapWidget(data);

            assertEquals(Arrays.asList("title", "maxUsers", "timeoutMs", "enabled", "db/url", "db/maxUsers"), w.getEntryNames());
            assertTrue(w.getEditor("db", "url") instanceof TextWidget, "a nested entry gets a real editor, not the read-only fallback");
            assertNull(w.getEditor("db"), "the map itself has no editor");
            LongWidget nested = (LongWidget) w.getEditor("db", "maxUsers");
            LongWidget top = (LongWidget) w.getEditor("maxUsers");
            assertNotSame(top, nested);
            assertEquals("5", nested.getText());

            nested.setValue(7);
            ((TextWidget) w.getEditor("db", "url")).setText("jdbc:h2:mem:y");
            assertTrue(w.isDirty());
            w.getSave().doClick();
            assertEquals(7, (Integer) db.getValue("maxUsers"));
            assertEquals("jdbc:h2:mem:y", db.getValue("url"));
            assertEquals(250, (Integer) data.getValue("maxUsers"), "the top-level entry of the same name is untouched");

            nested.setValue(9);
            w.getCancel().doClick();
            assertEquals("7", nested.getText());
        });
    }

    @Test
    void emptyMapShowsAHintAndNoTitleWhenUnnamed() throws Exception {
        onEDT(() -> {
            NVGenericMapWidget w = new NVGenericMapWidget(new NVGenericMap());
            assertTrue(w.getEntryNames().isEmpty());
            assertFalse(w.getSave().isEnabled());
            JComponent root = w;
            assertNotNull(root);
        });
    }

    private static void onEDT(ThrowingRunnable r) throws Exception {
        Throwable[] failure = new Throwable[1];
        SwingUtilities.invokeAndWait(() -> {
            try {
                r.run();
            } catch (Throwable t) {
                failure[0] = t;
            }
        });
        if (failure[0] instanceof Exception) throw (Exception) failure[0];
        if (failure[0] instanceof Error) throw (Error) failure[0];
    }

    private interface ThrowingRunnable {
        void run() throws Exception;
    }
}
