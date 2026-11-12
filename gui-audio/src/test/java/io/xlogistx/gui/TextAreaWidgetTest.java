package io.xlogistx.gui;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link TextAreaWidget} is a field several lines high: Enter submits, Shift+Enter breaks the
 * line, the height is its rows whatever it holds, and the placeholder is kept for the empty state.
 */
class TextAreaWidgetTest {

    @BeforeAll
    static void headless() {
        System.setProperty("java.awt.headless", "true");
    }

    @Test
    void enterSubmitsAndShiftEnterBreaksTheLine() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            TextAreaWidget field = new TextAreaWidget();
            AtomicInteger fired = new AtomicInteger();
            field.addActionListener(e -> fired.incrementAndGet());
            JTextArea area = field.getTextArea();
            Object submit = area.getInputMap().get(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0));
            area.getActionMap().get(submit).actionPerformed(new ActionEvent(area, ActionEvent.ACTION_PERFORMED, ""));
            assertEquals(1, fired.get(), "Enter tells the listeners");
            assertEquals("", field.getText(), "and inserts nothing");
            assertEquals("insert-break", area.getInputMap().get(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, InputEvent.SHIFT_DOWN_MASK)));
        });
    }

    @Test
    void theHeightIsItsRowsWhateverItHolds() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            TextAreaWidget field = new TextAreaWidget(3);
            int empty = field.getPreferredSize().height;
            StringBuilder many = new StringBuilder();
            for (int i = 1; i < 200; i++) many.append("192.168.1.").append(i).append(' ');
            field.setText(many.toString());
            assertEquals(empty, field.getPreferredSize().height, "a long list scrolls, the field does not grow");
            assertTrue(field.getTextArea().getLineWrap());
            assertEquals(field.getPreferredSize().height, field.getMinimumSize().height, "a layout short of room cannot squeeze it below its rows");
            assertEquals(many.toString(), field.getText());
            field.setText(null);
            assertEquals("", field.getText());
        });
    }

    @Test
    void thePlaceholderAndTheTooltipReachTheText() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            TextAreaWidget field = new TextAreaWidget().placeholder("10.0.0.0/24");
            assertEquals("10.0.0.0/24", field.getPlaceholder());
            field.setToolTipText("the targets");
            assertEquals("the targets", field.getTextArea().getToolTipText());
        });
    }
}
