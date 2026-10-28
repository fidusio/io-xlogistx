package io.xlogistx.gui;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.swing.Action;
import javax.swing.SwingUtilities;
import javax.swing.text.JTextComponent;
import java.awt.event.ActionEvent;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link FilterComboBox}: typing narrows the visible items through the matcher, a selection
 * clears the filter and shows the full list again, typed text resolves to an item it names
 * exactly or (with free text) stays as typed, Enter commits, and clearing the items clears all.
 */
public class FilterComboBoxTest {

    @BeforeAll
    static void headless() {
        System.setProperty("java.awt.headless", "true");
    }

    private static FilterComboBox<String> box(String... items) throws Exception {
        final FilterComboBox<String>[] out = new FilterComboBox[1];
        SwingUtilities.invokeAndWait(() -> out[0] = new FilterComboBox<>(Arrays.asList(items)));
        return out[0];
    }

    private static JTextComponent editor(FilterComboBox<?> box) {
        return (JTextComponent) box.getEditor().getEditorComponent();
    }

    /** Types into the editor and lets the deferred filter run. */
    private static void type(FilterComboBox<?> box, String text) throws Exception {
        SwingUtilities.invokeAndWait(() -> editor(box).setText(text));
        SwingUtilities.invokeAndWait(() -> {
        });
    }

    private static void pressEnter(FilterComboBox<?> box) throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            Action commit = editor(box).getActionMap().get("FilterComboBox.commit");
            assertNotNull(commit, "Enter is bound on the editor");
            commit.actionPerformed(new ActionEvent(editor(box), ActionEvent.ACTION_PERFORMED, "enter"));
        });
    }

    private static List<String> visible(FilterComboBox<String> box) {
        List<String> out = new ArrayList<>();
        for (int i = 0; i < box.getItemCount(); i++) out.add(box.getItemAt(i));
        return out;
    }

    @Test
    void typingNarrowsTheListAndKeepsTheTypedText() throws Exception {
        FilterComboBox<String> box = box("alpha", "beta", "alps");
        assertEquals(Arrays.asList("alpha", "beta", "alps"), visible(box));

        type(box, "al");
        assertEquals(Arrays.asList("alpha", "alps"), visible(box));
        assertEquals("al", editor(box).getText(), "the typed text survives the model events");
        assertEquals("al", box.getFilter());
        assertEquals(3, box.getItems().size(), "the full list is intact behind the filter");

        type(box, "zzz");
        assertEquals(0, box.getItemCount(), "no match, empty list, text kept");
        assertEquals("zzz", editor(box).getText());
    }

    @Test
    void aSelectionClearsTheFilterAndShowsEverythingAgain() throws Exception {
        FilterComboBox<String> box = box("alpha", "beta", "alps");
        type(box, "al");
        SwingUtilities.invokeAndWait(() -> box.setSelectedItem("alps"));

        assertEquals("alps", box.getSelectedItem());
        assertEquals("alps", editor(box).getText());
        assertEquals("", box.getFilter());
        assertEquals(3, box.getItemCount(), "the popup closed: the full list is back");
    }

    @Test
    void typedTextResolvesToAnItemItNamesOrStaysTypedOnlyWithFreeText() throws Exception {
        FilterComboBox<String> box = box("alpha", "beta");
        SwingUtilities.invokeAndWait(() -> box.setSelectedItem("alpha"));

        SwingUtilities.invokeAndWait(() -> box.setSelectedItem("  BETA "));
        assertEquals("beta", box.getSelectedItem(), "an exact name, any case, is that item");

        SwingUtilities.invokeAndWait(() -> box.setSelectedItem("gamma"));
        assertEquals("beta", box.getSelectedItem(), "no free text: an unknown name changes nothing");

        box.setFreeText(true);
        SwingUtilities.invokeAndWait(() -> box.setSelectedItem("gamma"));
        assertEquals("gamma", box.getSelectedItem(), "free text: the typed name is the value");
        assertEquals("gamma", editor(box).getText());

        SwingUtilities.invokeAndWait(() -> box.setSelectedItem(null));
        assertNull(box.getSelectedItem());
        assertEquals("", editor(box).getText());
    }

    @Test
    void enterCommitsTheTypedText() throws Exception {
        FilterComboBox<String> box = box("alpha", "beta");
        type(box, "Beta");
        pressEnter(box);
        assertEquals("beta", box.getSelectedItem(), "Enter on an exact name picks the item");
        assertEquals("", box.getFilter());

        box.setFreeText(true);
        type(box, "delta");
        pressEnter(box);
        assertEquals("delta", box.getSelectedItem(), "Enter on free text keeps it");
        assertEquals(2, box.getItemCount(), "and the list is whole again");
    }

    @Test
    void theMatcherIsPluggableAndSeesBlankText() throws Exception {
        FilterComboBox<String> box = box("alpha", "beta", "alps", "audio-x");
        // a host rule: blank hides the "audio" entry, text is a prefix test
        SwingUtilities.invokeAndWait(() -> box.setMatcher((typed, item) ->
                typed.isEmpty() ? !item.startsWith("audio") : item.startsWith(typed)));
        assertEquals(Arrays.asList("alpha", "beta", "alps"), visible(box), "blank text goes through the matcher too");

        type(box, "al");
        assertEquals(Arrays.asList("alpha", "alps"), visible(box));
        type(box, "au");
        assertEquals(Arrays.asList("audio-x"), visible(box), "a typed prefix reaches what blank hides");
    }

    @Test
    void removingAllItemsClearsFilterSelectionAndEditor() throws Exception {
        FilterComboBox<String> box = box("alpha", "beta");
        SwingUtilities.invokeAndWait(() -> box.setSelectedItem("alpha"));
        type(box, "al");
        SwingUtilities.invokeAndWait(box::removeAllItems);

        assertEquals(0, box.getItemCount());
        assertEquals(0, box.getItems().size());
        assertNull(box.getSelectedItem());
        assertEquals("", box.getFilter());
        assertEquals("", editor(box).getText());

        SwingUtilities.invokeAndWait(() -> {
            box.addItem("gamma");
            box.setSelectedItem("gamma");
        });
        assertEquals("gamma", box.getSelectedItem(), "the combo re-selects after a clear");
    }
}
