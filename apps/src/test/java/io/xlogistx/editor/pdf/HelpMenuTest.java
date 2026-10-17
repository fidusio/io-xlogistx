package io.xlogistx.editor.pdf;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;
import java.awt.event.KeyEvent;
import java.util.concurrent.Callable;

import static org.junit.jupiter.api.Assertions.*;

/** The Help menu: the user guide resource and the version notice. */
public class HelpMenuTest {

    @BeforeAll
    static void headless() {
        System.setProperty("java.awt.headless", "true");
    }

    @Test
    void helpMenuIsLastWithGuideAndVersion() throws Exception {
        PDFEditorPane pane = onEDT(PDFEditorPane::new);
        JMenuBar bar = onEDT(pane::createMenuBar);
        JMenu help = bar.getMenu(bar.getMenuCount() - 1);
        assertEquals("Help", help.getText());
        assertEquals("How to use the PDF editor...", help.getItem(0).getText());
        assertEquals(KeyStroke.getKeyStroke(KeyEvent.VK_F1, 0), help.getItem(0).getAccelerator());
        assertEquals("Version...", help.getItem(help.getItemCount() - 1).getText());
        assertNotNull(pane.getInputMap(javax.swing.JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT).get(KeyStroke.getKeyStroke(KeyEvent.VK_F1, 0)), "F1 is bound on the pane");
        // headless: the dialogs are skipped, nothing throws
        onEDT(() -> {
            pane.showHowTo();
            pane.showVersion();
            return null;
        });
    }

    @Test
    void guideResourceLoadsAndNamesEveryTool() {
        String md = PDFEditorPane.howToMarkdown();
        assertTrue(md.startsWith("# PDF Editor"), md.substring(0, Math.min(80, md.length())));
        assertFalse(md.contains("is missing from this build"), "the resource ships with the jar");
        for (String topic : new String[]{"Select / move / resize", "Edit text", "Fill form fields", "Highlight, Underline, Strikeout",
                "Note", "Ink, Rectangle, Ellipse, Line, Arrow", "Text box", "Image", "Keyboard", "Ctrl+Shift+H", "Ctrl+Shift+L", "F1", "Limits"})
            assertTrue(md.contains(topic), "the guide covers: " + topic);
    }

    @Test
    void versionNoticeCarriesTheApplicationVersion() {
        String md = PDFEditorPane.versionMarkdown();
        assertTrue(md.contains(PDFMain.VERSION.getName()), md);
        assertTrue(md.contains(PDFMain.VERSION.version()), md);
        assertTrue(md.contains("0.1.0"), md);
        assertTrue(md.contains("PDFBox"), md);
    }

    private static <T> T onEDT(Callable<T> call) throws Exception {
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
