package io.xlogistx.gui;

import org.junit.jupiter.api.Test;

import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The guarded clipboard wipe behind {@link GUIUtil#copyToClipboard(String, int)}, on a private
 * {@link Clipboard} so it runs headless: the wipe clears the clipboard only while it still holds
 * exactly the copied text.
 */
public class GUIUtilClipboardTest {

    @Test
    public void clearsWhileStillHoldingTheSecret() throws Exception {
        Clipboard clipboard = new Clipboard("test");
        GUIUtil.copyToClipboard(clipboard, "sk-secret");

        assertTrue(GUIUtil.clearClipboardIfHolding(clipboard, "sk-secret"));
        assertEquals("", clipboard.getData(DataFlavor.stringFlavor));
        assertFalse(GUIUtil.clearClipboardIfHolding(clipboard, "sk-secret"), "already cleared");
    }

    @Test
    public void leavesALaterCopyAlone() throws Exception {
        Clipboard clipboard = new Clipboard("test");
        GUIUtil.copyToClipboard(clipboard, "sk-secret");
        GUIUtil.copyToClipboard(clipboard, "something the user copied next");

        assertFalse(GUIUtil.clearClipboardIfHolding(clipboard, "sk-secret"));
        assertEquals("something the user copied next", clipboard.getData(DataFlavor.stringFlavor));
    }

    @Test
    public void emptyClipboardAndNullsAreNoOps() {
        Clipboard clipboard = new Clipboard("test");
        assertFalse(GUIUtil.clearClipboardIfHolding(clipboard, "sk-secret"));
        assertFalse(GUIUtil.clearClipboardIfHolding(null, "sk-secret"));
        assertFalse(GUIUtil.clearClipboardIfHolding(clipboard, null));
    }
}
